import SwiftUI
import UniformTypeIdentifiers
import CryptoKit
import CommonCrypto
import Compression
import UIKit
import Foundation

// MARK: - Server & App Models

struct RequestData: Codable {
    let deviceId: String
}

struct ServerResponse: Codable {
    let deviceId: String?
    let attemptCount: Int?
    let status: String?
    let message: String?
    let allowed: Bool
}

struct SaoFileMetadata {
    let fileName: String
    let fileSizeFormatted: String
    let modifiedDateFormatted: String
    let previewText: String?
}

struct SaoValidationReport {
    let isValidBundle: Bool
    let formatTag: String
    let isDeviceLocked: Bool
    let hasInfoJson: Bool
    let hasArt: Bool
    let hasAudio: Bool
    let hasUI: Bool
    let hasSkinImage: Bool
    let matchedSkinImagePath: String?
    let missingItems: [String]
    let summaryMessage: String
    let diagnosticDetail: String?
    let extractedPreview: SaoExtractedPreview?
    
    var allCriticalPresent: Bool {
        hasInfoJson && hasArt && hasAudio && hasUI && hasSkinImage
    }
}

enum AppError: LocalizedError {
    case invalidURL(String)
    case httpStatus(Int, String?)
    case decodingFailed(String)
    case networkFailure(String)
    case missingWebDAVServer
    case fileAccessDenied
    case missingSaoFile
    
    var errorDescription: String? {
        switch self {
        case .invalidURL(let target):
            return "Invalid URL for \(target)."
        case .httpStatus(let code, let serverMessage):
            if let serverMessage, !serverMessage.isEmpty {
                return "Server responded with HTTP \(code): \(serverMessage)"
            }
            return "Server responded with unexpected HTTP status \(code)."
        case .decodingFailed(let details):
            return "Could not parse server response: \(details)"
        case .networkFailure(let message):
            return "Network error: \(message)"
        case .missingWebDAVServer:
            return "Please enter a valid WebDAV server URL in Settings first."
        case .fileAccessDenied:
            return "Permission to read the selected file was denied by iOS."
        case .missingSaoFile:
            return "Please select a .SAO file before starting."
        }
    }
}

// MARK: - .SAO Validator Models & Engine

enum SaoReaderError: LocalizedError {
    case fileAccessDenied
    case emptyFile
    case truncatedHeader
    case unknownFormatHeader(String)
    case unsupportedFlag(UInt8)
    case missingDeviceId
    case wrongDeviceOrTampered
    case decompressionFailed(Int, String)
    case malformedEntries(String)
    
    var errorDescription: String? {
        switch self {
        case .fileAccessDenied:
            return "Unable to access the selected .SAO file."
        case .emptyFile:
            return "The selected .SAO file is empty (0 bytes)."
        case .truncatedHeader:
            return "The .SAO file is too short to contain a valid header."
        case .unknownFormatHeader(let magic):
            return "Unrecognized .SAO magic header: '\(magic)'."
        case .unsupportedFlag(let flag):
            return "Unsupported .SAO mode flag: 0x\(String(format: "%02x", flag))."
        case .missingDeviceId:
            return "This .SAO file is locked to a Device ID, but no Device ID was provided."
        case .wrongDeviceOrTampered:
            return "Could not unlock .SAO — it may be locked to another Device ID or corrupted."
        case .decompressionFailed(let payloadBytes, let reason):
            return "Failed to decompress .SAO payload (\(payloadBytes) bytes): \(reason)"
        case .malformedEntries(let reason):
            return "Entry table error: \(reason)"
        }
    }
}

struct SaoParsedEntry {
    let path: String
    let isDirectory: Bool
    let byteCount: Int
}

struct SaoExtractedPreview {
    let skinImagePath: String?
    let skinImageData: Data?
    let skinTitle: String?
    let skinDescription: String?
}

enum SaoValidator {
    private static let sao3Magic: [UInt8] = [0x53, 0x41, 0x4F, 0x33] // "SAO3"
    private static let saowMagic: [UInt8] = [0x53, 0x41, 0x4F, 0x57] // "SAOW"
    private static let flagOpen: UInt8 = 0x00
    private static let flagDeviceLocked: UInt8 = 0x01
    private static let saltLength = 16
    private static let ivLength = 12
    private static let pbkdf2Iterations: UInt32 = 100_000
    private static let jsFallbackIterations: UInt32 = 25_000
    private static let jsFallbackLabel = "SAOIRSE-SAOW-DEVICE-LOCK-V1"
    
    static func validateSaoFile(at url: URL, deviceId: String) -> SaoValidationReport {
        do {
            let (entries, rawDecompressed, formatTag, isDeviceLocked) = try extractEntriesAndPayload(at: url, deviceId: deviceId)
            return evaluateCriticalItems(
                entries: entries,
                rawDecompressed: rawDecompressed,
                formatTag: formatTag,
                isDeviceLocked: isDeviceLocked
            )
        } catch {
            let message = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
            return SaoValidationReport(
                isValidBundle: false,
                formatTag: "Invalid",
                isDeviceLocked: false,
                hasInfoJson: false,
                hasArt: false,
                hasAudio: false,
                hasUI: false,
                hasSkinImage: false,
                matchedSkinImagePath: nil,
                missingItems: ["info.json", "Art", "Audio", "UI", "SKIN_<code>.jpeg"],
                summaryMessage: message,
                diagnosticDetail: nil,
                extractedPreview: nil
            )
        }
    }
    
    private static func extractEntriesAndPayload(
        at url: URL,
        deviceId: String
    ) throws -> ([SaoParsedEntry], Data, String, Bool) {
        let hasScope = url.startAccessingSecurityScopedResource()
        defer {
            if hasScope { url.stopAccessingSecurityScopedResource() }
        }
        
        let fileData: Data
        fileData = try Data(contentsOf: url, options: .mappedIfSafe)
        
        guard !fileData.isEmpty else {
            throw SaoReaderError.emptyFile
        }
        guard fileData.count >= 5 else {
            throw SaoReaderError.truncatedHeader
        }
        
        let headerBytes = Array(fileData.prefix(4))
        let headerString = String(bytes: headerBytes, encoding: .ascii) ?? "<invalid>"
        guard headerBytes == sao3Magic || headerBytes == saowMagic else {
            throw SaoReaderError.unknownFormatHeader(headerString)
        }
        
        let flag = fileData[4]
        let bodyStart = 5
        let isDeviceLocked: Bool
        let compressedPayload: Data
        
        switch flag {
        case flagOpen:
            isDeviceLocked = false
            compressedPayload = Data(fileData[bodyStart...])
            
        case flagDeviceLocked:
            isDeviceLocked = true
            let cleanId = deviceId.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !cleanId.isEmpty, cleanId != "Unknown" else {
                throw SaoReaderError.missingDeviceId
            }
            guard fileData.count >= bodyStart + saltLength + ivLength + 16 else {
                throw SaoReaderError.truncatedHeader
            }
            
            let salt = Data(fileData[bodyStart..<(bodyStart + saltLength)])
            let ivStart = bodyStart + saltLength
            let iv = Data(fileData[ivStart..<(ivStart + ivLength)])
            let cipherAndTag = Data(fileData[(ivStart + ivLength)...])
            
            if headerBytes == saowMagic {
                compressedPayload = try decryptSaowPayload(
                    deviceId: cleanId,
                    salt: salt,
                    iv: iv,
                    cipherAndTag: cipherAndTag
                )
            } else {
                let sealedCombined = Data(fileData[ivStart...])
                let key = deriveHkdfKey(
                    deviceId: cleanId,
                    salt: salt,
                    info: Data("SAOIRSE-SAO3-DEVICE-LOCK".utf8)
                )
                do {
                    let box = try AES.GCM.SealedBox(combined: sealedCombined)
                    compressedPayload = try AES.GCM.open(box, using: key)
                } catch {
                    throw SaoReaderError.wrongDeviceOrTampered
                }
            }
            
        default:
            throw SaoReaderError.unsupportedFlag(flag)
        }
        
        let decompressed = try decompressAnyCompression(compressedPayload)
        let entries = try parseEntries(decompressed)
        return (entries, decompressed, headerString, isDeviceLocked)
    }
    
    private static func decryptSaowPayload(
        deviceId: String,
        salt: Data,
        iv: Data,
        cipherAndTag: Data
    ) throws -> Data {
        if let rawKey = try? derivePbkdf2Key(
            password: Data(deviceId.utf8),
            salt: salt,
            iterations: pbkdf2Iterations,
            keyByteCount: 32
        ) {
            let symmetricKey = SymmetricKey(data: rawKey)
            var combined = Data(capacity: iv.count + cipherAndTag.count)
            combined.append(iv)
            combined.append(cipherAndTag)
            
            if let box = try? AES.GCM.SealedBox(combined: combined),
               let opened = try? AES.GCM.open(box, using: symmetricKey) {
                return opened
            }
        }
        
        if cipherAndTag.count >= 32 {
            let cipher = cipherAndTag.prefix(cipherAndTag.count - 32)
            let expectedTag = cipherAndTag.suffix(32)
            let materialInput = Data("\(jsFallbackLabel):\(deviceId)".utf8)
            
            if let material = try? derivePbkdf2Key(
                password: materialInput,
                salt: salt,
                iterations: jsFallbackIterations,
                keyByteCount: 64
            ) {
                let encKey = SymmetricKey(data: material.prefix(32))
                let macKey = SymmetricKey(data: material.suffix(32))
                
                var macInput = Data(capacity: salt.count + iv.count + cipher.count)
                macInput.append(salt)
                macInput.append(iv)
                macInput.append(cipher)
                
                let computedTag = Data(HMAC<SHA256>.authenticationCode(for: macInput, using: macKey))
                if constantTimeEqual(computedTag, expectedTag) {
                    return jsCtrXor(key: encKey, iv: iv, data: cipher)
                }
            }
        }
        
        throw SaoReaderError.wrongDeviceOrTampered
    }
    
    private static func derivePbkdf2Key(
        password: Data,
        salt: Data,
        iterations: UInt32,
        keyByteCount: Int
    ) throws -> Data {
        var derivedKey = Data(count: keyByteCount)
        let status = derivedKey.withUnsafeMutableBytes { derivedBytes in
            salt.withUnsafeBytes { saltBytes in
                password.withUnsafeBytes { passBytes in
                    CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        passBytes.baseAddress?.assumingMemoryBound(to: Int8.self),
                        password.count,
                        saltBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        salt.count,
                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                        iterations,
                        derivedBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        keyByteCount
                    )
                }
            }
        }
        guard status == kCCSuccess else {
            throw SaoReaderError.wrongDeviceOrTampered
        }
        return derivedKey
    }
    
    private static func jsCtrXor(key: SymmetricKey, iv: Data, data: Data) -> Data {
        var out = Data(count: data.count)
        let blockCount = (data.count + 31) / 32
        var counterBlock = Data(count: iv.count + 4)
        counterBlock.replaceSubrange(0..<iv.count, with: iv)
        
        var pos = 0
        for c in 0..<blockCount {
            let counter = UInt32(c)
            counterBlock[iv.count] = UInt8((counter >> 24) & 0xff)
            counterBlock[iv.count + 1] = UInt8((counter >> 16) & 0xff)
            counterBlock[iv.count + 2] = UInt8((counter >> 8) & 0xff)
            counterBlock[iv.count + 3] = UInt8(counter & 0xff)
            
            let keystream = Data(HMAC<SHA256>.authenticationCode(for: counterBlock, using: key))
            let chunkLen = min(32, data.count - pos)
            for i in 0..<chunkLen {
                out[pos + i] = data[data.startIndex + pos + i] ^ keystream[i]
            }
            pos += chunkLen
        }
        return out
    }
    
    private static func constantTimeEqual(_ a: Data, _ b: Data) -> Bool {
        guard a.count == b.count else { return false }
        var diff: UInt8 = 0
        for (x, y) in zip(a, b) {
            diff |= x ^ y
        }
        return diff == 0
    }
    
    private static func deriveHkdfKey(deviceId: String, salt: Data, info: Data) -> SymmetricKey {
        let ikm = SymmetricKey(data: Data(deviceId.utf8))
        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: ikm,
            salt: salt,
            info: info,
            outputByteCount: 32
        )
    }
    
    private static func evaluateCriticalItems(
        entries: [SaoParsedEntry],
        rawDecompressed: Data,
        formatTag: String,
        isDeviceLocked: Bool
    ) -> SaoValidationReport {
        let normalizedPaths = entries.map { entry in
            entry.path
                .trimmingCharacters(in: CharacterSet(charactersIn: "/"))
                .lowercased()
        }
        
        let infoEntry = entries.first { entry in
            !entry.isDirectory && (
                entry.path.lowercased() == "info.json" ||
                entry.path.lowercased().hasSuffix("/info.json")
            )
        }
        let hasInfoJson = infoEntry != nil
        
        let hasArt = normalizedPaths.contains { path in
            path.split(separator: "/").contains("art")
        }
        
        let hasAudio = normalizedPaths.contains { path in
            path.split(separator: "/").contains("audio")
        }
        
        let hasUI = normalizedPaths.contains { path in
            path.split(separator: "/").contains("ui")
        }
        
        let skinImageEntry = entries.first { entry in
            guard !entry.isDirectory else { return false }
            let lowerPath = entry.path.lowercased()
            let isImage = lowerPath.hasSuffix(".jpeg") || lowerPath.hasSuffix(".jpg") || lowerPath.hasSuffix(".png")
            guard isImage else { return false }
            let pathComponents = lowerPath.split(separator: "/").map(String.init)
            let hasSkinFolder = pathComponents.contains { $0.hasPrefix("skin_") }
            let fileNameMatchesSkin = URL(fileURLWithPath: lowerPath).lastPathComponent.hasPrefix("skin_")
            return hasSkinFolder || fileNameMatchesSkin
        }
        
        let hasSkinImage = skinImageEntry != nil
        
        var missing: [String] = []
        if !hasInfoJson { missing.append("info.json") }
        if !hasArt { missing.append("Art") }
        if !hasAudio { missing.append("Audio") }
        if !hasUI { missing.append("UI") }
        if !hasSkinImage { missing.append("SKIN_<code>.jpeg") }
        
        let payloadMap = extractEntryPayloads(from: rawDecompressed)
        var skinData: Data? = nil
        if let skinPath = skinImageEntry?.path, let bytes = payloadMap[skinPath], UIImage(data: bytes) != nil {
            skinData = bytes
        }
        
        var skinTitle: String? = nil
        var skinDescription: String? = nil
        
        if let infoPath = infoEntry?.path,
           let infoBytes = payloadMap[infoPath],
           let jsonObj = try? JSONSerialization.jsonObject(with: infoBytes, options: []),
           let rootDict = jsonObj as? [String: Any] {
            let skinDict = rootDict["skin"] as? [String: Any]
            skinTitle = (skinDict?["name"] as? String)
            ?? (rootDict["skin.name"] as? String)
            ?? (rootDict["skinName"] as? String)
            ?? (rootDict["name"] as? String)
            skinDescription = (skinDict?["description"] as? String)
            ?? (rootDict["skin.description"] as? String)
            ?? (rootDict["skinDescription"] as? String)
            ?? (rootDict["description"] as? String)
        }
        
        let extractedPreview = SaoExtractedPreview(
            skinImagePath: skinImageEntry?.path,
            skinImageData: skinData,
            skinTitle: skinTitle,
            skinDescription: skinDescription
        )
        
        let summary: String
        if missing.isEmpty {
            summary = "All critical folders/files present (\(formatTag), \(isDeviceLocked ? "Device-Locked" : "Open"))."
        } else {
            summary = "Missing critical items: \(missing.joined(separator: ", "))."
        }
        
        let entrySummary = entries.prefix(8).map { $0.path }.joined(separator: ", ")
        
        return SaoValidationReport(
            isValidBundle: true,
            formatTag: formatTag,
            isDeviceLocked: isDeviceLocked,
            hasInfoJson: hasInfoJson,
            hasArt: hasArt,
            hasAudio: hasAudio,
            hasUI: hasUI,
            hasSkinImage: hasSkinImage,
            matchedSkinImagePath: skinImageEntry?.path,
            missingItems: missing,
            summaryMessage: summary,
            diagnosticDetail: "Entries (\(entries.count)): \(entrySummary)",
            extractedPreview: extractedPreview
        )
    }
    
    private static func extractEntryPayloads(from data: Data) -> [String: Data] {
        guard data.count >= 4 else { return [:] }
        var offset = 0
        let count = Int(readUInt32BE(from: data, at: offset))
        offset += 4
        guard count >= 0 && count <= 5000 else { return [:] }
        
        var result: [String: Data] = [:]
        for _ in 0..<count {
            guard offset + 2 <= data.count else { break }
            let pathLen = Int(readUInt16BE(from: data, at: offset))
            offset += 2
            guard offset + pathLen + 1 + 4 <= data.count else { break }
            let path = String(data: data.subdata(in: offset..<(offset + pathLen)), encoding: .utf8) ?? ""
            offset += pathLen
            let isDir = data[offset] != 0
            offset += 1
            let payloadLen = Int(readUInt32BE(from: data, at: offset))
            offset += 4
            guard payloadLen >= 0 && offset + payloadLen <= data.count else { break }
            if !isDir {
                result[path] = data.subdata(in: offset..<(offset + payloadLen))
            }
            offset += payloadLen
        }
        return result
    }
    
    private static func decompressStream(
        _ compressed: Data,
        algorithm: compression_algorithm,
        maxOutputBytes: Int = 1_500_000_000
    ) throws -> Data {
        guard !compressed.isEmpty else {
            throw SaoReaderError.decompressionFailed(0, "Empty compressed buffer")
        }
        
        var stream = compression_stream(
            dst_ptr: UnsafeMutablePointer<UInt8>.allocate(capacity: 1),
            dst_size: 0,
            src_ptr: UnsafePointer<UInt8>(bitPattern: 1)!,
            src_size: 0,
            state: nil
        )
        stream.dst_ptr.deallocate()
        
        let initStatus = compression_stream_init(&stream, COMPRESSION_STREAM_DECODE, algorithm)
        guard initStatus == COMPRESSION_STATUS_OK else {
            throw SaoReaderError.decompressionFailed(compressed.count, "Stream init failed (\(initStatus))")
        }
        defer {
            compression_stream_destroy(&stream)
        }
        
        let chunkSize = 262_144 // 256 KB
        let dstBuffer = UnsafeMutablePointer<UInt8>.allocate(capacity: chunkSize)
        defer { dstBuffer.deallocate() }
        
        var output = Data()
        output.reserveCapacity(min(compressed.count * 2, 16_777_216))
        
        var streamStatus: compression_status = COMPRESSION_STATUS_OK
        
        try compressed.withUnsafeBytes { rawSrc in
            guard let baseSrc = rawSrc.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                throw SaoReaderError.decompressionFailed(compressed.count, "Invalid source pointer")
            }
            
            stream.src_ptr = baseSrc
            stream.src_size = compressed.count
            
            repeat {
                stream.dst_ptr = dstBuffer
                stream.dst_size = chunkSize
                
                let flags: Int32 = stream.src_size == 0 ? Int32(COMPRESSION_STREAM_FINALIZE.rawValue) : 0
                streamStatus = compression_stream_process(&stream, flags)
                
                let produced = chunkSize - stream.dst_size
                if produced > 0 {
                    if output.count + produced > maxOutputBytes {
                        throw SaoReaderError.decompressionFailed(compressed.count, "Exceeded maximum output size")
                    }
                    output.append(dstBuffer, count: produced)
                }
                
                if streamStatus == COMPRESSION_STATUS_ERROR {
                    throw SaoReaderError.decompressionFailed(compressed.count, "Stream decoder reported error")
                }
            } while streamStatus == COMPRESSION_STATUS_OK
        }
        
        guard streamStatus == COMPRESSION_STATUS_END else {
            throw SaoReaderError.decompressionFailed(
                compressed.count,
                "Incomplete stream (status \(streamStatus.rawValue), produced \(output.count) bytes)"
            )
        }
        
        return output
    }
    
    private static func decompressAnyCompression(_ compressed: Data) throws -> Data {
        if let zlibData = try? decompressStream(compressed, algorithm: COMPRESSION_ZLIB) {
            return zlibData
        }
        
        if compressed.count > 2,
           let strippedZlib = try? decompressStream(Data(compressed.dropFirst(2)), algorithm: COMPRESSION_ZLIB) {
            return strippedZlib
        }
        
        if let lzfseData = try? decompressStream(compressed, algorithm: COMPRESSION_LZFSE) {
            return lzfseData
        }
        
        let headHex = compressed.prefix(8).map { String(format: "%02x", $0) }.joined(separator: " ")
        throw SaoReaderError.decompressionFailed(compressed.count, "ZLIB/LZFSE mismatch (head: [\(headHex)])")
    }
    
    private static func readUInt16BE(from data: Data, at offset: Int) -> UInt16 {
        let b0 = UInt16(data[offset]) << 8
        let b1 = UInt16(data[offset + 1])
        return b0 | b1
    }
    
    private static func readUInt32BE(from data: Data, at offset: Int) -> UInt32 {
        let b0 = UInt32(data[offset]) << 24
        let b1 = UInt32(data[offset + 1]) << 16
        let b2 = UInt32(data[offset + 2]) << 8
        let b3 = UInt32(data[offset + 3])
        return b0 | b1 | b2 | b3
    }
    
    private static func parseEntries(_ data: Data) throws -> [SaoParsedEntry] {
        guard data.count >= 4 else {
            throw SaoReaderError.malformedEntries("Buffer too short (\(data.count) bytes)")
        }
        var offset = 0
        
        let count = Int(readUInt32BE(from: data, at: offset))
        offset += 4
        
        guard count >= 0 && count <= 5000 else {
            throw SaoReaderError.malformedEntries("Invalid entry count \(count)")
        }
        
        var entries: [SaoParsedEntry] = []
        entries.reserveCapacity(count)
        
        for idx in 0..<count {
            guard offset + 2 <= data.count else {
                throw SaoReaderError.malformedEntries("Truncated path length at entry \(idx)")
            }
            let pathLen = Int(readUInt16BE(from: data, at: offset))
            offset += 2
            
            guard offset + pathLen + 1 + 4 <= data.count else {
                throw SaoReaderError.malformedEntries("Truncated header at entry \(idx)")
            }
            let pathData = data.subdata(in: offset..<(offset + pathLen))
            let path = String(data: pathData, encoding: .utf8) ?? ""
            offset += pathLen
            
            let isDir = data[offset] != 0
            offset += 1
            
            let payloadLen = Int(readUInt32BE(from: data, at: offset))
            offset += 4
            
            guard payloadLen >= 0 && offset + payloadLen <= data.count else {
                throw SaoReaderError.malformedEntries("Truncated payload at entry \(idx) (\(path))")
            }
            offset += payloadLen
            
            entries.append(SaoParsedEntry(path: path, isDirectory: isDir, byteCount: payloadLen))
        }
        
        return entries
    }
}

// MARK: - Main View

struct ContentView: View {
    private let checkEndpoint = "https://saoserver.onrender.com/check"
    
    // MARK: - Stored Settings
    
    @AppStorage("webdav_server") private var webdavServer = ""
    @AppStorage("webdav_username") private var webdavUsername = ""
    @AppStorage("webdav_path") private var webdavPath = "/"
    
    @AppStorage("app_theme") private var appTheme = "Blossom"
    @AppStorage("app_appearance") private var appAppearance = "System"
    
    // MARK: - States
    
    @State private var isUp = false
    @State private var isCheckingServer = false
    @State private var lastServerMessage = ""
    
    @State private var selectedFile: URL?
    @State private var saoMetadata: SaoFileMetadata?
    @State private var validationReport: SaoValidationReport?
    @State private var isValidatingSao = false
    @State private var showingFilePicker = false
    @State private var showingSettings = false
    @State private var showingAlert = false
    
    @State private var alertTitle = ""
    @State private var alertMessage = ""
    
    @State private var animateGradient = false
    @State private var webdavPassword = ""
    
    @State private var webdavStatus = "Disconnected"
    @State private var isConnecting = false
    
    @State private var isVerified: Bool? = nil
    
    // MARK: - Device
    
    private var deviceUUID: String {
        UIDevice.current.identifierForVendor?.uuidString ?? "Unknown"
    }
    
    private var isWebDavReady: Bool {
        webdavStatus == "Connected" && !webdavServer.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }
    
    // MARK: - Theme
    
    @Environment(\.colorScheme) private var colorScheme
    
    private var pink: Color {
        switch appTheme {
        case "Lavender":
            return Color(red: 0.72, green: 0.55, blue: 0.95)
        case "Rose":
            return Color(red: 0.95, green: 0.40, blue: 0.60)
        case "Sky":
            return Color(red: 0.40, green: 0.70, blue: 0.95)
        default:
            return Color(red: 0.95, green: 0.45, blue: 0.75)
        }
    }
    
    private var purple: Color {
        Color(red: 0.65, green: 0.40, blue: 0.90)
    }
    
    private var isDark: Bool {
        appAppearance == "Dark" ||
        (appAppearance == "System" && colorScheme == .dark)
    }
    
    private var primaryText: Color {
        isDark ? .white : Color.black.opacity(0.85)
    }
    
    private var secondaryText: Color {
        isDark ? .white.opacity(0.7) : Color.black.opacity(0.55)
    }
    
    private var cardColor: Color {
        isDark
        ? Color.white.opacity(0.10)
        : Color.white.opacity(0.65)
    }
    
    private var secondaryBackground: Color {
        isDark
        ? Color.black.opacity(0.20)
        : Color.white.opacity(0.35)
    }
    
    // MARK: - Animated Gradient
    
    private var animatedGradient: LinearGradient {
        LinearGradient(
            colors: [
                pink.opacity(0.85),
                purple.opacity(0.70),
                pink.opacity(0.45),
                Color.blue.opacity(0.30)
            ],
            startPoint: animateGradient ? .topLeading : .bottomLeading,
            endPoint: animateGradient ? .bottomTrailing : .topTrailing
        )
    }
    
    // MARK: - Body
    
    var body: some View {
        ZStack {
            animatedGradient
                .ignoresSafeArea()
            
            backgroundOverlay
            
            mainContent
        }
        .preferredColorScheme(
            appAppearance == "Light"
            ? .light
            : appAppearance == "Dark"
            ? .dark
            : nil
        )
        .onAppear {
            startGradientAnimation()
            Task {
                await refreshServerStatus(showErrorAlert: false)
            }
        }
        .sheet(isPresented: $showingSettings) {
            settingsView
        }
        .fileImporter(
            isPresented: $showingFilePicker,
            allowedContentTypes: [
                UTType(filenameExtension: "sao"),
                .data
            ].compactMap { $0 },
            allowsMultipleSelection: false
        ) { result in
            handleFileImport(result)
        }
        .alert(alertTitle, isPresented: $showingAlert) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(alertMessage)
        }
    }
    
    // MARK: - Background
    
    private var backgroundOverlay: some View {
        Rectangle()
            .fill(
                isDark
                ? Color.black.opacity(0.30)
                : Color.white.opacity(0.15)
            )
            .ignoresSafeArea()
    }
    
    // MARK: - Main Content
    
    private var mainContent: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 22) {
                    header
                    welcomeCard
                    deviceCard
                    fileCard
                    saoValidityCard
                    actionCard
                    footer
                }
                .padding(.horizontal, 18)
                .padding(.top, 15)
                .padding(.bottom, 35)
            }
            .background(Color.clear)
            .toolbarBackground(.hidden, for: .navigationBar)
        }
    }
    
    // MARK: - Header
    
    private var header: some View {
        HStack {
            VStack(alignment: .leading, spacing: 5) {
                Text("SAOIRSE")
                    .font(.system(size: 13, weight: .heavy))
                    .tracking(4)
                    .foregroundStyle(primaryText)
                
                Text("Saoirse's Tool")
                    .font(.system(size: 30, weight: .bold))
                    .foregroundStyle(primaryText)
            }
            
            Spacer()
            
            Button {
                showingSettings = true
            } label: {
                Image(systemName: "gearshape.fill")
                    .font(.system(size: 22))
                    .foregroundStyle(primaryText)
                    .padding(14)
                    .background(cardColor)
                    .clipShape(Circle())
                    .overlay {
                        Circle()
                            .strokeBorder(
                                pink.opacity(0.35),
                                lineWidth: 1
                            )
                    }
            }
            .buttonStyle(AnimatedButtonStyle())
            .accessibilityLabel("Settings")
        }
        .padding(.vertical, 10)
    }
    
    // MARK: - Welcome
    
    private var welcomeCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Image(systemName: "heart.fill")
                    .foregroundStyle(pink)
                
                Text("Welcome")
                    .font(.headline)
                    .foregroundStyle(primaryText)
            }
            
            Text("Welcome to Saoirse's Tool!")
                .font(.title2.bold())
                .foregroundStyle(primaryText)
            
            Text("Your personal workspace with a customizable interface.")
                .font(.subheadline)
                .foregroundStyle(secondaryText)
        }
        .padding(20)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(cardColor)
        .clipShape(RoundedRectangle(cornerRadius: 25))
        .overlay {
            RoundedRectangle(cornerRadius: 25)
                .strokeBorder(pink.opacity(0.35), lineWidth: 1)
        }
    }
    
    // MARK: - Device Card
    
    private var deviceCard: some View {
        VStack(alignment: .leading, spacing: 15) {
            HStack {
                sectionTitle("Device Information", icon: "iphone")
                
                Spacer()
                
                Button {
                    Task {
                        await refreshServerStatus(showErrorAlert: true)
                    }
                } label: {
                    if isCheckingServer {
                        ProgressView()
                            .tint(pink)
                    } else {
                        Label("Check", systemImage: "arrow.clockwise")
                            .font(.caption.bold())
                            .foregroundStyle(pink)
                            .padding(.horizontal, 10)
                            .padding(.vertical, 6)
                            .background(secondaryBackground)
                            .clipShape(Capsule())
                    }
                }
                .disabled(isCheckingServer)
            }
            
            VStack(alignment: .leading, spacing: 12) {
                Text("Device ID")
                    .font(.subheadline.weight(.medium))
                    .foregroundStyle(secondaryText)
                
                HStack {
                    Text(deviceUUID)
                        .font(
                            .system(
                                size: 12,
                                weight: .medium,
                                design: .monospaced
                            )
                        )
                        .foregroundStyle(primaryText)
                        .lineLimit(2)
                    
                    Spacer()
                    
                    Button {
                        UIPasteboard.general.string = deviceUUID
                        
                        showAlert(
                            title: "Copied!",
                            message: "Device ID copied to clipboard."
                        )
                    } label: {
                        Image(systemName: "doc.on.doc")
                            .foregroundStyle(pink)
                    }
                }
                
                Divider()
                
                HStack {
                    Label(
                        "Sao-Server Status",
                        systemImage: "server.rack"
                    )
                    .foregroundStyle(primaryText)
                    
                    Spacer()
                    
                    Text(isUp ? "Reached Successfully" : "Failed")
                        .font(.caption.bold())
                        .foregroundStyle(isUp ? .green : .white)
                        .padding(.horizontal, 10)
                        .padding(.vertical, 6)
                        .background(
                            (isUp ? Color.green : pink)
                                .opacity(isUp ? 0.20 : 0.65)
                        )
                        .clipShape(Capsule())
                }
                
                Divider()
                
                HStack {
                    Label(
                        "Device Status",
                        systemImage: "checkmark.shield"
                    )
                    .foregroundStyle(primaryText)
                    
                    Spacer()
                    
                    Text(isVerified == true ? "Verified" : "Unverified")
                        .font(.caption.bold())
                        .foregroundStyle(isVerified == true ? .green : pink)
                        .padding(.horizontal, 10)
                        .padding(.vertical, 6)
                        .background(
                            (isVerified == true ? Color.green : pink)
                                .opacity(0.15)
                        )
                        .clipShape(Capsule())
                }
                
                if !lastServerMessage.isEmpty {
                    Text(lastServerMessage)
                        .font(.caption)
                        .foregroundStyle(secondaryText)
                }
            }
            .padding(16)
            .background(secondaryBackground)
            .clipShape(RoundedRectangle(cornerRadius: 18))
        }
        .padding(18)
        .background(cardColor)
        .clipShape(RoundedRectangle(cornerRadius: 25))
    }
    
    // MARK: - SAO File Picker
    
    private var fileCard: some View {
        VStack(alignment: .leading, spacing: 15) {
            sectionTitle("SAO File", icon: "doc.zipper")
            
            Button {
                showingFilePicker = true
            } label: {
                HStack(spacing: 14) {
                    Image(systemName: "doc.badge.plus")
                        .font(.system(size: 25))
                        .foregroundStyle(pink)
                    
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Upload .SAO")
                            .font(.headline)
                            .foregroundStyle(primaryText)
                        
                        Text("Select a .sao file from Files")
                            .font(.caption)
                            .foregroundStyle(secondaryText)
                    }
                    
                    Spacer()
                    
                    Image(systemName: "chevron.right")
                        .foregroundStyle(secondaryText)
                }
                .padding(18)
                .background(secondaryBackground)
                .clipShape(RoundedRectangle(cornerRadius: 18))
            }
            .buttonStyle(AnimatedButtonStyle())
            
            if let saoMetadata {
                VStack(alignment: .leading, spacing: 8) {
                    Label(
                        "Selected File",
                        systemImage: "doc.fill"
                    )
                    .foregroundStyle(pink)
                    .font(.subheadline.bold())
                    
                    Text(saoMetadata.fileName)
                        .font(.subheadline.weight(.medium))
                        .foregroundStyle(primaryText)
                        .textSelection(.enabled)
                    
                    HStack(spacing: 12) {
                        Text("Size: \(saoMetadata.fileSizeFormatted)")
                        Text("•")
                        Text("Modified: \(saoMetadata.modifiedDateFormatted)")
                    }
                    .font(.caption)
                    .foregroundStyle(secondaryText)
                    
                    if let preview = saoMetadata.previewText, !preview.isEmpty {
                        Text("Preview: \(preview)")
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundStyle(primaryText.opacity(0.8))
                            .lineLimit(3)
                            .padding(8)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(secondaryBackground)
                            .clipShape(RoundedRectangle(cornerRadius: 10))
                    }
                    
                    Button {
                        clearSelectedFile()
                    } label: {
                        Label(
                            "Remove File",
                            systemImage: "trash"
                        )
                        .font(.caption.bold())
                        .foregroundStyle(pink)
                    }
                    .padding(.top, 4)
                }
                .padding(15)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(pink.opacity(0.12))
                .clipShape(RoundedRectangle(cornerRadius: 15))
            }
        }
        .padding(18)
        .background(cardColor)
        .clipShape(RoundedRectangle(cornerRadius: 25))
    }
    
    // MARK: - SAO Validity Indicator Card
    
    private var saoValidityCard: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                sectionTitle(".SAO Validity", icon: "checkmark.seal.fill")
                
                Spacer()
                
                if isValidatingSao {
                    HStack(spacing: 6) {
                        ProgressView()
                            .tint(pink)
                        Text("SCANNING")
                            .font(.caption.bold())
                            .foregroundStyle(secondaryText)
                    }
                } else if let report = validationReport {
                    let isGood = report.isValidBundle && report.allCriticalPresent
                    Text(isGood ? "VALID" : (report.isValidBundle ? "INCOMPLETE" : "INVALID"))
                        .font(.caption.bold())
                        .foregroundStyle(isGood ? .green : (report.isValidBundle ? .orange : .white))
                        .padding(.horizontal, 10)
                        .padding(.vertical, 5)
                        .background(
                            (isGood ? Color.green : (report.isValidBundle ? Color.orange : pink))
                                .opacity(isGood ? 0.20 : (report.isValidBundle ? 0.20 : 0.70))
                        )
                        .clipShape(Capsule())
                } else {
                    Text("NO FILE")
                        .font(.caption.bold())
                        .foregroundStyle(secondaryText)
                        .padding(.horizontal, 10)
                        .padding(.vertical, 5)
                        .background(secondaryBackground)
                        .clipShape(Capsule())
                }
            }
            
            if isValidatingSao {
                Text("Streaming and decompressing .SAO archive...")
                    .font(.caption)
                    .foregroundStyle(secondaryText)
            } else if let report = validationReport {
                Text(report.summaryMessage)
                    .font(.caption)
                    .foregroundStyle(report.isValidBundle ? secondaryText : pink)
                
                if let diag = report.diagnosticDetail {
                    Text(diag)
                        .font(.system(.caption2, design: .monospaced))
                        .foregroundStyle(secondaryText)
                        .lineLimit(3)
                }
                
                if report.isValidBundle {
                    VStack(spacing: 8) {
                        checklistRow("info.json", present: report.hasInfoJson)
                        checklistRow("Art", present: report.hasArt)
                        checklistRow("Audio", present: report.hasAudio)
                        checklistRow("UI", present: report.hasUI)
                        checklistRow(
                            report.matchedSkinImagePath ?? "SKIN_<code>.jpeg",
                            present: report.hasSkinImage
                        )
                    }
                    .padding(14)
                    .background(secondaryBackground)
                    .clipShape(RoundedRectangle(cornerRadius: 16))
                    
                    if let preview = report.extractedPreview {
                        extractedBundleContentView(preview)
                    }
                }
            } else {
                Text("Select a .SAO file above to verify its structure and required items (Art, Audio, UI, SKIN_<code>.jpeg, info.json).")
                    .font(.caption)
                    .foregroundStyle(secondaryText)
            }
        }
        .padding(18)
        .background(cardColor)
        .clipShape(RoundedRectangle(cornerRadius: 25))
        .overlay {
            RoundedRectangle(cornerRadius: 25)
                .strokeBorder(pink.opacity(0.30), lineWidth: 1)
        }
    }
    
    @ViewBuilder
    private func extractedBundleContentView(_ preview: SaoExtractedPreview) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            if let imgData = preview.skinImageData, let uiImage = UIImage(data: imgData) {
                Image(uiImage: uiImage)
                    .resizable()
                    .scaledToFit()
                    .frame(maxHeight: 220)
                    .frame(maxWidth: .infinity)
                    .padding(8)
                    .background(secondaryBackground)
                    .clipShape(RoundedRectangle(cornerRadius: 14))
            }
            
            if preview.skinTitle != nil || preview.skinDescription != nil {
                VStack(alignment: .leading, spacing: 6) {
                    if let title = preview.skinTitle, !title.isEmpty {
                        Text(title)
                            .font(.headline)
                            .foregroundStyle(primaryText)
                    }
                    if let desc = preview.skinDescription, !desc.isEmpty {
                        Text(desc)
                            .font(.caption)
                            .foregroundStyle(secondaryText)
                    }
                }
                .padding(12)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(secondaryBackground)
                .clipShape(RoundedRectangle(cornerRadius: 12))
            }
        }
        .padding(.top, 4)
    }
    
    private func checklistRow(_ label: String, present: Bool) -> some View {
        HStack {
            Image(systemName: present ? "checkmark.circle.fill" : "xmark.circle.fill")
                .foregroundStyle(present ? .green : pink)
            Text(label)
                .font(.system(.caption, design: .monospaced).weight(.medium))
                .foregroundStyle(primaryText)
                .lineLimit(1)
            Spacer()
            Text(present ? "Present" : "Missing")
                .font(.caption2.bold())
                .foregroundStyle(present ? .green : pink)
        }
    }
    
    // MARK: - Action Center
    
    private var actionCard: some View {
        VStack(alignment: .leading, spacing: 15) {
            sectionTitle("Action Center", icon: "bolt.fill")
            
            Button {
                Task {
                    await launchAttempt()
                }
            } label: {
                HStack {
                    if isCheckingServer || isValidatingSao {
                        ProgressView()
                            .tint(.white)
                    } else {
                        Image(systemName: "sparkles")
                            .font(.title2)
                    }
                    
                    Text((isCheckingServer || isValidatingSao) ? "Verifying..." : "Start")
                        .font(.headline)
                    
                    Spacer()
                    
                    Image(systemName: "arrow.right")
                }
                .foregroundStyle(.white)
                .padding(18)
                .background(
                    LinearGradient(
                        colors: [pink, purple],
                        startPoint: .leading,
                        endPoint: .trailing
                    )
                )
                .clipShape(RoundedRectangle(cornerRadius: 18))
            }
            .buttonStyle(AnimatedButtonStyle())
            .disabled(isCheckingServer || isValidatingSao)
        }
        .padding(18)
        .background(cardColor)
        .clipShape(RoundedRectangle(cornerRadius: 25))
    }
    
    // MARK: - Server & Launch Logic
    
    private func connectToServer(deviceId: String) async throws -> ServerResponse {
        guard let url = URL(string: checkEndpoint) else {
            throw AppError.invalidURL("Sao-Server")
        }
        
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.timeoutInterval = 15
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        
        let body = RequestData(deviceId: deviceId)
        
        do {
            request.httpBody = try JSONEncoder().encode(body)
        } catch {
            throw AppError.decodingFailed("Failed to encode request payload.")
        }
        
        let data: Data
        let response: URLResponse
        
        do {
            (data, response) = try await URLSession.shared.data(for: request)
        } catch {
            throw AppError.networkFailure(error.localizedDescription)
        }
        
        guard let httpResponse = response as? HTTPURLResponse else {
            throw AppError.networkFailure("Invalid HTTP response received.")
        }
        
        let rawJSON = String(data: data, encoding: .utf8) ?? "<not UTF-8>"
        print("Server HTTP \(httpResponse.statusCode) (\(data.count) bytes): \(rawJSON)")
        
        guard (200...299).contains(httpResponse.statusCode) else {
            let decodedError = try? JSONDecoder().decode(ServerResponse.self, from: data)
            throw AppError.httpStatus(httpResponse.statusCode, decodedError?.message ?? rawJSON)
        }
        
        do {
            return try JSONDecoder().decode(ServerResponse.self, from: data)
        } catch {
            throw AppError.decodingFailed("\(error.localizedDescription)\nRaw: \(rawJSON)")
        }
    }
    
    @discardableResult
    private func refreshServerStatus(showErrorAlert: Bool) async -> ServerResponse? {
        isCheckingServer = true
        defer { isCheckingServer = false }
        
        do {
            let result = try await connectToServer(deviceId: deviceUUID)
            isUp = true
            isVerified = result.allowed
            lastServerMessage = result.message ?? "Attempts: \(result.attemptCount ?? 0)"
            return result
        } catch {
            isUp = false
            isVerified = false
            let message = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
            lastServerMessage = message
            if showErrorAlert {
                showAlert(title: "Server Check Failed", message: message)
            }
            return nil
        }
    }
    
    private func runValidationTask(for url: URL) async -> SaoValidationReport {
        let currentDevice = deviceUUID
        isValidatingSao = true
        defer { isValidatingSao = false }
        return await Task.detached(priority: .userInitiated) {
            SaoValidator.validateSaoFile(at: url, deviceId: currentDevice)
        }.value
    }
    
    private func launchAttempt() async {
        guard let selectedFile else {
            showAlert(
                title: "Missing .SAO File",
                message: AppError.missingSaoFile.errorDescription ?? "Please select a .SAO file."
            )
            return
        }
        
        let report = await runValidationTask(for: selectedFile)
        validationReport = report
        
        guard report.isValidBundle && report.allCriticalPresent else {
            showAlert(
                title: "Invalid .SAO Bundle",
                message: report.summaryMessage
            )
            return
        }
        
        guard let serverResult = await refreshServerStatus(showErrorAlert: false) else {
            showAlert(
                title: "Server Unreachable",
                message: """
                Could not reach Sao-Server to verify your device.
                
                \(lastServerMessage)
                """
            )
            return
        }
        
        guard serverResult.allowed else {
            let serverDetail = serverResult.message ?? "Device not authorized (Attempts: \(serverResult.attemptCount ?? 0))"
            showAlert(
                title: "Device Not Whitelisted",
                message: """
                Your device is not verified.
                
                Server message: \(serverDetail)
                
                Your Device ID:
                \(deviceUUID)
                
                Please have your device authorized by the administrator before continuing.
                """
            )
            return
        }
        
        guard isWebDavReady else {
            showAlert(
                title: "WebDAV Not Connected",
                message: "Configure and test a valid WebDAV connection in Settings before starting."
            )
            return
        }
        
        showAlert(
            title: "Ready",
            message: "Device verified, \(saoMetadata?.fileName ?? ".SAO") validated, and WebDAV ready."
        )
    }
    
    // MARK: - File Import Handler
    
    private func handleFileImport(_ result: Result<[URL], Error>) {
        switch result {
        case .success(let urls):
            guard let url = urls.first else {
                showAlert(title: "No File Selected", message: "No file was returned from the picker.")
                return
            }
            
            guard url.pathExtension.lowercased() == "sao" else {
                showAlert(
                    title: "Invalid File",
                    message: "Please select a valid .SAO file."
                )
                return
            }
            
            do {
                let metadata = try inspectSaoFile(at: url)
                selectedFile = url
                saoMetadata = metadata
                validationReport = nil
                Task {
                    let report = await runValidationTask(for: url)
                    if selectedFile == url {
                        validationReport = report
                    }
                }
            } catch {
                let message = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
                showAlert(title: "File Read Error", message: message)
            }
            
        case .failure(let error):
            showAlert(
                title: "File Error",
                message: error.localizedDescription
            )
        }
    }
    
    private func inspectSaoFile(at url: URL) throws -> SaoFileMetadata {
        let hasSecurityScope = url.startAccessingSecurityScopedResource()
        defer {
            if hasSecurityScope {
                url.stopAccessingSecurityScopedResource()
            }
        }
        
        var coordinatorError: NSError?
        var inspected: SaoFileMetadata?
        var readFailure = false
        
        let coordinator = NSFileCoordinator()
        try coordinator.coordinate(readingItemAt: url, options: [], error: &coordinatorError) { coordinatedURL in
            do {
                let values = try coordinatedURL.resourceValues(forKeys: [
                    .fileSizeKey,
                    .contentModificationDateKey
                ])
                
                let byteCount = Int64(values.fileSize ?? 0)
                let sizeText = ByteCountFormatter.string(fromByteCount: byteCount, countStyle: .file)
                
                let dateFormatter = DateFormatter()
                dateFormatter.dateStyle = .medium
                dateFormatter.timeStyle = .short
                let dateText = values.contentModificationDate.map { dateFormatter.string(from: $0) } ?? "Unknown"
                
                let handle = try FileHandle(forReadingFrom: coordinatedURL)
                defer { try? handle.close() }
                let headSlice = try handle.read(upToCount: 64) ?? Data()
                let preview = String(data: headSlice, encoding: .utf8)?
                    .replacingOccurrences(of: "\n", with: " ")
                    .trimmingCharacters(in: .whitespacesAndNewlines)
                
                inspected = SaoFileMetadata(
                    fileName: coordinatedURL.lastPathComponent,
                    fileSizeFormatted: sizeText,
                    modifiedDateFormatted: dateText,
                    previewText: preview
                )
            } catch {
                readFailure = true
            }
        }
        
        if let coordinatorError {
            throw AppError.networkFailure(coordinatorError.localizedDescription)
        }
        if readFailure || inspected == nil {
            throw AppError.fileAccessDenied
        }
        
        return inspected!
    }
    
    private func clearSelectedFile() {
        selectedFile = nil
        saoMetadata = nil
        validationReport = nil
        isValidatingSao = false
    }
    
    // MARK: - Footer
    
    private var footer: some View {
        VStack(spacing: 8) {
            Text("SAOIRSE'S TOOL")
                .font(.system(size: 10, weight: .heavy))
                .tracking(3)
                .foregroundStyle(secondaryText)
            
            Text("Designed with ✦")
                .font(.caption)
                .foregroundStyle(secondaryText)
        }
        .padding(.top, 10)
    }
    
    // MARK: - Section Title
    
    private func sectionTitle(
        _ title: String,
        icon: String
    ) -> some View {
        HStack(spacing: 10) {
            Image(systemName: icon)
                .foregroundStyle(pink)
            
            Text(title)
                .font(.headline)
                .foregroundStyle(primaryText)
        }
    }
    
    // MARK: - Settings Sheet
    
    private var settingsView: some View {
        ZStack {
            animatedGradient
                .ignoresSafeArea()
            
            backgroundOverlay
            
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    settingsHeader
                    webdavSettings
                    themeSettings
                    deviceSettings
                    aboutSettings
                }
                .padding(20)
                .padding(.bottom, 30)
            }
        }
        .preferredColorScheme(
            appAppearance == "Light"
            ? .light
            : appAppearance == "Dark"
            ? .dark
            : nil
        )
    }
    
    // MARK: - Settings Header
    
    private var settingsHeader: some View {
        HStack {
            VStack(alignment: .leading, spacing: 6) {
                Text("SETTINGS")
                    .font(.system(size: 12, weight: .heavy))
                    .tracking(3)
                    .foregroundStyle(primaryText)
                
                Text("Customize your tool")
                    .font(.title2.bold())
                    .foregroundStyle(primaryText)
            }
            
            Spacer()
            
            Button {
                showingSettings = false
            } label: {
                Image(systemName: "xmark.circle.fill")
                    .font(.title2)
                    .foregroundStyle(primaryText)
            }
        }
        .padding(.bottom, 5)
    }
    
    // MARK: - WebDAV Settings
    
    private var webdavSettings: some View {
        settingsCard {
            VStack(alignment: .leading, spacing: 18) {
                sectionTitle("WebDAV", icon: "server.rack")
                
                adaptiveTextField(
                    title: "Server URL",
                    placeholder: "https://example.com",
                    text: $webdavServer,
                    icon: "network"
                )
                
                adaptiveTextField(
                    title: "Username",
                    placeholder: "Username",
                    text: $webdavUsername,
                    icon: "person"
                )
                
                adaptiveTextField(
                    title: "Path to MLBB",
                    placeholder: "/",
                    text: $webdavPath,
                    icon: "folder"
                )
                
                adaptiveTextField(
                    title: "Password",
                    placeholder: "Password (temporary)",
                    text: $webdavPassword,
                    icon: "lock",
                    secure: true
                )
                
                HStack {
                    Image(systemName: "circle.fill")
                        .font(.system(size: 8))
                        .foregroundStyle(
                            webdavStatus == "Connected"
                            ? .green
                            : pink
                        )
                    
                    Text(webdavStatus)
                        .font(.subheadline.bold())
                        .foregroundStyle(primaryText)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                
                Button {
                    saveWebDAVSettings()
                } label: {
                    Text("Save Settings")
                        .font(.headline)
                        .foregroundStyle(.white)
                        .frame(maxWidth: .infinity)
                        .padding(15)
                        .background(
                            LinearGradient(
                                colors: [pink, purple],
                                startPoint: .leading,
                                endPoint: .trailing
                            )
                        )
                        .clipShape(RoundedRectangle(cornerRadius: 15))
                }
                .buttonStyle(AnimatedButtonStyle())
                
                Button {
                    Task {
                        await testWebDAVConnection()
                    }
                } label: {
                    HStack {
                        if isConnecting {
                            ProgressView()
                                .tint(pink)
                        }
                        
                        Text(isConnecting ? "Testing..." : "Test Connection")
                            .font(.headline)
                    }
                    .foregroundStyle(primaryText)
                    .frame(maxWidth: .infinity)
                    .padding(15)
                    .background(secondaryBackground)
                    .clipShape(RoundedRectangle(cornerRadius: 15))
                }
                .buttonStyle(AnimatedButtonStyle())
                .disabled(isConnecting)
                
                Text("Tests reachability using an HTTP OPTIONS request to your configured path.")
                    .font(.caption)
                    .foregroundStyle(secondaryText)
            }
        }
    }
    
    // MARK: - WebDAV Save & Connection Test
    
    private func saveWebDAVSettings() {
        let trimmedServer = webdavServer.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedServer.isEmpty else {
            showAlert(
                title: "Missing Server",
                message: AppError.missingWebDAVServer.errorDescription ?? "Please enter a WebDAV server URL."
            )
            return
        }
        
        webdavServer = trimmedServer
        let normalizedPath = webdavPath.trimmingCharacters(in: .whitespacesAndNewlines)
        webdavPath = normalizedPath.isEmpty ? "/" : (normalizedPath.hasPrefix("/") ? normalizedPath : "/\(normalizedPath)")
        
        showAlert(
            title: "Settings Saved",
            message: """
            Your WebDAV preferences have been saved locally.
            
            Server: \(webdavServer)
            Path: \(webdavPath)
            """
        )
    }
    
    private func buildWebDAVTargetURL() throws -> URL {
        let cleanedServer = webdavServer.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !cleanedServer.isEmpty else {
            throw AppError.missingWebDAVServer
        }
        
        var base = cleanedServer
        while base.hasSuffix("/") {
            base.removeLast()
        }
        
        var subPath = webdavPath.trimmingCharacters(in: .whitespacesAndNewlines)
        if subPath.isEmpty {
            subPath = "/"
        } else if !subPath.hasPrefix("/") {
            subPath = "/" + subPath
        }
        
        guard let url = URL(string: base + subPath), url.scheme != nil else {
            throw AppError.invalidURL("WebDAV")
        }
        
        return url
    }
    
    private func testWebDAVConnection() async {
        isConnecting = true
        defer { isConnecting = false }
        
        do {
            let targetURL = try buildWebDAVTargetURL()
            var request = URLRequest(url: targetURL)
            request.httpMethod = "OPTIONS"
            request.timeoutInterval = 15
            
            if !webdavUsername.isEmpty || !webdavPassword.isEmpty {
                let credentials = "\(webdavUsername):\(webdavPassword)"
                if let authData = credentials.data(using: .utf8) {
                    request.setValue("Basic \(authData.base64EncodedString())", forHTTPHeaderField: "Authorization")
                }
            }
            
            let (_, response) = try await URLSession.shared.data(for: request)
            
            guard let httpResponse = response as? HTTPURLResponse else {
                throw AppError.networkFailure("Invalid HTTP response from WebDAV server.")
            }
            
            guard (200...299).contains(httpResponse.statusCode) || httpResponse.statusCode == 405 else {
                throw AppError.httpStatus(httpResponse.statusCode, "WebDAV endpoint rejected connection.")
            }
            
            webdavStatus = "Connected"
            showAlert(
                title: "Connection Successful",
                message: "Reached \(targetURL.absoluteString) (HTTP \(httpResponse.statusCode))."
            )
        } catch {
            webdavStatus = "Failed"
            let message = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
            showAlert(title: "Connection Failed", message: message)
        }
    }
    
    // MARK: - Theme Settings
    
    private var themeSettings: some View {
        settingsCard {
            VStack(alignment: .leading, spacing: 18) {
                sectionTitle("Appearance", icon: "paintpalette")
                
                Text("Theme")
                    .font(.subheadline.bold())
                    .foregroundStyle(primaryText)
                
                themePicker
                
                Divider()
                    .overlay(secondaryText.opacity(0.2))
                
                Text("Interface Mode")
                    .font(.subheadline.bold())
                    .foregroundStyle(primaryText)
                
                appearancePicker
            }
        }
    }
    
    // MARK: - Theme Picker
    
    private var themePicker: some View {
        VStack(spacing: 10) {
            themeOption(
                "Blossom",
                color: Color(red: 0.95, green: 0.45, blue: 0.75)
            )
            
            themeOption(
                "Lavender",
                color: Color(red: 0.72, green: 0.55, blue: 0.95)
            )
            
            themeOption(
                "Rose",
                color: Color(red: 0.95, green: 0.40, blue: 0.60)
            )
            
            themeOption(
                "Sky",
                color: Color(red: 0.40, green: 0.70, blue: 0.95)
            )
        }
    }
    
    private func themeOption(
        _ name: String,
        color: Color
    ) -> some View {
        Button {
            withAnimation(.easeInOut(duration: 0.4)) {
                appTheme = name
            }
        } label: {
            HStack {
                Circle()
                    .fill(color)
                    .frame(width: 25, height: 25)
                
                Text(name)
                    .font(.subheadline.weight(.medium))
                    .foregroundStyle(primaryText)
                
                Spacer()
                
                if appTheme == name {
                    Image(systemName: "checkmark.circle.fill")
                        .foregroundStyle(color)
                }
            }
            .padding(14)
            .background(secondaryBackground)
            .clipShape(RoundedRectangle(cornerRadius: 15))
        }
        .buttonStyle(.plain)
    }
    
    // MARK: - Appearance Picker
    
    private var appearancePicker: some View {
        VStack(spacing: 10) {
            appearanceOption("System", icon: "iphone")
            appearanceOption("Light", icon: "sun.max.fill")
            appearanceOption("Dark", icon: "moon.fill")
        }
    }
    
    private func appearanceOption(
        _ name: String,
        icon: String
    ) -> some View {
        Button {
            withAnimation(.easeInOut(duration: 0.3)) {
                appAppearance = name
            }
        } label: {
            HStack {
                Image(systemName: icon)
                    .foregroundStyle(pink)
                    .frame(width: 25)
                
                Text(name)
                    .foregroundStyle(primaryText)
                
                Spacer()
                
                if appAppearance == name {
                    Image(systemName: "checkmark.circle.fill")
                        .foregroundStyle(pink)
                }
            }
            .padding(14)
            .background(secondaryBackground)
            .clipShape(RoundedRectangle(cornerRadius: 15))
        }
        .buttonStyle(.plain)
    }
    
    // MARK: - Device Settings
    
    private var deviceSettings: some View {
        settingsCard {
            VStack(alignment: .leading, spacing: 15) {
                sectionTitle("Device ID", icon: "iphone.gen3")
                
                Text(deviceUUID)
                    .font(.system(size: 12, design: .monospaced))
                    .foregroundStyle(primaryText)
                    .textSelection(.enabled)
                
                Button {
                    UIPasteboard.general.string = deviceUUID
                    
                    showAlert(
                        title: "Copied",
                        message: "Device ID copied."
                    )
                } label: {
                    Label(
                        "Copy Device ID",
                        systemImage: "doc.on.doc"
                    )
                    .font(.subheadline.bold())
                    .foregroundStyle(pink)
                }
            }
        }
    }
    
    // MARK: - About
    
    private var aboutSettings: some View {
        settingsCard {
            VStack(alignment: .leading, spacing: 12) {
                sectionTitle("About", icon: "info.circle")
                
                Text("Saoirse's Tool")
                    .font(.headline)
                    .foregroundStyle(primaryText)
                
                Text("V1.1.0 Candy")
                    .font(.caption)
                    .foregroundStyle(secondaryText)
            }
        }
    }
    
    // MARK: - Card Builder
    
    private func settingsCard<Content: View>(
        @ViewBuilder content: () -> Content
    ) -> some View {
        content()
            .padding(18)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(cardColor)
            .clipShape(RoundedRectangle(cornerRadius: 25))
            .overlay {
                RoundedRectangle(cornerRadius: 25)
                    .strokeBorder(
                        pink.opacity(0.25),
                        lineWidth: 1
                    )
            }
    }
    
    // MARK: - Adaptive Input
    
    private func adaptiveTextField(
        title: String,
        placeholder: String,
        text: Binding<String>,
        icon: String,
        secure: Bool = false
    ) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title)
                .font(.subheadline.bold())
                .foregroundStyle(primaryText)
            
            HStack(spacing: 10) {
                Image(systemName: icon)
                    .foregroundStyle(pink)
                
                Group {
                    if secure {
                        SecureField(placeholder, text: text)
                    } else {
                        TextField(placeholder, text: text)
                    }
                }
                .foregroundStyle(primaryText)
                .tint(pink)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
            }
            .padding(14)
            .background(secondaryBackground)
            .clipShape(RoundedRectangle(cornerRadius: 15))
        }
    }
    
    // MARK: - Gradient Animation
    
    private func startGradientAnimation() {
        withAnimation(
            .easeInOut(duration: 5)
            .repeatForever(autoreverses: true)
        ) {
            animateGradient = true
        }
    }
    
    // MARK: - Alert
    
    private func showAlert(
        title: String,
        message: String
    ) {
        alertTitle = title
        alertMessage = message
        showingAlert = true
    }
}

// MARK: - Button Animation

struct AnimatedButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .scaleEffect(configuration.isPressed ? 0.96 : 1.0)
            .opacity(configuration.isPressed ? 0.85 : 1.0)
            .animation(
                .easeInOut(duration: 0.15),
                value: configuration.isPressed
            )
    }
}
