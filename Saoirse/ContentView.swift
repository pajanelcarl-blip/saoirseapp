import SwiftUI

struct ContentView: View {
    var body: some View {
        NavigationStack {
            VStack(spacing: 16) {
                Text("Saoirse")
                    .font(.largeTitle)
                    .fontWeight(.bold)

                Text("Welcome to your new iOS app")
                    .foregroundStyle(.secondary)
            }
            .navigationTitle("Saoirse")
        }
    }
}

#Preview {
    ContentView()
}
