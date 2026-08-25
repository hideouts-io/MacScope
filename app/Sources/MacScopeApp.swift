import SwiftUI

@main
@MainActor
struct MacScopeApp: App {
    @StateObject private var coordinator = ScanCoordinator()

    var body: some Scene {
        WindowGroup {
            RootView(coordinator: coordinator)
                .frame(minWidth: 1_080, minHeight: 720)
        }
        .windowStyle(.titleBar)
        .windowToolbarStyle(.unified(showsTitle: false))
        .commands {
            CommandGroup(after: .newItem) {
                Button("Start Standard Scan") {
                    coordinator.startStandardScan()
                }
                .keyboardShortcut("r", modifiers: [.command, .shift])
                .disabled(coordinator.phase.isActive)
            }
        }
    }
}
