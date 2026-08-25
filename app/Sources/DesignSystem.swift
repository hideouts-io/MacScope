import SwiftUI

enum MacScopeStyle {
    static let cornerRadius: CGFloat = 14
    static let contentSpacing: CGFloat = 18
    static let maximumReadableWidth: CGFloat = 1_180

    static func severityColor(_ severity: String) -> Color {
        switch severity.lowercased() {
        case "critical": .purple
        case "high": .red
        case "medium": .orange
        case "low": .yellow
        default: .blue
        }
    }

    static func coverageColor(_ status: String) -> Color {
        switch status.lowercased() {
        case "complete": .green
        case "partial": .orange
        case "failed": .red
        default: .secondary
        }
    }
}

struct CardModifier: ViewModifier {
    func body(content: Content) -> some View {
        content
            .padding(18)
            .background(.background.secondary)
            .clipShape(RoundedRectangle(cornerRadius: MacScopeStyle.cornerRadius, style: .continuous))
            .overlay {
                RoundedRectangle(cornerRadius: MacScopeStyle.cornerRadius, style: .continuous)
                    .stroke(.separator.opacity(0.7), lineWidth: 1)
            }
    }
}

extension View {
    func macScopeCard() -> some View {
        modifier(CardModifier())
    }
}

struct SectionHeading: View {
    let eyebrow: String
    let title: String
    let subtitle: String

    var body: some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(eyebrow.uppercased())
                .font(.caption.weight(.semibold))
                .foregroundStyle(.red)
                .tracking(0.8)
            Text(title)
                .font(.system(size: 30, weight: .bold, design: .rounded))
            Text(subtitle)
                .font(.body)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .accessibilityElement(children: .combine)
    }
}

struct StatusPill: View {
    let text: String
    let color: Color
    let symbol: String

    var body: some View {
        Label(text, systemImage: symbol)
            .font(.caption.weight(.semibold))
            .foregroundStyle(color)
            .padding(.horizontal, 9)
            .padding(.vertical, 5)
            .background(color.opacity(0.12), in: Capsule())
            .accessibilityLabel(text)
    }
}

struct EmptyState: View {
    let symbol: String
    let title: String
    let message: String

    var body: some View {
        VStack(spacing: 12) {
            Image(systemName: symbol)
                .font(.system(size: 36, weight: .light))
                .foregroundStyle(.secondary)
            Text(title)
                .font(.title3.weight(.semibold))
            Text(message)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 460)
        }
        .frame(maxWidth: .infinity, minHeight: 260)
        .macScopeCard()
    }
}
