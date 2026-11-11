import CryptoTokenKit
import Foundation

/// PC/SC reader access through CryptoTokenKit (any CCID contactless reader, e.g. ACR122U, ACR1252U).
public final class SmartCardTransport: CardTransport {
    let card: TKSmartCard
    public let readerName: String

    private init(card: TKSmartCard, readerName: String) {
        self.card = card
        self.readerName = readerName
    }

    public static var readerNames: [String] { TKSmartCardSlotManager.default?.slotNames ?? [] }

    /// Waits until a card is present on the named reader (or the first reader) and opens a session.
    public static func connect(reader: String? = nil, timeout: TimeInterval = 30,
                               status: (String) -> Void = { _ in }) async throws -> SmartCardTransport {
        guard let manager = TKSmartCardSlotManager.default else {
            throw MRTDError.transport("Smart card services are not available")
        }
        guard let name = reader ?? manager.slotNames.first else {
            throw MRTDError.transport("No NFC/smart card reader found. Connect a PC/SC contactless reader.")
        }
        guard let slot = await manager.getSlot(withName: name) else {
            throw MRTDError.transport("Reader \(name) is not available")
        }
        let deadline = Date().addingTimeInterval(timeout)
        var announced = false
        while slot.state != .validCard {
            try Task.checkCancellation()
            if slot.state == .missing { throw MRTDError.transport("Reader \(name) was disconnected") }
            if !announced { status("Place the document on the reader…"); announced = true }
            if Date() > deadline { throw MRTDError.transport("No document detected on the reader") }
            try await Task.sleep(nanoseconds: 200_000_000)
        }
        guard let card = slot.makeSmartCard() else { throw MRTDError.transport("Could not access the card") }
        guard try await card.beginSession() else { throw MRTDError.transport("Could not open a session with the card") }
        return SmartCardTransport(card: card, readerName: name)
    }

    public var atr: Bytes { card.slot.atr.map { Bytes($0.bytes) } ?? [] }

    public func transmit(_ apdu: Bytes) async throws -> Bytes {
        do {
            return Bytes(try await card.transmit(Data(apdu)))
        } catch {
            throw MRTDError.transport("\(error.localizedDescription) – keep the document still on the reader")
        }
    }

    private var sessionOpen = true
    private let lock = NSLock()

    /// Ends the card session. Safe to call more than once: TKSmartCard asserts (crashes the process)
    /// if endSession is called on a session that is already closed.
    public func close() {
        lock.lock()
        defer { lock.unlock() }
        guard sessionOpen else { return }
        sessionOpen = false
        // A removed card is already invalid and its session gone; ending it again also asserts.
        if card.isValid { card.endSession() }
    }

    deinit { close() }
}
