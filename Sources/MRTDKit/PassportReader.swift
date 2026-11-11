import Foundation

public struct PassportData {
    public var accessControl: String = ""
    public var paceInfos: [PACEInfo] = []
    public var com: EFCOM?
    public var mrz: MRZ?
    public var faceImage: FaceImage?
    public var signatureImage: FaceImage?
    public var personalDetails: LabeledFields?
    public var documentDetails: LabeledFields?
    public var sod: SOD?
    public var passiveAuth: PassiveAuthResult?
    /// Raw file contents as read from the chip.
    public var files: [DataGroupID: Bytes] = [:]
    /// Files that could not be read, with the reason.
    public var errors: [DataGroupID: String] = [:]
    /// Biometric files (fingerprints, iris) that only government terminals may read (Extended Access Control).
    public var restricted: [DataGroupID] = []

    public init() {}
}

public struct ReadProgress {
    public var step: String
    public var fraction: Double
}

/// Reads an eMRTD (passport or ICAO-compliant ID card). Only reads: the commands used are
/// SELECT, READ BINARY, GET CHALLENGE and the authentication commands for BAC/PACE.
public final class PassportReader {
    public struct Options {
        public var readFaceImage = true
        public var readOptionalGroups = true
        public var preferPACE = true
        /// Trusted CSCA certificates for checking the Document Signer certificate.
        public var csca: CSCAStore?

        public init() {}
    }

    let chip: Chip
    public var options = Options()
    let log: (String) -> Void

    public init(transport: CardTransport, log: @escaping (String) -> Void = { _ in }) {
        self.log = log
        chip = Chip(transport: transport, log: log)
    }

    public func read(key: AccessKey, progress: @escaping (ReadProgress) -> Void = { _ in }) async throws -> PassportData {
        var result = PassportData()
        progress(ReadProgress(step: "Connecting to chip", fraction: 0.02))

        // EF.CardAccess tells whether the chip supports PACE (ID cards, newer passports).
        var cardAccess: Bytes?
        do {
            cardAccess = try await chip.readFile(sfi: 0x1C, name: "EF.CardAccess")
        } catch {
            log("No EF.CardAccess (\(error.localizedDescription)) – chip probably supports BAC only")
        }
        if let ca = cardAccess {
            result.paceInfos = PACEInfo.parse(cardAccess: ca)
            for info in result.paceInfos { log("Chip offers \(info) [\(info.oid)]") }
        }

        try await authenticate(key: key, paceInfos: result.paceInfos, result: &result, progress: progress)

        // EF.COM lists the available data groups; fall back to the SOD's list if it is missing.
        progress(ReadProgress(step: "Reading EF.COM", fraction: 0.15))
        var groups: [DataGroupID] = []
        if let com = try? await readGroup(.com, into: &result) {
            result.com = try? EFCOM(com)
            groups = result.com?.dataGroups ?? []
        }
        progress(ReadProgress(step: "Reading EF.SOD", fraction: 0.2))
        if let sodBytes = try? await readGroup(.sod, into: &result) {
            result.sod = try? SOD(sodBytes)
            if groups.isEmpty { groups = result.sod?.hashes.keys.sorted() ?? [] }
        }
        if groups.isEmpty { groups = [.dg1, .dg2] }

        var toRead = groups.filter { !$0.requiresEAC }
        if !options.readFaceImage { toRead.removeAll { $0 == .dg2 } }
        if !options.readOptionalGroups { toRead.removeAll { ![.dg1, .dg2].contains($0) } }
        for dg in groups where dg.requiresEAC {
            result.restricted.append(dg)
        }

        for (i, dg) in toRead.enumerated() {
            let base = 0.25 + 0.7 * Double(i) / Double(toRead.count)
            let span = 0.7 / Double(toRead.count)
            progress(ReadProgress(step: "Reading \(dg.name) – \(dg.title)", fraction: base))
            do {
                let bytes = try await readGroup(dg, into: &result) { f in
                    progress(ReadProgress(step: "Reading \(dg.name) – \(dg.title)", fraction: base + span * f))
                }
                parse(dg, bytes, into: &result)
            } catch is CancellationError {
                throw MRTDError.cancelled
            } catch {
                result.errors[dg] = error.localizedDescription
                log("\(dg.name): \(error.localizedDescription)")
                if chip.sm == nil {
                    // The chip dropped secure messaging; the remaining files cannot be read.
                    break
                }
            }
        }

        if let sod = result.sod {
            result.passiveAuth = sod.verify(files: result.files, csca: options.csca)
        }
        progress(ReadProgress(step: "Done", fraction: 1))
        return result
    }

    static func wrongKeyMessage(sw: UInt16) -> String {
        "Wrong access key (chip status \(String(format: "%04X", sw))): the document number, birth date and expiry date "
            + "– or the CAN – do not match the chip. Check them against the document."
    }

    private func authenticate(key: AccessKey, paceInfos: [PACEInfo], result: inout PassportData,
                              progress: (ReadProgress) -> Void) async throws {
        let supported = paceInfos.filter(\.isSupported)
        if options.preferPACE, let info = supported.first {
            progress(ReadProgress(step: "PACE authentication (\(info.cipher?.rawValue ?? ""), \(info.curve?.name ?? ""))", fraction: 0.05))
            do {
                try await PACE.perform(chip: chip, key: key, info: info)
                try await chip.selectApplication()
                result.accessControl = "PACE (\(info.description.dropFirst(5)))"
                log("PACE established")
                return
            } catch {
                log("PACE failed: \(error.localizedDescription)")
                chip.sm = nil
                guard case .mrz = key else { throw error }
                log("Trying BAC instead")
            }
        } else if !paceInfos.isEmpty && supported.isEmpty {
            log("Chip's PACE variants are not supported: \(paceInfos.map(\.description).joined(separator: "; "))")
        }

        guard case .mrz(let mrzKey) = key else {
            throw MRTDError.unsupported("This chip does not offer a supported PACE variant, so it cannot be opened with a CAN. Use the MRZ instead.")
        }
        progress(ReadProgress(step: "BAC authentication", fraction: 0.08))
        try await chip.selectApplication()
        try await BAC.perform(chip: chip, key: mrzKey)
        result.accessControl = "BAC (3DES)"
        log("BAC established")
    }

    private func readGroup(_ dg: DataGroupID, into result: inout PassportData, progress: ((Double) -> Void)? = nil) async throws -> Bytes {
        let bytes = try await chip.readFile(dg.fileID, name: dg.name, progress: progress)
        result.files[dg] = bytes
        return bytes
    }

    private func parse(_ dg: DataGroupID, _ bytes: Bytes, into result: inout PassportData) {
        do {
            switch dg {
            case .dg1: result.mrz = try DG1.parse(bytes)
            case .dg2: result.faceImage = try DG2.parse(bytes)
            case .dg7: result.signatureImage = try DG7.parse(bytes)
            case .dg11: result.personalDetails = try DG11.parse(bytes)
            case .dg12: result.documentDetails = try DG12.parse(bytes)
            default: break
            }
        } catch {
            result.errors[dg] = "Read but could not be parsed: \(error.localizedDescription)"
        }
    }
}
