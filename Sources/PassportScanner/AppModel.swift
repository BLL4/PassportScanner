import AppKit
import MRTDKit
import SwiftUI

enum DocumentKind: String {
    case chip, license
}

enum AccessMode: String, CaseIterable, Identifiable {
    case mrz = "MRZ"
    case can = "CAN"
    var id: String { rawValue }
}

@MainActor
final class AppModel: ObservableObject {
    @Published var documentKind: DocumentKind = .chip {
        didSet { if oldValue != documentKind { errorMessage = nil } }
    }
    /// Driver's license decoded from its barcode.
    @Published var license: DriverLicense?

    // Access key input
    @Published var accessMode: AccessMode = .mrz
    @Published var documentNumber = ""
    @Published var dateOfBirth = ""
    @Published var dateOfExpiry = ""
    @Published var can = ""
    /// MRZ recognised from the camera or an image, shown for reference.
    @Published var scannedMRZ: MRZ?

    // Reader
    @Published var readers: [String] = []
    @Published var selectedReader: String?

    // Reading state
    @Published var isReading = false
    @Published var progress: Double = 0
    @Published var step = ""
    @Published var log: [String] = []
    @Published var result: PassportData?
    @Published var errorMessage: String?
    @Published var readFaceImage = true

    @Published var showCamera = false

    /// Trusted CSCA certificates, kept between launches.
    @Published private(set) var csca: CSCAStore
    static let cscaURL = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        .appendingPathComponent("PassportScanner/csca-certificates.der")

    private var readTask: Task<Void, Never>?
    private var readerTimer: Timer?

    init() {
        csca = CSCAStore.load(from: AppModel.cscaURL)
        refreshReaders()
        readerTimer = Timer.scheduledTimer(withTimeInterval: 1.5, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.refreshReaders() }
        }
    }

    func refreshReaders() {
        let names = SmartCardTransport.readerNames
        if names != readers { readers = names }
        if selectedReader == nil || !names.contains(selectedReader!) {
            // Prefer the contactless interface of dual readers.
            selectedReader = names.first { $0.localizedCaseInsensitiveContains("PICC") || $0.localizedCaseInsensitiveContains("contactless") } ?? names.first
        }
    }

    var mrzKey: MRZKey {
        MRZKey(documentNumber: documentNumber, dateOfBirth: dateOfBirth, dateOfExpiry: dateOfExpiry)
    }

    var keyError: String? {
        switch accessMode {
        case .mrz:
            if documentNumber.isEmpty && dateOfBirth.isEmpty && dateOfExpiry.isEmpty { return "Scan the MRZ or enter the data" }
            return mrzKey.validationError
        case .can:
            return can.count >= 6 && can.allSatisfy(\.isNumber) ? nil : "The CAN has 6 digits"
        }
    }

    var canRead: Bool { !isReading && keyError == nil && selectedReader != nil }

    func apply(_ dl: DriverLicense) {
        license = dl
        documentKind = .license
        errorMessage = nil
    }

    func apply(_ mrz: MRZ) {
        scannedMRZ = mrz
        documentNumber = mrz.documentNumber
        dateOfBirth = mrz.dateOfBirth
        dateOfExpiry = mrz.dateOfExpiry
        accessMode = .mrz
        documentKind = .chip
    }

    func scanImageFile() {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [.image, .pdf]
        panel.message = documentKind == .license
            ? "Choose a photo of the back of the driver's license (with the barcode)"
            : "Choose a photo or scan of the passport / ID card page with the MRZ"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        scanImage(at: url)
    }

    func scanImage(at url: URL) {
        guard let image = NSImage(contentsOf: url), let cg = image.cgImage(forProposedRect: nil, context: nil, hints: nil) else {
            errorMessage = "Could not open the image"
            return
        }
        Task {
            // A photo may show either a license barcode or an MRZ; try both.
            if let dl = await BarcodeRecognizer.recognize(cgImage: cg) {
                apply(dl)
            } else if let mrz = await MRZTextRecognizer.recognize(cgImage: cg) {
                apply(mrz)
                errorMessage = nil
            } else {
                errorMessage = documentKind == .license
                    ? "No driver's license barcode found in the image. Make sure the whole barcode is sharp and visible."
                    : "No valid MRZ found in the image. Make sure the 2–3 lines with <<< are sharp and fully visible."
            }
        }
    }

    func read() {
        guard canRead else { return }
        let key: AccessKey = accessMode == .mrz ? .mrz(mrzKey) : .can(can)
        let readerName = selectedReader
        isReading = true
        errorMessage = nil
        result = nil
        log = []
        progress = 0
        step = "Connecting…"
        let wantImage = readFaceImage

        readTask = Task { [weak self] in
            let addLog: (String) -> Void = { line in Task { @MainActor in self?.log.append(line) } }
            do {
                let transport = try await SmartCardTransport.connect(reader: readerName, timeout: 60) { s in
                    Task { @MainActor in self?.step = s }
                }
                defer { transport.close() }
                addLog("Reader: \(transport.readerName), ATR \(transport.atr.hex)")
                let reader = PassportReader(transport: transport, log: addLog)
                reader.options.readFaceImage = wantImage
                reader.options.csca = await MainActor.run { self?.csca }
                let data = try await reader.read(key: key) { p in
                    Task { @MainActor in
                        self?.step = p.step
                        self?.progress = p.fraction
                    }
                }
                await MainActor.run {
                    self?.result = data
                    self?.step = "Done – you can remove the document"
                }
            } catch {
                let message: String
                if error is CancellationError || (error as? MRTDError).map({ if case .cancelled = $0 { return true } else { return false } }) == true {
                    message = "Cancelled"
                } else {
                    message = error.localizedDescription
                }
                await MainActor.run {
                    self?.errorMessage = message
                    self?.step = ""
                }
            }
            await MainActor.run { self?.isReading = false }
        }
    }

    func loadMasterList() {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = true
        panel.message = "Choose CSCA master lists (.ml, ICAO PKD .ldif) or certificates (.der, .cer, .pem)"
        guard panel.runModal() == .OK else { return }
        var found = 0, added = 0
        for url in panel.urls {
            guard let d = try? Data(contentsOf: url) else { continue }
            let certs = CSCAStore.certificates(fromFile: Bytes(d))
            found += certs.count
            added += csca.add(certs)
        }
        try? csca.save(to: AppModel.cscaURL)
        objectWillChange.send()
        cscaMessage = found == 0 ? "No certificates found in the selected file(s)"
            : "Loaded \(found) certificates (\(added) new). \(csca.certificates.count) CSCA certificates from \(csca.countries.count) countries."
        reverify()
    }

    func clearMasterList() {
        csca = CSCAStore()
        try? FileManager.default.removeItem(at: AppModel.cscaURL)
        cscaMessage = "CSCA certificates removed"
        reverify()
    }

    @Published var cscaMessage: String?

    /// Re-runs passive authentication of the current result, e.g. after loading CSCA certificates.
    private func reverify() {
        guard var r = result, let sod = r.sod else { return }
        r.passiveAuth = sod.verify(files: r.files, csca: csca)
        result = r
    }

    func cancel() {
        readTask?.cancel()
    }

    func clear() {
        result = nil
        license = nil
        scannedMRZ = nil
        documentNumber = ""
        dateOfBirth = ""
        dateOfExpiry = ""
        can = ""
        log = []
        errorMessage = nil
        step = ""
        progress = 0
    }
}
