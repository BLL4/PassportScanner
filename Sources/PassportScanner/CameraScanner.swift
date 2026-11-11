import AVFoundation
import MRTDKit
import SwiftUI
import Vision

/// Live camera capture that continuously looks for a valid MRZ.
enum CameraMode { case mrz, barcode }

final class CameraScanner: NSObject, ObservableObject, AVCaptureVideoDataOutputSampleBufferDelegate {
    var mode: CameraMode = .mrz
    var onLicense: ((DriverLicense) -> Void)?
    @Published var devices: [AVCaptureDevice] = []
    @Published var selectedDeviceID: String? {
        didSet { if oldValue != selectedDeviceID { configure() } }
    }
    @Published var status = "Starting camera…"
    @Published var lastSeen: [String] = []
    @Published var permissionDenied = false

    let session = AVCaptureSession()
    var onFound: ((MRZ) -> Void)?

    private let queue = DispatchQueue(label: "camera.mrz")
    private var busy = false
    private var frameCount = 0
    private var candidate: MRZKey?
    private var finished = false
    private var recentLines: [[String]] = []

    func start() {
        switch AVCaptureDevice.authorizationStatus(for: .video) {
        case .authorized:
            setup()
        case .notDetermined:
            AVCaptureDevice.requestAccess(for: .video) { ok in
                DispatchQueue.main.async { ok ? self.setup() : self.denied() }
            }
        default:
            denied()
        }
    }

    private func denied() {
        permissionDenied = true
        status = "Camera access denied. Allow it in System Settings → Privacy & Security → Camera."
    }

    private func setup() {
        let discovery = AVCaptureDevice.DiscoverySession(
            deviceTypes: [.builtInWideAngleCamera, .external, .continuityCamera, .deskViewCamera],
            mediaType: .video, position: .unspecified)
        devices = discovery.devices
        if selectedDeviceID == nil {
            selectedDeviceID = (AVCaptureDevice.default(for: .video) ?? devices.first)?.uniqueID
        } else {
            configure()
        }
    }

    private func configure() {
        guard let id = selectedDeviceID, let device = devices.first(where: { $0.uniqueID == id }) else {
            status = "No camera found"
            return
        }
        queue.async { [self] in
            session.beginConfiguration()
            session.inputs.forEach { session.removeInput($0) }
            if session.outputs.isEmpty {
                let output = AVCaptureVideoDataOutput()
                output.alwaysDiscardsLateVideoFrames = true
                output.setSampleBufferDelegate(self, queue: queue)
                if session.canAddOutput(output) { session.addOutput(output) }
            }
            if let input = try? AVCaptureDeviceInput(device: device), session.canAddInput(input) { session.addInput(input) }
            // Highest resolution available: ID-card MRZ characters are small.
            for preset: AVCaptureSession.Preset in [.hd4K3840x2160, .hd1920x1080, .high] where session.canSetSessionPreset(preset) {
                session.sessionPreset = preset
                break
            }
            session.commitConfiguration()
            if !session.isRunning { session.startRunning() }
            DispatchQueue.main.async {
                self.status = self.mode == .barcode
                    ? "Hold the barcode on the back of the license close to the camera, flat and well lit"
                    : "Hold the MRZ (the lines with <<<) close to the camera, flat and well lit. On ID cards it is on the back."
            }
        }
    }

    func stop() {
        queue.async { [self] in if session.isRunning { session.stopRunning() } }
    }

    func captureOutput(_ output: AVCaptureOutput, didOutput sampleBuffer: CMSampleBuffer, from connection: AVCaptureConnection) {
        frameCount += 1
        guard !busy, !finished, frameCount % 3 == 0, let pixels = CMSampleBufferGetImageBuffer(sampleBuffer) else { return }
        busy = true
        defer { busy = false }

        if mode == .barcode {
            // PDF417 has built-in error correction: a decoded AAMVA barcode can be accepted at once.
            guard let dl = BarcodeRecognizer.recognize(pixelBuffer: pixels) else { return }
            finished = true
            DispatchQueue.main.async {
                self.status = "Barcode recognised"
                self.onLicense?(dl)
            }
            return
        }

        // Alternate between normal and mirrored orientation (front cameras / mirrored Continuity Camera).
        let orientation: CGImagePropertyOrientation = (frameCount / 3) % 2 == 0 ? .up : .upMirrored
        let request = MRZTextRecognizer.makeRequest()
        try? VNImageRequestHandler(cvPixelBuffer: pixels, orientation: orientation).perform([request])
        let lines = MRZTextRecognizer.lines(from: request.results ?? [])
        let mrzish = lines.map(MRZRecognizer.normalize).filter { $0.contains("<") && $0.count >= 20 }
        if !mrzish.isEmpty { DispatchQueue.main.async { self.lastSeen = mrzish } }

        // Remember MRZ-like lines from the last few frames: on small ID cards the lines are often
        // recognised correctly in different frames rather than all at once.
        recentLines.append(mrzish)
        if recentLines.count > 6 { recentLines.removeFirst() }
        var mrz = MRZRecognizer.find(in: lines)
        if mrz?.allValid != true, let combined = MRZRecognizer.find(in: recentLines.flatMap { $0 }),
           combined.allValid || mrz == nil {
            mrz = combined
        }
        guard let mrz else { return }
        // Accept at once if every check digit is valid; otherwise require the same key twice.
        if mrz.allValid || candidate == mrz.key {
            finished = true
            DispatchQueue.main.async {
                self.status = "MRZ recognised"
                self.onFound?(mrz)
            }
        } else {
            candidate = mrz.key
        }
    }
}

struct CameraPreview: NSViewRepresentable {
    let session: AVCaptureSession

    func makeNSView(context: Context) -> NSView {
        let view = NSView()
        view.wantsLayer = true
        let layer = AVCaptureVideoPreviewLayer(session: session)
        layer.videoGravity = .resizeAspect
        layer.autoresizingMask = [.layerWidthSizable, .layerHeightSizable]
        view.layer = layer
        return view
    }

    func updateNSView(_ nsView: NSView, context: Context) {}
}

struct CameraSheet: View {
    @StateObject private var scanner = CameraScanner()
    @Environment(\.dismiss) private var dismiss
    var mode: CameraMode = .mrz
    let onFound: (MRZ) -> Void
    var onLicense: (DriverLicense) -> Void = { _ in }

    var body: some View {
        VStack(spacing: 12) {
            HStack {
                Text(mode == .barcode ? "Scan license barcode with camera" : "Scan MRZ with camera").font(.headline)
                Spacer()
                if scanner.devices.count > 1 {
                    Picker("Camera", selection: $scanner.selectedDeviceID) {
                        ForEach(scanner.devices, id: \.uniqueID) { d in Text(d.localizedName).tag(Optional(d.uniqueID)) }
                    }
                    .frame(maxWidth: 260)
                }
            }
            ZStack {
                Color.black
                CameraPreview(session: scanner.session)
                RoundedRectangle(cornerRadius: 8)
                    .strokeBorder(Color.green.opacity(0.8), style: StrokeStyle(lineWidth: 2, dash: [8, 6]))
                    .frame(width: 560, height: 170)
                    .overlay(alignment: .bottom) {
                        Text(mode == .barcode ? "Place the barcode here" : "Place the MRZ lines here")
                            .font(.caption).foregroundStyle(.green).offset(y: 18)
                    }
            }
            .frame(width: 720, height: 405)
            .clipShape(RoundedRectangle(cornerRadius: 8))

            Text(scanner.status).font(.callout).foregroundStyle(scanner.permissionDenied ? .red : .secondary)
            if !scanner.lastSeen.isEmpty {
                Text(scanner.lastSeen.joined(separator: "\n"))
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .lineLimit(3)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            if mode == .barcode {
                Text("Tips: Fill the box with the barcode and avoid glare. An iPhone via Continuity Camera or a photo (“Open Image…”) works best: the barcode is dense, and Mac webcams often can't focus close enough.")
                    .font(.caption).foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
            } else {
            VStack(alignment: .leading, spacing: 2) {
                Text("Tips: Fill the box with the MRZ, avoid glare from lamps, and tilt slightly if the card reflects. Only the first two lines are needed.")
                Text("European ID card? Using the 6-digit CAN printed on the front is usually quicker than scanning.")
                Text("An iPhone works as a sharper camera via Continuity Camera; a photo of the card (“Open Image…”) also works well.")
            }
            .font(.caption).foregroundStyle(.secondary)
            .frame(maxWidth: .infinity, alignment: .leading)
            }
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
            }
        }
        .padding()
        .onAppear {
            scanner.mode = mode
            scanner.onFound = { mrz in
                onFound(mrz)
                dismiss()
            }
            scanner.onLicense = { dl in
                onLicense(dl)
                dismiss()
            }
            scanner.start()
        }
        .onDisappear { scanner.stop() }
    }
}
