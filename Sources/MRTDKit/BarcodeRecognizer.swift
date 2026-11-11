import CoreGraphics
import CoreVideo
import ImageIO
import Vision

/// Finds and decodes the PDF417 barcode on the back of US / Canadian driver's licenses.
public enum BarcodeRecognizer {
    public static func makeRequest() -> VNDetectBarcodesRequest {
        let r = VNDetectBarcodesRequest()
        r.symbologies = [.pdf417]
        return r
    }

    public static func license(from request: VNDetectBarcodesRequest) -> DriverLicense? {
        for obs in request.results ?? [] {
            if let text = obs.payloadStringValue, let dl = try? DriverLicense(barcode: text) { return dl }
        }
        return nil
    }

    public static func recognize(cgImage: CGImage) async -> DriverLicense? {
        await Task.detached(priority: .userInitiated) {
            let request = makeRequest()
            try? VNImageRequestHandler(cgImage: cgImage).perform([request])
            return license(from: request)
        }.value
    }

    public static func recognize(pixelBuffer: CVPixelBuffer) -> DriverLicense? {
        let request = makeRequest()
        try? VNImageRequestHandler(cvPixelBuffer: pixelBuffer).perform([request])
        return license(from: request)
    }
}
