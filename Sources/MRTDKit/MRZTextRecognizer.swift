import CoreGraphics
import ImageIO
import Vision

/// Runs Apple's on-device text recognition and hands the lines to `MRZRecognizer`.
public enum MRZTextRecognizer {
    public static func lines(from observations: [VNRecognizedTextObservation]) -> [String] {
        // Vision sometimes splits one MRZ line into several boxes: merge boxes on the same row.
        let items = observations.compactMap { o -> (CGRect, String)? in
            guard let t = o.topCandidates(1).first?.string else { return nil }
            return (o.boundingBox, t)
        }.sorted { $0.0.midY > $1.0.midY }
        var rows: [[(CGRect, String)]] = []
        for item in items {
            if let last = rows.last?.first, abs(last.0.midY - item.0.midY) < min(last.0.height, item.0.height) * 0.5 {
                rows[rows.count - 1].append(item)
            } else {
                rows.append([item])
            }
        }
        return rows.map { $0.sorted { $0.0.minX < $1.0.minX }.map(\.1).joined() }
    }

    public static func makeRequest() -> VNRecognizeTextRequest {
        let r = VNRecognizeTextRequest()
        r.recognitionLevel = .accurate
        r.usesLanguageCorrection = false
        r.recognitionLanguages = ["en-US"]
        return r
    }

    public static func recognize(handler: VNImageRequestHandler) -> MRZ? {
        let request = makeRequest()
        do { try handler.perform([request]) } catch { return nil }
        return MRZRecognizer.find(in: lines(from: request.results ?? []))
    }

    /// Tries the image in all four orientations (photos of documents are often rotated).
    public static func recognize(cgImage: CGImage) async -> MRZ? {
        await Task.detached(priority: .userInitiated) {
            for o: CGImagePropertyOrientation in [.up, .right, .left, .down] {
                if let m = recognize(handler: VNImageRequestHandler(cgImage: cgImage, orientation: o)) { return m }
            }
            return nil
        }.value
    }
}
