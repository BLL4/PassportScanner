import Foundation

/// Builds file and folder names from untrusted document data (chip contents, barcodes).
/// A malicious chip can put anything into its name fields, e.g. "../../", so such data must never
/// reach a path unfiltered.
public enum SafeFileName {
    /// Keeps only ASCII letters, digits, '-' and '_' (everything else becomes '_'), collapses runs,
    /// and limits the length. Never returns an empty name, "." or "..".
    public static func make(_ parts: [String?], fallback: String = "document", maxLength: Int = 64) -> String {
        let joined = parts.compactMap { $0 }.filter { !$0.isEmpty }.joined(separator: "_")
        var out = ""
        for scalar in joined.unicodeScalars {
            let c = Character(scalar)
            let ok = scalar.isASCII && (c.isLetter || c.isNumber || c == "-" || c == "_")
            if ok {
                out.append(c)
            } else if out.last != "_" {
                out.append("_")
            }
        }
        out = String(out.trimmingCharacters(in: CharacterSet(charactersIn: "_-")).prefix(maxLength))
        return out.isEmpty ? fallback : out
    }

    /// Returns `base/name`, throwing if the result would not be strictly inside `base`
    /// (defence in depth in case a name was not built with `make`).
    public static func child(of base: URL, _ name: String) throws -> URL {
        let root = base.standardizedFileURL.resolvingSymlinksInPath()
        let candidate = root.appendingPathComponent(name).standardizedFileURL.resolvingSymlinksInPath()
        let rootPath = root.path.hasSuffix("/") ? root.path : root.path + "/"
        guard name != "." && name != ".." && !name.contains("/") && candidate.path.hasPrefix(rootPath) else {
            throw CocoaError(.fileWriteInvalidFileName, userInfo: [NSFilePathErrorKey: candidate.path])
        }
        return candidate
    }
}
