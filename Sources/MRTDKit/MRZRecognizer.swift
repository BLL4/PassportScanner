import Foundation

/// Turns noisy OCR output into a validated MRZ. OCR engines commonly confuse
/// O/0, I/1, S/5, B/8 etc. and drop or merge '<' fillers, so this normalises
/// candidate lines and uses the check digits to choose between alternatives.
public enum MRZRecognizer {
    static let letterToDigit: [Character: Character] = [
        "O": "0", "Q": "0", "D": "0", "U": "0", "I": "1", "L": "1", "T": "1", "Z": "2", "S": "5", "B": "8", "G": "6", "A": "4",
    ]
    static let digitToLetter: [Character: Character] = [
        "0": "O", "1": "I", "2": "Z", "5": "S", "8": "B", "6": "G", "4": "A",
    ]

    /// Normalises a single OCR line into MRZ alphabet characters.
    public static func normalize(_ line: String) -> String {
        var s = line.uppercased()
        for (from, to) in [("«", "<<"), ("‹", "<"), ("〈", "<"), ("(", "<"), ("{", "<"), ("[", "<"), ("К", "K"), ("С", "C"), ("Е", "E"), ("О", "O")] {
            s = s.replacingOccurrences(of: from, with: to)
        }
        s = s.filter { !$0.isWhitespace }
        return String(s.compactMap { c -> Character? in
            if MRZ.isMRZChar(c) { return c }
            return nil
        })
    }

    /// Finds a valid MRZ among recognised text lines (in reading order).
    public static func find(in rawLines: [String]) -> MRZ? {
        let lines = rawLines.map(normalize).filter { $0.count >= 26 && $0.contains("<") || $0.count >= 28 }
        var best: MRZ?
        for (len, count) in [(44, 2), (30, 3), (36, 2)] {
            let candidates = lines.compactMap { fit($0, to: len) }
            guard candidates.count >= count else { continue }
            for start in 0...(candidates.count - count) {
                let group = Array(candidates[start..<start + count])
                if let mrz = correct(group) {
                    if mrz.allValid { return mrz }
                    if best == nil { best = mrz }
                }
            }
        }
        if best == nil { best = findTD1KeyLines(lines) }
        return best
    }

    /// TD1 (ID card): only lines 1 (document number) and 2 (dates) are needed for chip access, and the
    /// lines may come from different camera frames. Tries every ordered pair of 30-character lines,
    /// using a recognised third line if there is one and fillers otherwise.
    static func findTD1KeyLines(_ lines: [String]) -> MRZ? {
        var candidates: [String] = []
        for l in lines.compactMap({ fit($0, to: 30) }) where !candidates.contains(l) { candidates.append(l) }
        guard candidates.count >= 2, candidates.count <= 12 else { return nil }
        let isLine1 = { (l: String) in ["I", "A", "C"].contains(l.first) }
        let nameLine = candidates.first { l in !isLine1(l) && l.prefix(6).allSatisfy(\.isLetter) && l.contains("<<") }
        var best: MRZ?
        for l1 in candidates where isLine1(l1) {
            for l2 in candidates where l2 != l1 && l2 != nameLine && !isLine1(l2) {
                guard let m = correct([l1, l2, nameLine ?? String(repeating: "<", count: 30)]) else { continue }
                if m.allValid { return m }
                if best == nil { best = m }
            }
        }
        return best
    }

    /// Accepts lines whose length is close to `len`, padding or trimming trailing fillers.
    static func fit(_ s: String, to len: Int) -> String? {
        if s.count == len { return s }
        if s.count < len && s.count >= len - 3 { return s + String(repeating: "<", count: len - s.count) }
        if s.count > len && s.count <= len + 3 {
            let extra = s.suffix(s.count - len)
            if extra.allSatisfy({ $0 == "<" }) { return String(s.prefix(len)) }
        }
        return nil
    }

    /// Applies field-aware corrections and returns an MRZ whose key fields validate.
    static func correct(_ lines: [String]) -> MRZ? {
        var l = lines.map { Array($0) }
        func digits(_ line: Int, _ r: Range<Int>) {
            for i in r where i < l[line].count {
                if let d = letterToDigit[l[line][i]] { l[line][i] = d }
            }
        }
        func letters(_ line: Int, _ r: Range<Int>) {
            for i in r where i < l[line].count {
                if let c = digitToLetter[l[line][i]] { l[line][i] = c }
            }
        }

        let docRange: Range<Int>
        let docLine: Int
        if lines.count == 3 {
            // TD1
            letters(0, 0..<5)
            digits(1, 0..<7)      // birth date + check
            digits(1, 8..<15)     // expiry + check
            letters(1, 15..<18)   // nationality
            digits(1, 29..<30)
            letters(2, 0..<30)
            docLine = 0
            docRange = 5..<14
            digits(0, 14..<15)
        } else {
            letters(0, 0..<l[0].count)
            digits(1, 13..<20)
            digits(1, 21..<28)
            letters(1, 10..<13)
            digits(1, 9..<10)
            digits(1, l[1].count - 1..<l[1].count)
            docLine = 1
            docRange = 0..<9
        }
        // OCR often reads a '<' inside a run of fillers as 'K'.
        for i in 0..<l.count {
            let s = String(l[i]).replacingOccurrences(of: "<<K<<", with: "<<<<<")
            l[i] = Array(s)
        }

        guard var mrz = try? MRZ(lines: l.map { String($0) }) else { return nil }
        if mrz.keyFieldsValid { return mrz }

        // Try ambiguous substitutions in the document number until its check digit matches.
        if !mrz.documentNumberValid {
            let ambiguous: [Character: [Character]] = [
                "0": ["O", "D"], "O": ["0", "D"], "D": ["0", "O"], "1": ["I"], "I": ["1"], "5": ["S"], "S": ["5"],
                "8": ["B"], "B": ["8"], "2": ["Z"], "Z": ["2"], "6": ["G"], "G": ["6"],
            ]
            let positions = docRange.filter { ambiguous[l[docLine][$0]] != nil }
            guard positions.count <= 8 else { return nil }
            var found: MRZ?
            func search(_ idx: Int) {
                if found != nil { return }
                if idx == positions.count {
                    if let m = try? MRZ(lines: l.map { String($0) }), m.documentNumberValid { found = m }
                    return
                }
                let p = positions[idx]
                let orig = l[docLine][p]
                search(idx + 1)
                for alt in ambiguous[orig] ?? [] {
                    l[docLine][p] = alt
                    search(idx + 1)
                }
                l[docLine][p] = orig
            }
            search(0)
            if let f = found { mrz = f }
        }
        return mrz.keyFieldsValid ? mrz : nil
    }
}
