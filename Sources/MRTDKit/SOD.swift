import Foundation
import Security

/// Minimal X.509 certificate view, enough to show the Document Signer and verify with its key.
public struct Certificate {
    public let der: Bytes
    public let subject: [(String, String)]
    public let issuer: [(String, String)]
    public let notBefore: Date?
    public let notAfter: Date?
    public let serialNumber: Bytes
    let publicKeyAlgorithm: TLV
    let publicKeyBits: Bytes
    /// DER of the issuer / subject Name, compared byte-wise when looking for the issuing CSCA.
    let issuerDER: Bytes
    let subjectDER: Bytes
    let tbsDER: Bytes
    let signatureAlgorithm: TLV
    let signatureValue: Bytes
    public let subjectKeyIdentifier: Bytes?
    public let authorityKeyIdentifier: Bytes?
    /// basicConstraints cA flag.
    public let isCA: Bool

    public init(der: Bytes) throws {
        let (cert, _) = try TLV.parse(der)
        self.der = cert.encoded
        let parts = cert.children
        guard cert.tag == 0x30, parts.count == 3, parts[0].tag == 0x30, parts[1].tag == 0x30, parts[2].tag == 0x03 else {
            throw MRTDError.malformed("certificate")
        }
        tbsDER = parts[0].encoded
        signatureAlgorithm = parts[1]
        signatureValue = Array(parts[2].value.dropFirst()) // unused-bits byte
        var fields = parts[0].children
        if fields.first?.tag == 0xA0 { fields.removeFirst() } // version
        guard fields.count >= 6 else { throw MRTDError.malformed("certificate fields") }
        serialNumber = fields[0].value
        issuerDER = fields[2].encoded
        issuer = Certificate.name(fields[2])
        let validity = fields[3].children
        notBefore = validity.first.flatMap(ASN1.date)
        notAfter = validity.count > 1 ? ASN1.date(validity[1]) : nil
        subjectDER = fields[4].encoded
        subject = Certificate.name(fields[4])
        let spki = fields[5].children
        guard spki.count == 2, spki[1].tag == 0x03 else { throw MRTDError.malformed("subject public key info") }
        publicKeyAlgorithm = spki[0]
        publicKeyBits = Array(spki[1].value.dropFirst()) // unused-bits byte

        var ski: Bytes?, aki: Bytes?, ca = false
        for ext in fields.first(where: { $0.tag == 0xA3 })?.child(0x30)?.children ?? [] {
            guard let oid = ext.child(0x06).map({ ASN1.decodeOID($0.value) }), let value = ext.child(0x04)?.value,
                  let (inner, _) = try? TLV.parse(value) else { continue }
            switch oid {
            case "2.5.29.14": ski = inner.value
            case "2.5.29.35": aki = inner.child(0x80)?.value
            case "2.5.29.19": ca = inner.child(0x01)?.value.first.map { $0 != 0 } ?? false
            default: break
            }
        }
        subjectKeyIdentifier = ski
        authorityKeyIdentifier = aki
        isCA = ca
    }

    /// Verifies `signature` over `data` with this certificate's public key. `fallbackHash` is used when
    /// the algorithm identifier does not name a hash (plain rsaEncryption / ecPublicKey in CMS).
    func verify(signature: Bytes, algorithm: TLV?, data: Bytes, fallbackHash: HashAlgorithm?) -> PassiveAuthResult.Status {
        let signedBytes = data
        let sigOID = algorithm?.child(0x06).map { ASN1.decodeOID($0.value) } ?? ""
        let keyOID = publicKeyAlgorithmOID

        if keyOID == "1.2.840.10045.2.1" {
            let hashAlg: HashAlgorithm
            switch sigOID {
            case "1.2.840.10045.4.1": hashAlg = .sha1
            case "1.2.840.10045.4.3.1": hashAlg = .sha224
            case "1.2.840.10045.4.3.2": hashAlg = .sha256
            case "1.2.840.10045.4.3.3": hashAlg = .sha384
            case "1.2.840.10045.4.3.4": hashAlg = .sha512
            default:
                guard let f = fallbackHash else { return .notChecked("signature algorithm \(sigOID)") }
                hashAlg = f
            }
            guard let group = ecGroup(), let q = group.decode(publicKeyBits) else {
                return .notChecked("unsupported EC key parameters")
            }
            guard let (seq, _) = try? TLV.parse(signature), seq.children.count == 2 else { return .invalid("malformed ECDSA signature") }
            let ok = group.verify(digest: hashAlg.hash(signedBytes), r: seq.children[0].value, s: seq.children[1].value, publicKey: q)
            return ok ? .valid : .invalid("ECDSA signature does not verify")
        }

        if keyOID == "1.2.840.113549.1.1.1" || keyOID == "1.2.840.113549.1.1.10" {
            if sigOID == "1.2.840.113549.1.1.10" {
                return RSAPSS.verify(publicKey: publicKeyBits, params: algorithm?.child(0x30), message: signedBytes, signature: signature)
                    ? .valid : .invalid("RSA-PSS signature does not verify")
            }
            let attrsDict: [CFString: Any] = [kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeyClass: kSecAttrKeyClassPublic]
            guard let key = SecKeyCreateWithData(Data(publicKeyBits) as CFData, attrsDict as CFDictionary, nil) else {
                return .notChecked("cannot import RSA key")
            }
            var hash = fallbackHash ?? .sha256
            switch sigOID {
            case "1.2.840.113549.1.1.5": hash = .sha1
            case "1.2.840.113549.1.1.14": hash = .sha224
            case "1.2.840.113549.1.1.11": hash = .sha256
            case "1.2.840.113549.1.1.12": hash = .sha384
            case "1.2.840.113549.1.1.13": hash = .sha512
            default: break
            }
            let secAlg: SecKeyAlgorithm
            switch hash {
            case .sha1: secAlg = .rsaSignatureMessagePKCS1v15SHA1
            case .sha224: secAlg = .rsaSignatureMessagePKCS1v15SHA224
            case .sha256: secAlg = .rsaSignatureMessagePKCS1v15SHA256
            case .sha384: secAlg = .rsaSignatureMessagePKCS1v15SHA384
            case .sha512: secAlg = .rsaSignatureMessagePKCS1v15SHA512
            }
            let ok = SecKeyVerifySignature(key, secAlg, Data(signedBytes) as CFData, Data(signature) as CFData, nil)
            return ok ? .valid : .invalid("RSA signature does not verify")
        }
        return .notChecked("signature algorithm \(sigOID)")
    }

    public var isSelfIssued: Bool { issuerDER == subjectDER }

    /// Verifies that this certificate was signed by `issuer`'s key.
    public func isSigned(by issuer: Certificate) -> PassiveAuthResult.Status {
        issuer.verify(signature: signatureValue, algorithm: signatureAlgorithm, data: tbsDER, fallbackHash: nil)
    }

    static func name(_ t: TLV) -> [(String, String)] {
        let short: [String: String] = [
            "2.5.4.3": "CN", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST", "2.5.4.10": "O", "2.5.4.11": "OU",
            "2.5.4.5": "serialNumber", "1.2.840.113549.1.9.1": "email",
        ]
        return t.children.flatMap { rdn in
            rdn.children.compactMap { atv -> (String, String)? in
                let parts = atv.children
                guard parts.count == 2, parts[0].tag == 0x06 else { return nil }
                let oid = ASN1.decodeOID(parts[0].value)
                return (short[oid] ?? oid, ASN1.string(parts[1]))
            }
        }
    }

    public var subjectDescription: String { subject.map { "\($0.0)=\($0.1)" }.joined(separator: ", ") }
    public var issuerDescription: String { issuer.map { "\($0.0)=\($0.1)" }.joined(separator: ", ") }

    var publicKeyAlgorithmOID: String {
        publicKeyAlgorithm.child(0x06).map { ASN1.decodeOID($0.value) } ?? ""
    }

    /// The EC group of an EC public key: a named curve or explicit domain parameters.
    func ecGroup() -> ECGroup? {
        let params = publicKeyAlgorithm.children.dropFirst().first
        if let p = params, p.tag == 0x06 { return ECCurve.forOID(ASN1.decodeOID(p.value))?.group }
        guard let p = params, p.tag == 0x30 else { return nil }
        let c = p.children
        // ECParameters ::= SEQUENCE { version, fieldID, curve, base, order, cofactor OPTIONAL }
        guard c.count >= 5, let prime = c[1].children.last?.value,
              let a = c[2].children.first?.value, c[2].children.count >= 2 else { return nil }
        let b = c[2].children[1].value
        let base = c[3].value
        let n = ASN1.unsignedInteger(c[4].value)
        let pr = ASN1.unsignedInteger(prime)
        let len = pr.count
        guard base.first == 0x04, base.count == 1 + 2 * len else { return nil }
        let curve = ECCurve(name: "explicit", paceParameterID: nil, p: pr, a: leftPad(a, to: len), b: leftPad(b, to: len),
                            gx: Array(base[1...len]), gy: Array(base[(1 + len)...]), n: n,
                            h: c.count > 5 ? (ASN1.intValue(c[5]) ?? 1) : 1)
        return curve.group
    }

    var curveDescription: String? {
        let params = publicKeyAlgorithm.children.dropFirst().first
        if let p = params, p.tag == 0x06 { return ECCurve.forOID(ASN1.decodeOID(p.value))?.name }
        guard let g = ecGroup() else { return nil }
        return ECCurve.all.first { $0.p == g.curve.p && $0.n == g.curve.n }?.name ?? "explicit parameters"
    }

    public var keyDescription: String {
        switch publicKeyAlgorithmOID {
        case "1.2.840.10045.2.1": return "ECDSA \(curveDescription ?? "")"
        case "1.2.840.113549.1.1.1", "1.2.840.113549.1.1.10":
            if let seq = try? TLV.parse(publicKeyBits).0, let mod = seq.children.first {
                return "RSA \(ASN1.unsignedInteger(mod.value).count * 8) bit"
            }
            return "RSA"
        default: return publicKeyAlgorithmOID
        }
    }
}

public struct PassiveAuthResult {
    public enum Status: Equatable { case valid, invalid(String), notChecked(String) }

    public var hashAlgorithm: String
    /// Per data group: true if the hash in the SOD matches the data read from the chip.
    public var dataGroupHashes: [DataGroupID: Bool]
    public var dataGroupsInSOD: [DataGroupID]
    public var signature: Status
    public var signer: Certificate?
    /// Whether the Document Signer certificate chains to a trusted CSCA certificate.
    public var csca: Status = .notChecked("no CSCA certificates loaded")
    public var cscaCertificate: Certificate?

    public init(hashAlgorithm: String, dataGroupHashes: [DataGroupID: Bool], dataGroupsInSOD: [DataGroupID],
                signature: Status, signer: Certificate?) {
        self.hashAlgorithm = hashAlgorithm
        self.dataGroupHashes = dataGroupHashes
        self.dataGroupsInSOD = dataGroupsInSOD
        self.signature = signature
        self.signer = signer
    }

    public var hashesValid: Bool { !dataGroupHashes.isEmpty && dataGroupHashes.values.allSatisfy { $0 } }
}

/// EF.SOD: a CMS SignedData whose content is the LDSSecurityObject with hashes of all data groups.
public struct SOD {
    public let hashAlgorithm: HashAlgorithm?
    public let hashAlgorithmOID: String
    public let hashes: [DataGroupID: Bytes]
    public let certificate: Certificate?
    let eContent: Bytes
    let signedAttributes: TLV?
    let digestAlgorithmOID: String
    let signatureAlgorithm: TLV?
    let signature: Bytes

    public init(_ bytes: Bytes) throws {
        let (outer, _) = try TLV.parse(bytes)
        guard outer.tag == 0x77, let contentInfo = outer.child(0x30),
              let signedData = contentInfo.child(0xA0)?.child(0x30) else { throw MRTDError.malformed("EF.SOD structure") }
        let sd = signedData.children
        guard let encap = sd.first(where: { $0.tag == 0x30 && $0.child(0x06) != nil }),
              let content = encap.child(0xA0)?.child(0x04)?.value else { throw MRTDError.malformed("SOD content") }
        eContent = content

        let (lds, _) = try TLV.parse(content)
        let ldsItems = lds.children
        guard ldsItems.count >= 3 else { throw MRTDError.malformed("LDSSecurityObject") }
        hashAlgorithmOID = ldsItems[1].child(0x06).map { ASN1.decodeOID($0.value) } ?? ""
        hashAlgorithm = HashAlgorithm(oid: hashAlgorithmOID)
        var h: [DataGroupID: Bytes] = [:]
        for entry in ldsItems[2].children {
            let e = entry.children
            if e.count == 2, let num = ASN1.intValue(e[0]), let dg = DataGroupID(rawValue: num), num <= 16 {
                h[dg] = e[1].value
            }
        }
        hashes = h

        certificate = sd.first(where: { $0.tag == 0xA0 })?.children.first.flatMap { try? Certificate(der: $0.encoded) }

        let signerInfo = sd.last(where: { $0.tag == 0x31 })?.children.first
        let si = signerInfo?.children ?? []
        signedAttributes = si.first { $0.tag == 0xA0 }
        let algs = si.filter { $0.tag == 0x30 }
        // SignerInfo: version, sid (SEQUENCE or [0]), digestAlgorithm, [0] signedAttrs, signatureAlgorithm, signature
        let afterSid = si.first?.tag == 0x02 ? Array(si.dropFirst(2)) : si
        let digestAlg = afterSid.first { $0.tag == 0x30 } ?? algs.first
        digestAlgorithmOID = digestAlg?.child(0x06).map { ASN1.decodeOID($0.value) } ?? ""
        signatureAlgorithm = afterSid.last { $0.tag == 0x30 }
        signature = si.last { $0.tag == 0x04 }?.value ?? []
    }

    public func verify(files: [DataGroupID: Bytes], csca: CSCAStore? = nil) -> PassiveAuthResult {
        var dgResults: [DataGroupID: Bool] = [:]
        if let alg = hashAlgorithm {
            for (dg, data) in files where dg != .com && dg != .sod {
                guard let expected = hashes[dg] else { continue }
                dgResults[dg] = alg.hash(data) == expected
            }
        }
        var result = PassiveAuthResult(hashAlgorithm: hashAlgorithm?.rawValue ?? hashAlgorithmOID, dataGroupHashes: dgResults,
                                       dataGroupsInSOD: hashes.keys.sorted(), signature: verifySignature(), signer: certificate)
        if let dsc = certificate, let csca {
            (result.csca, result.cscaCertificate) = csca.verify(dsc: dsc)
        }
        return result
    }

    func verifySignature() -> PassiveAuthResult.Status {
        guard let cert = certificate else { return .notChecked("no document signer certificate in SOD") }
        guard let digestAlg = HashAlgorithm(oid: digestAlgorithmOID) else { return .notChecked("digest \(digestAlgorithmOID)") }
        guard let attrs = signedAttributes else { return .notChecked("SOD has no signed attributes") }

        // The messageDigest attribute must match the hash of the LDSSecurityObject.
        let messageDigest = attrs.children.first { a in a.child(0x06).map { ASN1.decodeOID($0.value) } == "1.2.840.113549.1.9.4" }
        guard let md = messageDigest?.child(0x31)?.child(0x04)?.value else { return .invalid("messageDigest attribute missing") }
        guard md == digestAlg.hash(eContent) else { return .invalid("messageDigest does not match the security object") }

        // Signature covers the DER encoding of the attributes as a SET (tag 0x31).
        let signedBytes = [0x31] + attrs.encoded.dropFirst()
        return cert.verify(signature: signature, algorithm: signatureAlgorithm, data: Bytes(signedBytes), fallbackHash: digestAlg)
    }
}
