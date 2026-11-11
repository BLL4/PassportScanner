import CryptoKit
import XCTest
@testable import MRTDKit

/// Vectors from ICAO Doc 9303 part 11 appendix D (BAC worked example), RFC 4493 and
/// ECDH/ECDSA results produced with Python `cryptography` (OpenSSL).
final class CryptoTests: XCTestCase {
    func h(_ s: String) -> Bytes { Bytes(hex: s)! }

    func testBACKeyDerivation() {
        let key = MRZKey(documentNumber: "L898902C", dateOfBirth: "690806", dateOfExpiry: "940623")
        XCTAssertEqual(key.mrzInformation, "L898902C<369080619406236")
        let keys = BAC.keys(for: key)
        XCTAssertEqual(keys.kEnc.hex, "AB94FDECF2674FDFB9B391F85D7F76F2")
        XCTAssertEqual(keys.kMac.hex, "7962D9ECE03D1ACD4C76089DCE131543")
    }

    func testBACMutualAuthentication() throws {
        let keys = BAC.keys(for: MRZKey(documentNumber: "L898902C", dateOfBirth: "690806", dateOfExpiry: "940623"))
        let rndIC = h("4608F91988702212"), rndIFD = h("781723860C06C226"), kIFD = h("0B795240CB7049B01C19B33E32804F0B")
        let cmd = BAC.authenticationData(keys: keys, rndIC: rndIC, rndIFD: rndIFD, kIFD: kIFD)
        XCTAssertEqual(cmd.hex, "72C29C2371CC9BDB65B779B8E8D37B29ECC154AA56A8799FAE2F498F76ED92F25F1448EEA8AD90A7")

        let resp = h("46B9342A41396CD7386BF5803104D7CEDC122B9132139BAF2EEDC94EE178534F2F2D235D074D7449")
        let sm = try BAC.sessionKeys(keys: keys, response: resp, rndIC: rndIC, rndIFD: rndIFD, kIFD: kIFD)
        XCTAssertEqual(sm.kEnc.hex, "979EC13B1CBFE9DCD01AB0FED307EAE5")
        XCTAssertEqual(sm.kMac.hex, "F1CB1F1FB5ADF208806B89DC579DC1F8")
        XCTAssertEqual(sm.ssc.hex, "887022120C06C226")
    }

    func testSecureMessagingExample() throws {
        let sm = SecureMessaging(algorithm: .tdes, kEnc: h("979EC13B1CBFE9DCD01AB0FED307EAE5"),
                                 kMac: h("F1CB1F1FB5ADF208806B89DC579DC1F8"), ssc: h("887022120C06C226"))
        let select = sm.protect(CommandAPDU(ins: 0xA4, p1: 0x02, p2: 0x0C, data: [0x01, 0x1E]))
        XCTAssertEqual(select.encoded.hex, "0CA4020C158709016375432908C044F68E08BF8B92D635FF24F800")
        let r = try sm.unprotect(ResponseAPDU(h("990290008E08FA855A5D4C50A8ED9000")))
        XCTAssertEqual(r.sw, 0x9000)

        let read = sm.protect(CommandAPDU(ins: 0xB0, p1: 0, p2: 0, ne: 4))
        XCTAssertEqual(read.encoded.hex, "0CB000000D9701048E08ED6705417E96BA5500")
        let data = try sm.unprotect(ResponseAPDU(h("8709019FF0EC34F9922651990290008E08AD55CC17140B2DED9000")))
        XCTAssertEqual(data.data.hex, "60145F01")
    }

    func testAESCMAC() {
        let k = h("2B7E151628AED2A6ABF7158809CF4F3C")
        XCTAssertEqual(aesCMAC(key: k, []).hex, "BB1D6929E95937287FA37D129B756746")
        XCTAssertEqual(aesCMAC(key: k, h("6BC1BEE22E409F96E93D7E117393172A")).hex, "070A16B46B4D4144F79BDD9DD04A287C")
        XCTAssertEqual(aesCMAC(key: k, h("6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411")).hex,
                       "DFA66747DE9AE63030CA32611497C827")
    }

    func testPACEPasswordAndNonce() {
        // ICAO 9303 part 11 appendix G.1 (ECDH generic mapping, AES-128).
        let key = MRZKey(documentNumber: "T22000129", dateOfBirth: "640812", dateOfExpiry: "101031")
        let (kPi, ref) = PACE.passwordKey(.mrz(key), algorithm: .aes128)
        XCTAssertEqual(ref, 1)
        XCTAssertEqual(kPi.hex, "89DED1B26624EC1E634C1989302849DD")
        let s = PACE.decryptNonce(h("95A3A016522EE98D01E76CB6B98B42C3"), key: kPi, algorithm: .aes128)
        XCTAssertEqual(s.hex, "3F00C4D39D153F2B2A214A078D899B22")
    }

    func testCurvesAreConsistent() {
        for curve in ECCurve.all {
            let g = curve.group
            XCTAssertTrue(g.isOnCurve(g.generator), curve.name)
            XCTAssertTrue(g.multiply(curve.n, g.generator).isInfinity, "\(curve.name): n·G must be infinity")
            let a = g.randomScalar(), b = g.randomScalar()
            let ab = g.multiply(a, g.multiply(b, g.generator))
            let ba = g.multiply(b, g.multiply(a, g.generator))
            XCTAssertEqual(ab, ba, curve.name)
            XCTAssertTrue(g.isOnCurve(ab), curve.name)
        }
    }

    func testECDHAgainstOpenSSL() {
        let vectors: [(ECCurve, String, String, String)] = [
            (.brainpoolP256r1, "8FAA816B6E1138C1D3C91247BCB8E45AE2AC7A7AB284F6DE0BDC0FA76EAEDB49", "04857A8D8F4AC754014468CCBD39E46828C063614A4E7D59A9D4CAF88D4CA7EF4F2E96A8318A984C3B53D95AEFA85EC56B3A586FA739CEED50377E8D4E8F4A31F5", "5A84A69970C8EED5372894358AB770A59D1802C86198D1818FEAE23B26BC66F2"),
            (.p384, "32C21BCEDA7CEB65DE270E80F48A6328E70D3B74673C160EDB11B33405FA576EBE14587E5BA86FED1FE23B3B0441FB3C", "04BDB61734B1AA82494B92BF65A7B8D5F8E3DD329366149EF5870BCEB7632A26DB00BA1B8E79D266F2523AF637022BB8360984E18904C29FEFC8D15D365E75AD0E62801E2850EDD1BBF3E93B745429F8E63715C9EC79901F24886AF9CC5AB30C79", "8B14237C17E1F93934AF5820721FB6E0D24FC0F6E46830528FE40C7104BDC4C21A3F242B96BB4C72F30B4D2D6FDE208C"),
            (.brainpoolP512r1, "8777D550F090A7DD02A12D602B37972C3B64AFE7B96F87C567D69DB031678FEA595202792359FFA0B23BF747B5437A14017DE79E08FF0A06113A8AB2B7829E9D", "046F4AE26AE919B440466D24F3B57A7BC52FB6CE64E665C5FEDEDE5F45EB56BE9FCE7B745A3242C5B72D58483B720ED252977789C0E7859F7A6D2A94CDD3163EE818523D04076048112905BCE4D6E1A8284CCAC519C300AAD86ACB7C5342561761EE94B1DAE11E9354856A544AB00251767AD493FB9B20C6E16D4D6E635B110F03", "41AD003AE1C0E97021D8148E4C654EC3BFB19137A97132523B0925C74C89ED608365B4B778033D86CD41FA1FBFCC68742934D6DDFD38E1BD53A018B0F5A6FA72"),
            (.p521, "01BE016716735748A3116E05383CC45A09B2CBF9872AD3E1287358DE9E6B7FBC873BB70930BEF53953CEDC9275B1E25A15DE86500F860C624A48A90F27C478D40324", "0400203A03271BBDD34F03C767854C995BF87ABD6548252C44AE99183FC0CD54C96110778C7A5DA1ED3758855B2E7876AAA9068C776264255AB13368ECD4E432524A850074366C3484A60FF9540F176C6FE27026E372CE3109CBF33374CCFD1D4310B0E684F82AE7A112D7E7EE61DD0D535F4271378C1F6F234B7DA115BE50DA48CF772371", "0092D0F740A47E132B8F19361A2C8285A42A668C264DDE5924C2F3AF062F5BFF0B976C5072DA673ABC944886DAD90CC2CCAADAE8A3055233C62A9855E5EC5DF43DBC"),
        ]
        for (curve, d, pub, shared) in vectors {
            let g = curve.group
            guard let q = g.decode(h(pub)) else { return XCTFail("\(curve.name): public key not on curve") }
            XCTAssertEqual(g.multiply(h(d), q).x.hex, shared, curve.name)
        }
    }

    func testECDSAVerify() throws {
        let msg = Bytes("ICAO 9303 test message".utf8)
        let vectors: [(ECCurve, HashAlgorithm, String, String, String)] = [
            (.brainpoolP256r1, .sha256, "044ECAE6473FEDF5C2E7848794E416A7E50ADAA92AA032B95D7649099323E71327677FBB638191E13D3C84FA6690C6E6D0A13EDA67C2C783771CD42B166925C6EC", "5F3E1CE56957CDD907F69B9837AE0C416DED2903DB4D04114D93E2B92D311E", "2AAB6AA2CE74C2C7567FC010C83135B98D268C7FF686B1ECE344C59BD69BC511"),
            (.brainpoolP384r1, .sha384, "04237EE0E20B93F9227FAA7D6C3B39AF219C7487F4FF707765CBD6EC985132959494DB5AE6AB85A6C1DDD2BAD0DA5F6A6813A439B97EC3C4B7560BE89B3FB86894CFEF41AA7D2818E032EED2B594CDA5E638DD65C21BE82CEE045D0C493424E3B0", "3D825EC739B6FD65C3C0DF6CA1DA7BBDB33EBB556872993485EA38F5EDDFAD3809BC2AE2B5D87C6B15DADB0876CB74DC", "73D66852B3C9EA6B2646656E03B09B1984DB30FD5615937D14F5894DFA504EF94B851347CF7538152409124B3F4E7A35"),
            (.p521, .sha512, "0400108E72918DB0C9B7D135FDC91A414E9A551F98C1CC0277DD8D9CA20B182E372A25A648556756DDB4760EF49B1E35EA25AB6B8CA02AB5D7E4A3EA7FDC2AFE5A26B60197C585F15F50C78DCA645FF61A2523726C9305DAA8D2BAE1A606C54416632C50B4E06673FB9EB7B1E87121B057D668AD4EA54E403EB2879AEFB1B97FF3240A417E", "18F8B562445C2637D8C00E299E58BB8EF6D7C4ACD8DFB4B425AEFFD055F519A3B061E86FC1B9469466044E028CFC3CFA88429F4EC2F550EA92F8FFDC3FE03810035", "95A6513048E384A4FF163D16CBAECFCEA6037692324E3A5E468261EF7352D602C8520B452620C3BDA00D18B1E5A50E2607133C469A9C87E181D80D4690F748BA24"),
        ]
        for (curve, hash, pub, r, s) in vectors {
            let g = curve.group
            let q = try XCTUnwrap(g.decode(h(pub)))
            let rb = Bytes(hex: r.count % 2 == 1 ? "0" + r : r)!, sb = Bytes(hex: s.count % 2 == 1 ? "0" + s : s)!
            XCTAssertTrue(g.verify(digest: hash.hash(msg), r: rb, s: sb, publicKey: q), curve.name)
            XCTAssertFalse(g.verify(digest: hash.hash(msg + [0]), r: rb, s: sb, publicKey: q), curve.name)
        }

        // P-256 signature from CryptoKit.
        let key = P256.Signing.PrivateKey()
        let sig = Bytes(try key.signature(for: Data(msg)).rawRepresentation)
        let g = ECCurve.p256.group
        let q = try XCTUnwrap(g.decode(Bytes(key.publicKey.x963Representation)))
        XCTAssertTrue(g.verify(digest: HashAlgorithm.sha256.hash(msg), r: Array(sig[0..<32]), s: Array(sig[32...]), publicKey: q))
    }

    func testTLVAndOID() throws {
        XCTAssertEqual(ASN1.decodeOID(ASN1.encodeOID("0.4.0.127.0.7.2.2.4.2.2")), "0.4.0.127.0.7.2.2.4.2.2")
        XCTAssertEqual(ASN1.encodeOID("0.4.0.127.0.7.2.2.4.2.2").hex, "04007F00070202040202")
        let enc = TLV.encode(0x5F1F, Bytes(repeating: 0x41, count: 300))
        XCTAssertEqual(Array(enc.prefix(5)).hex, "5F1F82012C")
        let (t, next) = try TLV.parse(enc)
        XCTAssertEqual(t.tag, 0x5F1F)
        XCTAssertEqual(t.value.count, 300)
        XCTAssertEqual(next, enc.count)
        XCTAssertEqual(TLV.headerInfo(Array(enc.prefix(4)))?.headerLength, nil) // needs 5 bytes for 82 xx xx
        XCTAssertEqual(TLV.headerInfo(Array(enc.prefix(5)))?.valueLength, 300)
    }
}
