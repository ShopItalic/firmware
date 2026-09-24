// Sign firmware release statements with a per-product P-256 key held in this
// Mac's Keychain. Only public keys and signatures leave Security.framework.
//
//   swift tools/sign_release.swift public <product> <out.x963>
//   swift tools/sign_release.swift sign <product> <statement.json> <out.der>
//
// Glyph reuses the P10 release key, whose public half is compiled into the
// firmware as its trust anchor, so a missing Glyph key is an error rather
// than a reason to create one. Other products create their key on first use.
import Foundation
import Security

let keys: [String: (tag: String, createIfMissing: Bool)] = [
    "glyph": ("com.italic.glyph.firmware.p10.release-signing.v1", false),
    "sudo": ("com.italic.sudo.firmware.release-signing.v1", true),
]
func fail(_ text: String) -> Never { fputs(text + "\n", stderr); exit(1) }

let args = CommandLine.arguments
guard args.count >= 4, let spec = keys[args[2]] else {
    fail("Usage: sign_release.swift public <product> <out> | sign <product> <statement> <out>")
}
let product = args[2]
let tag = Data(spec.tag.utf8)

var item: CFTypeRef?
let query: [String: Any] = [kSecClass as String: kSecClassKey, kSecAttrApplicationTag as String: tag,
    kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
    kSecAttrKeyClass as String: kSecAttrKeyClassPrivate, kSecReturnRef as String: true]
let status = SecItemCopyMatching(query as CFDictionary, &item)
var key: SecKey
if status == errSecSuccess {
    key = item as! SecKey
} else if status == errSecItemNotFound && spec.createIfMissing && args[1] == "public" {
    var error: Unmanaged<CFError>?
    let attributes: [String: Any] = [kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits as String: 256, kSecPrivateKeyAttrs as String: [
            kSecAttrIsPermanent as String: true, kSecAttrApplicationTag as String: tag,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly]]
    guard let created = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else { fail("Keychain key creation failed") }
    key = created
} else {
    fail("Keychain release key for \(product) unavailable")
}

let output: Data
switch (args[1], args.count) {
case ("public", 4):
    var error: Unmanaged<CFError>?
    guard let publicKey = SecKeyCopyPublicKey(key),
          let bytes = SecKeyCopyExternalRepresentation(publicKey, &error) else { fail("Public key unavailable") }
    output = bytes as Data
case ("sign", 5):
    let statement = try Data(contentsOf: URL(fileURLWithPath: args[3]))
    // Domain separation: only sign release statements for this key's product.
    guard statement.count <= 4096,
          let object = try? JSONSerialization.jsonObject(with: statement) as? [String: Any],
          object["schema"] as? String == "italic-firmware-release/1",
          object["product"] as? String == product else { fail("Refusing to sign: not a \(product) release statement") }
    var error: Unmanaged<CFError>?
    guard let signature = SecKeyCreateSignature(key, .ecdsaSignatureMessageX962SHA256, statement as CFData, &error) else {
        fail("Keychain signing failed")
    }
    output = signature as Data
default:
    fail("Invalid arguments")
}
let path = args[args.count - 1]
try output.write(to: URL(fileURLWithPath: path), options: .withoutOverwriting)
print("Wrote \(output.count) bytes to \(path)")
