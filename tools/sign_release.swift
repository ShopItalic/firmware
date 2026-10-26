// Sign firmware release statements with a per-product P-256 key kept in the
// Italic 1Password account's "Italic Release" vault, never on a Mac. The key
// is read with the 1Password CLI (`op`) for each signature, held only in this
// process and checked against keys/<keyId>.x963 before it signs. Only public
// keys and signatures leave it.
//
//   swift tools/sign_release.swift public <product> <out.x963>
//   swift tools/sign_release.swift sign <product> <statement.json> <out.der>
//
// Keys are never created here. Glyph's is its firmware trust anchor (P10
// onward) and the Italic app pins Sudo's, so a missing key is an error.
import CryptoKit
import Foundation

let keys: [String: (item: String, keyId: String)] = [
    "glyph": ("Glyph firmware release key glyph-release-1", "glyph-release-1"),
    "sudo": ("Sudo firmware release key sudo-release-1", "sudo-release-1"),
]
let account = "italic.1password.com"
let vault = "Italic Release"
func fail(_ text: String) -> Never { fputs(text + "\n", stderr); exit(1) }

let args = CommandLine.arguments
guard args.count >= 4, let spec = keys[args[2]] else {
    fail("Usage: sign_release.swift public <product> <out> | sign <product> <statement> <out>")
}
let product = args[2]
let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
guard let pinned = try? Data(contentsOf: root.appendingPathComponent("keys/\(spec.keyId).x963")), pinned.count == 65 else {
    fail("keys/\(spec.keyId).x963 is missing")
}

// `op` asks for Touch ID when this terminal has no 1Password session yet.
let op = Process()
op.executableURL = URL(fileURLWithPath: "/usr/bin/env")
op.arguments = ["op", "document", "get", spec.item, "--vault", vault, "--account", account]
let pipe = Pipe()
op.standardOutput = pipe
do { try op.run() } catch { fail("The 1Password CLI (op) isn't available") }
let pem = pipe.fileHandleForReading.readDataToEndOfFile()
op.waitUntilExit()
guard op.terminationStatus == 0,
      let key = try? P256.Signing.PrivateKey(pemRepresentation: String(decoding: pem, as: UTF8.self)) else {
    fail("Couldn't read \"\(spec.item)\" from 1Password's \(vault) vault (\(account))")
}
guard key.publicKey.x963Representation == pinned else { fail("1Password's \(product) key does not match keys/\(spec.keyId).x963") }

let output: Data
switch (args[1], args.count) {
case ("public", 4):
    output = key.publicKey.x963Representation
case ("sign", 5):
    let statement = try Data(contentsOf: URL(fileURLWithPath: args[3]))
    // Domain separation: only sign release statements for this key's product.
    // Version 2 (automatic installs) and the signed policy are Sudo's only:
    // Glyph firmware reads version 1.
    let schemas = product == "sudo" ? ["italic-firmware-release/1", "italic-firmware-release/2", "italic-firmware-policy/1"]
        : ["italic-firmware-release/1"]
    guard statement.count <= 4096,
          let object = try? JSONSerialization.jsonObject(with: statement) as? [String: Any],
          let schema = object["schema"] as? String, schemas.contains(schema),
          object["product"] as? String == product else { fail("Refusing to sign: not a \(product) release statement") }
    // ECDSA P-256 over SHA-256, DER encoded: the same bytes SecKeyCreateSignature
    // made with .ecdsaSignatureMessageX962SHA256.
    guard let signature = try? key.signature(for: statement) else { fail("Signing failed") }
    output = signature.derRepresentation
default:
    fail("Invalid arguments")
}
let path = args[args.count - 1]
try output.write(to: URL(fileURLWithPath: path), options: .withoutOverwriting)
print("Wrote \(output.count) bytes to \(path)")
