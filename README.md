# Italic firmware distribution

Public home for Italic device firmware: one signed catalog per product and
immutable GitHub Release assets. This repository contains **no source code,
vendor packages, keys or build notes**. Those stay in each product's private
source repository, together with its qualification gates.

| Product | Device | Catalog (raw) |
|---|---|---|
| `glyph` | Glyph (PKS3-101) | `https://raw.githubusercontent.com/ShopItalic/firmware/main/products/glyph/catalog-v1.json` |
| `sudo` | Sudo / Italic Ring (603V1.23.2) | `https://raw.githubusercontent.com/ShopItalic/firmware/main/products/sudo/catalog-v1.json` |

Firmware files are served from
`https://github.com/ShopItalic/firmware/releases/download/<product>-<id>/<asset>`.
The same file is also available through the anonymous asset API
(`apiURL`, `Accept: application/octet-stream`).

## Trust model

GitHub, TLS and this repository decide only whether a file is **available**. What
makes it **trustworthy** is a signature from the product's release key:

- Every catalog entry carries a `statement`: the exact JSON bytes, base64-encoded,
  with schema `italic-firmware-release/1`. The statement covers the product,
  hardware, release ID, version, package revision, channel, whether the release
  is installable, the package name/size/SHA-256, the permitted source versions
  (if any) and the issue time. It deliberately contains no URL, so hosting can
  move without re-signing.
- `signature` is an ECDSA P-256 / SHA-256 DER signature over those bytes
  (`ES256`, key `keys/<keyId>.x963`, uncompressed X9.63).
- **Clients must** check that the signature matches the stored statement
  bytes, parse the statement, and act only on what the statement says. They
  must then check the downloaded package against the statement's size and
  SHA-256. The unsigned entry fields (notes, `details`, URLs) are for display
  only. The one exception is `withdrawn: true`, which clients honour unsigned
  because it can only remove an offer.
- Release keys live in the publisher's macOS Keychain and are only used through
  `tools/sign_release.swift`. Each product has its own key. The signer refuses
  anything that is not a release statement for that key's product. Glyph's key is
  its firmware trust anchor (P10 onward), so it is never regenerated.

Glyph firmware downloads over TLS, but it only logs certificate errors instead
of rejecting them. For Glyph, the signature is therefore the only real protection.

## Layout

```
keys/<product>-release-<n>.x963     public keys (65-byte X9.63)
products/<product>/catalog-v1.json  signed catalog, newest first
tools/release.py                    stage | publish | withdraw
tools/catalog.py                    schema + verification (also run by CI)
tools/p256.py                       dependency-free P-256 verification
tools/sign_release.swift            Keychain signer
tools/migrate.py                    one-time import from ShopItalic/sudo and Glyph
```

## Channels and installability

`channel` is `test`, `beta` or `stable`. `test` and `beta` are published as
GitHub prereleases. `installable: false` means the file can be downloaded but
must not be offered as an update. When `sourceVersions` is present, the release
may only be installed on top of one of those versions. The product's source repo
decides channel and installability from its qualification evidence. This
repository only records and signs that decision.

## Publishing

```sh
# 1. Stage and sign locally (Keychain prompt on first use).
python3 tools/release.py stage --product glyph --id P12-rc.1 --version P12-rc.1 \
  --channel test --asset path/to/glyph-pks3-101-P12-rc.1.ufw \
  --extra path/to/release-notes.md --notes "What changed" --out .staging/glyph-P12-rc.1
# 2. Upload, verify the public copies anonymously, add to the catalog, commit.
python3 tools/release.py publish .staging/glyph-P12-rc.1 --push
```

Rules:

- **Tags and assets are immutable.** Never re-upload or reuse a tag. Fix a bad
  release by publishing a new revision (`-r2`, `-rc.2`).
- Assets are published and verified before the catalog references them.
- To withdraw a release, run
  `python3 tools/release.py withdraw --product P --id ID --reason ...`, then
  commit and push. Delete the GitHub release as well if the file itself must
  disappear.
- Never upload private build manifests with host names, ELF/map files with
  vendor symbols, vendor supplier packages, chip keys or unit dumps.

## Migration record

The Sudo entries were mirrored from the curated `releases-v9.json` in
`ShopItalic/sudo`. Each file was checked against that catalog and the upstream
`SHA256SUMS`. The original fields are kept under `details`, with
`details.migratedFrom` recording the source. Already-shipped app builds keep
reading the catalogs in `ShopItalic/sudo`, which stay in place until those
builds age out. New app builds read this catalog.

The Glyph entries come from the verified staged bundles in the private Glyph
repository (factory-derived P-series only; withdrawn builds excluded). None is
offered for automatic installation. Each release includes a `release.json`
public summary that pins the private manifest's hash.
