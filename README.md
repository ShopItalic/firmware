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

### Version 2 statements: stable releases and automatic installs (Sudo)

Schema `italic-firmware-release/2` adds what the Italic app needs to install a
Ring release by itself (ShopItalic/app `docs/design/ring-firmware-auto-update.md`,
section 9). Only Sudo uses it; Glyph firmware reads version 1. The added fields
are signed:

| Field | Meaning |
|---|---|
| `autoInstall` | the release may install itself; only an installable, application-only `stable` release |
| `minimumAppBuild` | the oldest app build that may install it, in place of the per-revision review list |
| `erasesStorage` | its first boot formats the Ring's recording storage |
| `applicationOnly` | the package replaces the application, never the bootloader or SoftDevice |
| `buildIdentity` | generation, revision, codec, settings schema and build ID the Ring reports after the update |
| `minimumSourceRevision` | optional: the oldest revision of its generation it may replace |
| `customerVersion` | optional, never on `test`: the version people see, `major.subrelease.increment` with the revision as its increment (`1.0.124`, which the app shows as `Sudo 1.0.124`). `promote` takes only that form; the app still reads the two-part `1.<revision>` of earlier fixtures as `1.0.<revision>` |
| `changeNote` | optional: one line (60 characters at most) of what people will feel or see |

Two unsigned fields are honoured because they can only narrow a signed
`autoInstall`:

- an entry's `rollout`, `{"percent": 10, "since": "2026-11-02"}`: a Ring whose
  bucket (0–99, from its Bluetooth address and the release) is below `percent`
  may install it by itself. No `rollout` means 0%.
- the catalog's `automaticUpdatesPaused`: `"all"` stops every automatic
  install, `"background"` only those the app would start in a background window.

### The signed policy (Sudo)

Those controls are unsigned. So anyone who can push to `main`, or serve an
older copy of the catalog, could un-withdraw a release, widen a rollout, or
bring back an older state. The policy closes that (ShopItalic/app
`docs/design/ring-firmware-stable-release.md`, 1.1).

`products/sudo/policy-v1.json` is an envelope signed with `sudo-release-1`,
like an entry's. Apps fetch it beside the catalog, from the same two hosts. A
404 means none is published, and an unreadable policy leaves an app with the
one it has:

```json
{"schemaVersion": 1, "product": "sudo", "hardware": "603V1.23.2",
 "statement": "<base64 of the exact signed bytes>",
 "signature": {"alg": "ES256", "keyId": "sudo-release-1", "der": "<base64>"}}
```

The statement, `italic-firmware-policy/1`, is canonical JSON of at most 4,096
bytes. Its fields are exact:

| Field | Meaning |
|---|---|
| `sequence` | 1 to 2,147,483,647; each policy is above the one it replaces |
| `issuedAt` | UTC seconds |
| `minimumRevision` | generation → package revision, such as `{"21": 124}`. Nothing ranked below the highest floor installs, in the app's order (generation, source revision, revision), so earlier generations and Z62 are below it too. Team builds may go below it |
| `withdrawn` | `{"id", "sha256"}` pairs, sorted by `id`: withdrawn for good. Apps match the package SHA-256, whatever entry offers it |
| `rollout` | release ID → the signed ceiling (0–100) of its automatic rollout |

- **New fields:** apps apply the fields they know and ignore others, which
  is safe because a field only narrows what installs. A field that changes
  how a known one reads needs a new schema, published beside this file for
  as long as apps read only version 1. There is no expiry: a floor that
  lapsed would let older releases back in.
- **What apps keep:** the highest sequence they have seen, every withdrawal
  (signed or not) and the highest floor, plus a baseline compiled into each
  build. So no push, and no older catalog, undoes a policy.
- **What CI checks** (`tools/catalog.py --previous <base>`):
  - the signature and the exact fields;
  - each withdrawal names a catalog entry with that package, whose own
    `withdrawn` is `true`;
  - each floor names an installable release;
  - each ceiling names a signed `autoInstall` release, and no entry's
    unsigned `rollout` is above its ceiling (missing is 0%);
  - against the base commit: a higher sequence, no withdrawal dropped, no
    lower floor, and no policy removed.
- **Effective rollout**, once an app has a policy:
  - It is the lower of the signed ceiling and the entry's `rollout`; a
    release without a ceiling gets 0%.
  - An entry without a `rollout` takes its ceiling.
  - So the unsigned `rollout` only lowers, and the pause and `withdraw` work
    at once without a signature.
  - Before an app has any policy, the entry's `rollout` alone decides, as in
    builds that predate the policy. So publish the first policy before the
    first release that installs itself, and compile it into the App Store
    build.
- **Catalog size:** CI also refuses a catalog past what apps read (512 KiB;
  200 Sudo or 500 Glyph entries), and warns from 75%.

The Italic app fetches Glyph firmware from this catalog and delivers it over
Bluetooth, or over a local Wi-Fi fast transfer the app opens. Glyph never
downloads from here itself. Glyph checks this signature and the package SHA-256
before installing, because neither link authenticates the package.

## Layout

```
keys/<product>-release-<n>.x963     public keys (65-byte X9.63)
products/<product>/catalog-v1.json  signed catalog, newest first
tools/release.py                    stage | publish | promote | rollout | pause-automatic |
                                    resume-automatic | withdraw | policy | record-images
products/sudo/policy-v1.json        the signed policy (floor, withdrawals, rollout ceilings)
products/sudo/package-images.json   application image sizes for the dual-bank check
tools/catalog.py                    schema + verification (also run by CI)
tools/p256.py                       dependency-free P-256 verification
tools/sign_release.swift            Keychain signer
tools/migrate.py                    one-time import from ShopItalic/sudo and Glyph
```

## Channels and installability

`channel` is `test`, `beta` or `stable`. `test` and `beta` are published as
GitHub prereleases; a promotion leaves its release as it was. `installable: false` means the file can be downloaded but
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

Sudo P21 releases from revision 107 onward use the customer title
`Sudo 1.0.<revision>`. For example, publishing the signed identity
`6.0.3.3P21-r123` produces **Sudo 1.0.123**. The publisher derives this title
from the verified statement's product, wire version, revision and matching
release ID. Earlier Sudo families and Glyph keep their existing titles.

For a later customer release or major version, provide its display version:

```sh
python3 tools/release.py publish .staging/sudo-6.0.3.3P21-r123 --firmware-version 1.1.123 --push
```

`--firmware-version` applies to the same Sudo P21 identities. Its increment
must match the signed package revision; legacy input such as `1.123` is
displayed as `1.0.123`. This option changes the GitHub title only. It does not
alter the signed statement, channel, installability, release tag or package,
and unsigned entry metadata does not select the title. Existing published
releases are not renamed.

A tested release reaches customers by being signed again for `stable`: the
same ID, tag and package, a version 2 statement. `promote` stages it without
network access; `publish` replaces the entry once the public package still
matches. A stable release's customers read `--notes`, and a test build's tester
`notice` is dropped:

```sh
python3 tools/release.py promote --product sudo --id 6.0.3.3P21-r120 --channel stable \
  --asset path/to/BCL603S2P_6.0.3.3P21.zip --minimum-app-build BUILD --erases-storage yes \
  --auto --customer-version 1.0.120 --source-version 6.0.3.3P21 \
  --qualification ../sudo/docs/reference/p21-r120-qualification.json \
  --notes "What people get" --out .staging/sudo-r120-stable
python3 tools/release.py publish .staging/sudo-r120-stable --push
# Automatic installs, staged: none until a rollout (0%), then 1%, 10%, 50%, 100%.
# Unsigned; commit and push each change.
python3 tools/release.py rollout --product sudo --id 6.0.3.3P21-r120 --percent 1
python3 tools/release.py pause-automatic --product sudo [--background]
python3 tools/release.py resume-automatic --product sudo
```

**A policy change** is signed with the Keychain key and committed together
with the unsigned fields that builds before the policy read: a withdrawal's
`withdrawn: true`, and a ceiling's `rollout`.
`--dry-run` signs and changes nothing; it prints what the policy would do
(`--out` also writes the unsigned statement):

```sh
python3 tools/release.py policy --product sudo --dry-run --floor 21:124 --withdraw 6.0.3.3P21-r107
python3 tools/release.py policy --product sudo --floor 21:124 --withdraw 6.0.3.3P21-r107 --push
# Each rollout stage, signed; `rollout` alone can then only lower it.
python3 tools/release.py policy --product sudo --rollout 6.0.3.3P21-r126:1 --push
```

A stable release's **settings evidence** is its qualification record in
ShopItalic/sudo (`docs/reference/p21-r<revision>-qualification.json`; Jeremy's
option (a), October 22, 2026). `promote` refuses it unless the record is for
this release, build and image and shows:

- the verifier's settings contract: `recipe.settingsContract` starting
  "unchanged: no protected source is edited and no FDS record is added", and
  `checks.verifier` passing with nothing pending. Or a reviewed migration
  (Jeremy, October 22, 2026, for Ring 119's touch area): a contract starting
  "a reviewed migration", with `recipe.settingsMigration` naming the release
  sudo's settings contract reviewed (`reviewedRevision`, the record's own
  release), the protected sources it edits, `fdsRecordsAdded` 0 and the
  settings the app's readback compares (`readback`):

```json
"settingsMigration": {"reviewedRevision": "P21 revision 119",
  "protectedSources": ["firmware/bc_ros/bc_application/app_factory_controls.c"],
  "fdsRecordsAdded": 0, "readback": ["touchArea"]}
```

- the dual-bank record, `image.dualBankMarginBytes`, beside this tool's own
  check;
- the release on Rings A and B with their settings and bonds intact:

```json
"stableEvidence": {"rings": [
  {"ring": "Ring A (C34A)", "buildID": "<the release's build ID>", "settings": "same", "bonds": "kept"},
  {"ring": "Ring B (5B31)", "buildID": "<the release's build ID>", "settings": "same", "bonds": "kept"}
]}
```

"settings": "same" is what the app's readback logs after the update ("Settings
after updating to P21-r118: all the same as before: …"); "bonds": "kept" means
the Ring reconnected to its iPhones without pairing again. The catalog's
`settingsCompatibility` names the record's SHA-256, never the record itself. A
hand-written `--settings-evidence` is for beta only.

Sudo packages pass the **dual-bank check** before they are staged installable,
and before any stable release: the Ring's bootloader stages an update right after the
running image and takes flash up to itself as free, but bonds and settings
start at `0xE0000`. Every image a Ring may run (each package recorded in
`products/sudo/package-images.json`, withdrawn and retired ones too) must leave
room for the new one, and the new one for every installable image. Every
catalog package needs a record; `publish` adds the new one, and
`record-images --download` records any the catalog lists without one.

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
