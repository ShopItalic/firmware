#!/usr/bin/env python3
"""Stage (sign locally) and publish firmware releases to ShopItalic/firmware.

  stage    Copy the package and extra assets into a new staging directory,
           write the canonical release statement and sign it with the product's
           Keychain key. No network access.
  publish  Create an immutable GitHub prerelease/release for a staged
           directory, verify every asset anonymously, then add the signed entry
           to products/<product>/catalog-v1.json and commit. Order matters:
           assets are public and verified before the catalog offers them.
           A promotion's directory replaces its release's entry instead.
  promote  Sign a published release again for the beta or stable channel, with
           a version 2 statement: the oldest app build that may install it,
           whether it may install itself, and the rest of section 9 of
           ShopItalic/app docs/design/ring-firmware-auto-update.md. The tag and
           assets stay as they are; the statement names no URL. No network.
  rollout  Admit devices whose bucket is below a percentage to a release's
           automatic installs. Unsigned: it can only narrow a signed autoInstall.
  pause-automatic / resume-automatic
           The catalog's pause switch for automatic installs, for every release
           ("all", or with --background only installs started in the background).
  withdraw Mark a release withdrawn. Unsigned: it only removes an offer.
  policy   Sign the product's next policy: a floor below which nothing installs,
           withdrawals and each automatic rollout's ceiling, which apps keep
           and a push can't undo. It commits the policy, the catalog's copy and
           the unsigned fields older apps read. --dry-run signs nothing.
  record-images
           Record the application image inside packages for the dual-bank check.

Sudo packages pass the dual-bank check before they are staged installable and
before they may install themselves: every image a Ring may run must leave room
for the new one beside it, and the new one for every installable image, below
the Ring's settings (products/sudo/package-images.json).

Qualification gates live in each product's source repo; this tool refuses
anything that is not signed, hashed and uniquely tagged.
"""
import argparse
import base64
import copy
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import catalog
import p256

SIGNER = catalog.ROOT / 'tools/sign_release.swift'


def sha256(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1 << 20), b''):
            h.update(block)
    return h.hexdigest()


def record(path):
    return {'name': path.name, 'bytes': path.stat().st_size, 'sha256': sha256(path)}


def utc_seconds():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def sign(product, statement_path, signature_path, signer=None):
    """Sign with the Keychain key (default) or an injected test signer."""
    if signer:
        signature_path.write_bytes(signer(statement_path.read_bytes()))
    else:
        subprocess.run(['swift', str(SIGNER), 'sign', product, str(statement_path), str(signature_path)],
                       check=True, stdout=subprocess.DEVNULL)


# The Ring (603V1.23.2) runs Nordic's SDK 17 secure bootloader. It stages an
# application update in bank 1, right after the running image rounded up to
# a 4 KiB page, and takes flash up to itself as free, but bonds and settings
# (FDS) start at 0xE0000. A copy past that overwrites them, and one that
# doesn't fit beside the running image makes the bootloader delete that image
# first, so an interrupted update leaves a Ring that can only wait in its
# bootloader. ShopItalic/sudo's tools/firmware/check_dual_bank_budget.py has
# the derivation; this is its rule, run where packages are published.
DUAL_BANK = {'sudo': {'applicationStart': 0x27000, 'settingsStart': 0xE0000}}
PAGE = 0x1000


def images_path(product):
    return catalog.ROOT / 'products' / product / 'package-images.json'


def load_images(product):
    path = images_path(product)
    return json.loads(path.read_text()) if path.exists() else {'schema': 1, 'note': '', 'packages': {}}


def write_images(product, images):
    """One line per package, ordered by version and revision, as sudo's own record."""
    rows = sorted(images['packages'].items(), key=lambda item: (
        item[1]['version'], item[1]['packageRevision'], item[1]['release'], item[0]))
    lines = ['{', '  "schema": 1,', f'  "note": {json.dumps(images.get("note", ""))},', '  "packages": {']
    for i, (digest, row) in enumerate(rows):
        lines.append(f'    {json.dumps(digest)}: {json.dumps(row)}' + (',' if i < len(rows) - 1 else ''))
    images_path(product).write_text('\n'.join(lines + ['  }', '}']) + '\n')


def package_parts(path):
    """The parts a Nordic DFU package replaces, and its application image if that is all."""
    with zipfile.ZipFile(path) as archive:
        manifest = json.loads(archive.read('manifest.json')).get('manifest', {})
        parts = set(manifest)
        image = archive.read(manifest['application']['bin_file']) if parts == {'application'} else None
        return parts, (manifest['application']['bin_file'], image) if image is not None else None


def image_record(release_tag, s, path):
    parts, application = package_parts(path)
    catalog.require(application is not None, f'{path.name}: the package replaces {sorted(parts)}, not only the application')
    name, image = application
    return {'release': release_tag, 'version': s['version'], 'packageRevision': s['packageRevision'],
            'packageBytes': s['asset']['bytes'], 'image': name, 'imageBytes': len(image),
            'imageSha256': hashlib.sha256(image).hexdigest()}


def dual_bank(product, package_sha, image_bytes, current, images):
    """The margin the worst staged copy involving this package leaves below the
    Ring's settings, or CatalogError. The images a Ring may run are every one
    recorded (withdrawn and retired ones too) and this one, since reinstalling
    is an update too; this package is staged over each of them, and every
    installable catalog package over this one. Every catalog package must have
    a record, so nothing a Ring runs goes unchecked."""
    layout = DUAL_BANK.get(product)
    if layout is None:
        return None
    limit = layout['settingsStart'] - layout['applicationStart']
    records = images['packages']
    installable = [image_bytes]
    for entry in current['releases']:
        s = json.loads(base64.b64decode(entry['statement']))
        row = records.get(s['asset']['sha256'])
        catalog.require(row is not None, f"{s['id']}: its package has no recorded image; run record-images")
        catalog.require(row['packageBytes'] == s['asset']['bytes'], f"{s['id']}: its recorded package size differs")
        if s['installable'] and not entry['withdrawn'] and s['asset']['sha256'] != package_sha:
            installable.append(row['imageBytes'])
    def staged(old, new):
        return (old + PAGE - 1) // PAGE * PAGE + new
    running = [row['imageBytes'] for row in records.values()] + [image_bytes]
    worst = max([staged(old, image_bytes) for old in running] + [staged(image_bytes, new) for new in installable])
    catalog.require(worst <= limit, f'dual-bank budget: a staged copy would end {worst - limit} bytes into the '
                                    f'Ring\'s settings (limit {limit} bytes from the application start)')
    return limit - worst


def stage(product, release_id, version, revision, channel, installable, asset, extras, out,
          source_versions=None, display=None, details=None, key_id=None, signer=None, keys=None,
          automatic=None, images=None):
    """`automatic` holds version 2's statement fields (catalog.check_automatic)."""
    catalog.require(product in catalog.PRODUCTS, 'unknown product')
    key_id = key_id or catalog.PRODUCTS[product]['keys'][0]
    keys = keys or catalog.load_keys()
    names = [asset.name] + [p.name for p in extras]
    catalog.require(len(set(names)) == len(names), 'duplicate asset names')
    catalog.require(not {'statement.json', 'signature.der', 'SHA256SUMS', 'image.json'} & set(names),
                    'asset name collides with a release-level file')
    out.mkdir(parents=True, exist_ok=False)
    files = out / 'assets'; files.mkdir()
    for path in [asset, *extras]:
        catalog.require(path.is_file() and not path.is_symlink(), f'not a regular file: {path}')
        shutil.copyfile(path, files / path.name)
        catalog.require(sha256(files / path.name) == sha256(path), f'copy changed {path.name}')
    statement = catalog.make_statement(product, release_id, version, revision, channel, installable,
                                       record(files / asset.name), utc_seconds(), source_versions, automatic)
    if product in DUAL_BANK:
        image = image_record(catalog.tag(product, release_id), statement, files / asset.name)
        if installable:
            current = catalog.read(product) if catalog.catalog_path(product).exists() else catalog.empty(product)
            margin = dual_bank(product, statement['asset']['sha256'], image['imageBytes'], current,
                               images or load_images(product))
            print(f'dual-bank budget: {margin} bytes to spare')
        (out / 'image.json').write_text(json.dumps(image, indent=2) + '\n')
    raw = catalog.encode_statement(statement)
    (out / 'statement.json').write_bytes(raw)
    sign(product, out / 'statement.json', out / 'signature.der', signer)
    der = (out / 'signature.der').read_bytes()
    catalog.require(p256.verify(keys[key_id], raw, der), 'fresh signature does not verify with the published key')
    url = catalog.DOWNLOAD + catalog.tag(product, release_id) + '/' + asset.name
    entry = catalog.signed_entry(raw, key_id, der, url, display=display, details=details,
                                 extra_assets=[p.name for p in extras])
    entry['asset']['md5'] = hashlib.md5((files / asset.name).read_bytes()).hexdigest()
    catalog.verify_entry(product, entry, keys)
    (out / 'entry.json').write_text(json.dumps({'product': product, 'entry': entry}, indent=2) + '\n')
    sums = ''.join(f'{sha256(p)}  {p.name}\n' for p in sorted(files.iterdir()))
    (out / 'SHA256SUMS').write_text(sums)
    return entry


def load_stage(directory, keys=None):
    data = json.loads((directory / 'entry.json').read_text())
    product, entry = data['product'], data['entry']
    s = catalog.verify_entry(product, entry, keys or catalog.load_keys())
    catalog.require(base64.b64decode(entry['statement']) == (directory / 'statement.json').read_bytes(),
                    'statement file differs from entry')
    files = directory / 'assets'
    expected = {s['asset']['name'], *entry['extraAssets']}
    catalog.require({p.name for p in files.iterdir()} == expected, 'staged asset set changed')
    catalog.require(record(files / s['asset']['name']) == s['asset'], 'staged package changed')
    if 'md5' in entry['asset']:
        catalog.require(hashlib.md5((files / s['asset']['name']).read_bytes()).hexdigest() == entry['asset']['md5'],
                        'staged md5 mismatch')
    sums = ''.join(f'{sha256(p)}  {p.name}\n' for p in sorted(files.iterdir()))
    catalog.require((directory / 'SHA256SUMS').read_text() == sums, 'staged SHA256SUMS mismatch')
    return product, entry, s


def gh(*args, capture=True):
    result = subprocess.run(['gh', *args], check=True, text=True, capture_output=capture)
    return result.stdout if capture else ''


def anonymous_get(url, accept=None, attempts=6):
    request = urllib.request.Request(url, headers={'User-Agent': 'italic-firmware-publisher',
                                                   **({'Accept': accept} if accept else {})})
    for attempt in range(attempts):
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                return response.read()
        except OSError:
            if attempt == attempts - 1:
                raise
            time.sleep(5 * (attempt + 1))


def commit(paths, message, push):
    for path in paths:
        subprocess.run(['git', '-C', str(catalog.ROOT), 'add', str(path.relative_to(catalog.ROOT))], check=True)
    subprocess.run(['git', '-C', str(catalog.ROOT), 'commit', '-q', '-m', message], check=True)
    if push:
        subprocess.run(['git', '-C', str(catalog.ROOT), 'push', '-q'], check=True)


def release_title(statement, firmware_version=None, option='--firmware-version'):
    """Display title from a verified statement; never changes release identity."""
    product, revision = statement['product'], statement['packageRevision']
    sudo_version = '6.0.3.3P21'
    named_sudo = (product == 'sudo' and statement['version'] == sudo_version
                  and type(revision) is int and 107 <= revision <= 999
                  and statement['id'] == f'{sudo_version}-r{revision}')
    if firmware_version is None:
        return f'Sudo 1.0.{revision}' if named_sudo else f"{product.capitalize()} {statement['id']}"
    catalog.require(named_sudo, f'{option} requires a canonical Sudo P21 release at revision 107 or later')
    catalog.require(isinstance(firmware_version, str) and
                    re.fullmatch(r'[1-9][0-9]{0,2}\.[0-9]{1,3}(?:\.[0-9]{1,3})?', firmware_version),
                    f'{option} must be major.release.increment or legacy major.increment')
    parts = [int(part) for part in firmware_version.split('.')]
    major, release_number, increment = parts if len(parts) == 3 else (parts[0], 0, parts[1])
    catalog.require(increment == revision, f'{option} increment must match the signed packageRevision')
    return f'Sudo {major}.{release_number}.{increment}'


def publish(directory, notes=None, push=False, dry_run=False, firmware_version=None):
    if json.loads((directory / 'entry.json').read_text()).get('promotes'):
        catalog.require(firmware_version is None, 'a promotion publishes no GitHub release, so it has no title to set')
        return publish_promotion(directory, push=push, dry_run=dry_run)
    product, entry, s = load_stage(directory)
    title = release_title(s, firmware_version)
    current = catalog.read(product) if catalog.catalog_path(product).exists() else catalog.empty(product)
    catalog.require(all(e['id'] != s['id'] for e in current['releases']), f"{s['id']} already in catalog")
    release_tag = entry['tag']
    existing = subprocess.run(['gh', 'release', 'view', release_tag, '--repo', catalog.OWNER_REPO],
                              capture_output=True, text=True)
    catalog.require(existing.returncode != 0, f'tag {release_tag} already exists; tags are never reused')
    files = sorted((directory / 'assets').iterdir()) + [directory / 'SHA256SUMS', directory / 'statement.json',
                                                         directory / 'signature.der']
    body = notes or entry.get('releaseNotes') or entry.get('notice') or title
    body += f"\n\nPackage `{s['asset']['name']}`: {s['asset']['bytes']} bytes, SHA-256 `{s['asset']['sha256']}`." \
            f"\nSigned statement `statement.json` / `signature.der` (key `{entry['signature']['keyId']}`)."
    command = ['release', 'create', release_tag, '--repo', catalog.OWNER_REPO, '--title', title,
               '--notes', body, *([] if s['channel'] == 'stable' else ['--prerelease']), *map(str, files)]
    if dry_run:
        print('gh', ' '.join(command[:8]), f'... {len(files)} files'); return entry
    gh(*command)
    # Verify the public copies anonymously before anything references them.
    for path in files:
        url = catalog.DOWNLOAD + release_tag + '/' + path.name
        catalog.require(hashlib.sha256(anonymous_get(url)).hexdigest() == sha256(path),
                        f'public download mismatch: {path.name}')
    assets = json.loads(gh('api', f'repos/{catalog.OWNER_REPO}/releases/tags/{release_tag}'))['assets']
    asset_id = next(a['id'] for a in assets if a['name'] == s['asset']['name'])
    api_url = f'{catalog.ASSET_API}{asset_id}'
    catalog.require(hashlib.sha256(anonymous_get(api_url, 'application/octet-stream')).hexdigest()
                    == s['asset']['sha256'], 'asset API download mismatch')
    entry['asset']['apiURL'] = api_url
    current['releases'].insert(0, entry)
    catalog.write(product, current)
    paths = [catalog.catalog_path(product)]
    if (directory / 'image.json').exists():
        # Every published package keeps its record: Rings may run it long after.
        images = load_images(product)
        images['packages'][s['asset']['sha256']] = json.loads((directory / 'image.json').read_text())
        write_images(product, images)
        paths.append(images_path(product))
    commit(paths, f'Publish {product} {s["id"]}', push)
    print(f'published {release_tag}: {entry["asset"]["url"]}')
    return entry


# Stable settings evidence, option (a) (Jeremy, October 22, 2026). A stable
# release's evidence is its ShopItalic/sudo qualification record
# (docs/reference/p21-r<revision>-qualification.json), which shows
#   - the verifier's settings contract: no protected source edited, no FDS
#     record added, and the verifier passing with nothing pending;
#   - the dual-bank budget record, beside this tool's own check;
#   - the release on Rings A and B with their settings and bonds intact:
#     `stableEvidence.rings`, one entry a Ring, each naming the release's
#     build ID, "settings": "same" as the app's readback logged it ("Settings
#     after updating to …: all the same as before"), and "bonds": "kept".
# The catalog names the record's SHA-256; the record itself stays private.
SETTINGS_CONTRACT = 'unchanged: no protected source is edited and no FDS record is added'
# Or a reviewed migration (Jeremy, October 22, 2026, for Ring 119's touch area:
# "accept a reviewed change like this, with the app's after-update check
# covering the area"): `recipe.settingsContract` starting REVIEWED_MIGRATION,
# and `recipe.settingsMigration` naming the release sudo's settings contract
# reviewed (`reviewedRevision`, the record's own), the protected sources it
# edits, `fdsRecordsAdded` 0, and the settings the app's readback compares
# (`readback`).
REVIEWED_MIGRATION = 'a reviewed migration'


def settings_contract_kept(q):
    """The record's settings contract is unchanged, or a reviewed migration that adds no FDS record."""
    recipe = q.get('recipe') or {}
    contract = recipe.get('settingsContract')
    if not isinstance(contract, str):
        return False
    if contract.startswith(SETTINGS_CONTRACT):
        return True
    migration = recipe.get('settingsMigration')
    if not contract.startswith(REVIEWED_MIGRATION) or not isinstance(migration, dict):
        return False
    named = lambda field: (isinstance(migration.get(field), list) and bool(migration[field])  # noqa: E731
                           and all(isinstance(item, str) and item for item in migration[field]))
    return (migration.get('reviewedRevision') == q.get('release') and isinstance(q.get('release'), str)
            and named('protectedSources') and type(migration.get('fdsRecordsAdded')) is int
            and migration['fdsRecordsAdded'] == 0 and named('readback'))


def stable_evidence(s, identity, asset, record_bytes, source_versions):
    """The settingsCompatibility a stable release publishes, from its qualification record."""
    try:
        q = json.loads(record_bytes)
    except ValueError:
        raise catalog.CatalogError('the qualification record is not JSON')
    catalog.require(isinstance(q, dict), 'the qualification record is not an object')
    catalog.require(q.get('wireVersion') == s['version'] and q.get('packageRevision') == s['packageRevision'],
                    f"the qualification record is for {q.get('wireVersion')} revision {q.get('packageRevision')}, not {s['id']}")
    catalog.require(q.get('generation') == 21, 'stable settings evidence (option (a)) covers P21 releases only')
    catalog.require(isinstance(identity.get('buildID'), str) and q.get('buildID') == identity['buildID'],
                    'the qualification record names another build')
    catalog.require(settings_contract_kept(q),
                    "the record doesn't show the verifier's settings contract unchanged or a reviewed migration")
    verifier = (q.get('checks') or {}).get('verifier') or {}
    catalog.require(verifier.get('status') == 'pass-source-and-binary-checks' and verifier.get('pendingEvidence') == []
                    and verifier.get('stackBudgetFailures') == [], "the record doesn't show the verifier passing")
    _, application = package_parts(asset)
    catalog.require(application is not None, 'a stable release replaces only the application')
    image = q.get('image') or {}
    catalog.require(image.get('sha256') == hashlib.sha256(application[1]).hexdigest(),
                    'the qualification record is for another image')
    margin = image.get('dualBankMarginBytes')
    catalog.require(type(margin) is int and margin >= 0, 'the record has no dual-bank budget')
    rings = (q.get('stableEvidence') or {}).get('rings')
    catalog.require(isinstance(rings, list) and all(isinstance(r, dict) for r in rings), 'the record names no Rings')
    names = [r.get('ring') for r in rings]
    catalog.require(all(isinstance(n, str) and n for n in names) and len(set(names)) == len(names) >= 2,
                    'the release must run on Rings A and B')
    for ring in rings:
        catalog.require(ring.get('buildID') == identity['buildID'] and ring.get('settings') == 'same'
                        and ring.get('bonds') == 'kept',
                        f"{ring['ring']}: not this build with its settings and bonds intact")
    catalog.require(bool(source_versions), 'a stable release names the versions it replaces (--source-version)')
    return {'contract': 'factory-settings-v1', 'packageSHA256': s['asset']['sha256'],
            'evidenceSHA256': hashlib.sha256(record_bytes).hexdigest(), 'sourceVersions': list(source_versions),
            'preservesAllSettings': True}


def promote(product, release_id, channel, asset, out, minimum_app_build, erases_storage, auto_install=False,
            customer_version=None, change_note=None, minimum_source_revision=None, source_versions=None,
            settings_compatibility=None, qualification=None, notes=None, notice=None, key_id=None, signer=None,
            keys=None, images=None):
    """Stage a version 2 statement for a published release on `channel`.

    Channels are signed and tags never change, so a release moves to beta or
    stable by being signed again: same ID, revision and package, a new
    statement. `asset` is a copy of the published package, checked against the
    signed statement. The entry keeps its tag, URLs and unsigned display fields;
    a test build's tester `notice` is dropped unless `notice` replaces it, and
    `notes` replaces its release notes. `publish` of `out` replaces the entry.
    A stable release's settings evidence comes from its qualification record
    (`qualification`, its bytes; `stable_evidence`), never a hand-written one."""
    catalog.require(channel in ('beta', 'stable'), 'promote signs a release for beta or stable')
    catalog.require(channel == 'stable' or qualification is None, 'a qualification record is for stable releases')
    catalog.require(catalog.SCHEMA_V2 in catalog.PRODUCTS[product]['schemas'], f'{product} has no version 2 statements')
    key_id = key_id or catalog.PRODUCTS[product]['keys'][0]
    keys = keys or catalog.load_keys()
    current = catalog.read(product)
    old = next((e for e in current['releases'] if e['id'] == release_id), None)
    catalog.require(old is not None, f'{release_id} is not in the {product} catalog')
    s = catalog.verify_entry(product, old, keys)
    catalog.require(s['installable'] and not old['withdrawn'], f'{release_id} is withdrawn or not installable')
    catalog.require(asset.is_file() and record(asset) == s['asset'], f'{asset} is not the package {release_id} signed')
    details = copy.deepcopy(old.get('details') or {})
    identity = details.get('buildIdentity')
    catalog.require(isinstance(identity, dict), f'{release_id}: its details carry no build identity')
    parts, application = package_parts(asset)
    automatic = {'autoInstall': auto_install, 'minimumAppBuild': minimum_app_build, 'erasesStorage': erases_storage,
                 'applicationOnly': application is not None, 'buildIdentity': identity}
    if customer_version is not None:
        # What the app calls it is what GitHub calls it (release_title): Sudo
        # major.subrelease.increment, the increment its signed revision.
        catalog.require(isinstance(customer_version, str) and customer_version.count('.') == 2,
                        '--customer-version must be major.subrelease.increment, such as 1.0.124')
        release_title(s, customer_version, option='--customer-version')
    for field, value in (('customerVersion', customer_version), ('changeNote', change_note),
                         ('minimumSourceRevision', minimum_source_revision)):
        if value is not None:
            automatic[field] = value
    if channel == 'stable':
        catalog.require(settings_compatibility is None, 'a stable release takes its settings evidence from its qualification record')
        catalog.require(qualification is not None, 'a stable release needs its qualification record (--qualification)')
        settings_compatibility = stable_evidence(s, identity, asset, qualification, source_versions)
    if source_versions is not None:
        catalog.require(isinstance(settings_compatibility, dict)
                        and settings_compatibility.get('sourceVersions') == list(source_versions)
                        and settings_compatibility.get('packageSHA256') == s['asset']['sha256'],
                        'signed source versions need settings evidence for exactly those versions and this package')
        details['settingsCompatibility'] = settings_compatibility
    else:
        catalog.require(settings_compatibility is None, 'settings evidence without signed source versions grants nothing')
    if (auto_install or channel == 'stable') and product in DUAL_BANK:
        row = (images or load_images(product))['packages'].get(s['asset']['sha256'])
        catalog.require(row is not None, f'{release_id}: its package has no recorded image; run record-images')
        margin = dual_bank(product, s['asset']['sha256'], row['imageBytes'], current, images or load_images(product))
        print(f'dual-bank budget: {margin} bytes to spare')
    statement = catalog.make_statement(product, s['id'], s['version'], s['packageRevision'], channel, True,
                                       s['asset'], utc_seconds(), source_versions, automatic)
    raw = catalog.encode_statement(statement)
    out.mkdir(parents=True, exist_ok=False)
    (out / 'statement.json').write_bytes(raw)
    sign(product, out / 'statement.json', out / 'signature.der', signer)
    der = (out / 'signature.der').read_bytes()
    catalog.require(p256.verify(keys[key_id], raw, der), 'fresh signature does not verify with the published key')
    entry = copy.deepcopy(old)
    # The rollout is the catalog's live control (`rollout`), never part of a
    # promotion: publish_promotion keeps whatever the catalog has by then.
    entry.pop('rollout', None)
    entry['channel'] = channel
    entry['statement'] = base64.b64encode(raw).decode()
    entry['signature'] = {'alg': 'ES256', 'keyId': key_id, 'der': base64.b64encode(der).decode()}
    if details.get('status') == 'signed-test-ota':
        details['status'] = 'supplier-signed-ota'  # what apps read as an installable release, not a test build
    details['promotedFrom'] = {'channel': s['channel'], 'schema': s['schema'], 'issuedAt': s['issuedAt'],
                               'statementSHA256': hashlib.sha256(base64.b64decode(old['statement'])).hexdigest()}
    for field, value in (('notice', notice), ('releaseNotes', notes)):
        if value is not None:
            entry[field] = details[field] = value
        elif field == 'notice':
            entry.pop(field, None); details.pop(field, None)
    entry['details'] = details
    catalog.verify_entry(product, entry, keys)
    (out / 'entry.json').write_text(json.dumps({'product': product, 'promotes': release_id, 'entry': entry},
                                               indent=2) + '\n')
    return entry


def publish_promotion(directory, push=False, dry_run=False):
    """Replace a release's entry with its promotion, once its package is still
    publicly the signed bytes. Nothing on GitHub changes."""
    data = json.loads((directory / 'entry.json').read_text())
    product, entry = data['product'], data['entry']
    keys = catalog.load_keys()
    s = catalog.verify_entry(product, entry, keys)
    catalog.require(data['promotes'] == s['id'], 'promotion names another release')
    catalog.require(base64.b64decode(entry['statement']) == (directory / 'statement.json').read_bytes(),
                    'statement file differs from entry')
    current = catalog.read(product)
    index = next((i for i, e in enumerate(current['releases']) if e['id'] == s['id']), None)
    catalog.require(index is not None, f"{s['id']} is no longer in the catalog")
    old = current['releases'][index]
    old_s = catalog.verify_entry(product, old, keys)
    catalog.require(not old['withdrawn'], f"{s['id']} was withdrawn since it was promoted")
    catalog.require(old_s['asset'] == s['asset'] and old['tag'] == entry['tag']
                    and old['asset'].get('url') == entry['asset'].get('url')
                    and old['asset'].get('apiURL') == entry['asset'].get('apiURL'),
                    f"{s['id']}: the promotion's package or URLs differ from the published entry")
    # A rollout changed after staging (lowered to stop installs) stays as it
    # is now. It needs a signed autoInstall, so signing one away drops it.
    entry.pop('rollout', None)
    if 'rollout' in old and s['schema'] == catalog.SCHEMA_V2 and s['autoInstall']:
        entry['rollout'] = copy.deepcopy(old['rollout'])
    catalog.verify_entry(product, entry, keys)
    if dry_run:
        print(f"would promote {s['id']} from {old_s['channel']} to {s['channel']}"); return entry
    for url, accept in ((entry['asset']['url'], None), (entry['asset'].get('apiURL'), 'application/octet-stream')):
        if url:
            catalog.require(hashlib.sha256(anonymous_get(url, accept)).hexdigest() == s['asset']['sha256'],
                            f'public download mismatch: {url}')
    current['releases'][index] = entry
    catalog.write(product, current)
    commit([catalog.catalog_path(product)], f"Promote {product} {s['id']} to {s['channel']}", push)
    print(f"promoted {s['id']} to {s['channel']}")
    return entry


def withdraw(product, release_id, reason):
    """Unsigned withdrawal is honoured by clients because it only removes an offer."""
    current = catalog.read(product)
    entry = next(e for e in current['releases'] if e['id'] == release_id)
    entry['withdrawn'] = True; entry['withdrawnReason'] = reason
    catalog.write(product, current)


def set_rollout(product, release_id, percent, since=None):
    """Devices whose bucket is below `percent` may install this release by
    themselves. The catalog refuses a rollout without a signed autoInstall, and
    above a signed policy's ceiling: then this only lowers (`policy` raises)."""
    current = catalog.read(product)
    entry = next((e for e in current['releases'] if e['id'] == release_id), None)
    catalog.require(entry is not None, f'{release_id} is not in the {product} catalog')
    entry['rollout'] = {'percent': percent,
                        'since': since or datetime.now(timezone.utc).strftime('%Y-%m-%d')}
    catalog.write(product, current)


def set_pause(product, pause):
    """`pause`: "all", "background" or None (automatic installs resume)."""
    current = catalog.read(product)
    releases = current.pop('releases')
    current.pop('automaticUpdatesPaused', None)
    if pause is not None:
        current['automaticUpdatesPaused'] = pause
    current['releases'] = releases
    catalog.write(product, current)


def release_name(s):
    """What people call a release: "Sudo 1.0.124", or its ID before Sudo 1.0.107."""
    title = release_title(s)
    return title if title.startswith('Sudo 1.') else s['id']


def policy_summary(product, before, after, releases):
    """What a policy does, in words, for the review before it is signed."""
    statements = [(e, json.loads(base64.b64decode(e['statement']))) for e in releases]
    lines = [f"Policy {product} {after['sequence']}" + ('' if before else ' (the first)') + f", issued {after['issuedAt']}"]
    cut = catalog.floor_cut(after)
    if cut is None:
        lines.append('Floor: none.')
    else:
        generation, revision = max(((int(g), r) for g, r in after['minimumRevision'].items()),
                                   key=lambda item: catalog.rank(f'6.0.3.3P{item[0]:02d}', item[1]))
        below = [s for e, s in statements if catalog.below_floor(after, s) and s['installable'] and not e['withdrawn']]
        lines.append(f'Floor: P{generation} revision {revision}. Below it nothing installs on App Store or TestFlight '
                     f'builds (team builds may go below): {len(below)} installable releases, from '
                     + (f"{release_name(below[-1])} to {release_name(below[0])}." if below else 'none.'))
    old = {w['id'] for w in before['withdrawn']} if before else set()
    for w in after['withdrawn']:
        lines.append(f"Withdrawn{'' if w['id'] in old else ' (new)'}: {w['id']}, package {w['sha256'][:12]}…")
    if not after['withdrawn']:
        lines.append('Withdrawn: none.')
    for release_id, percent in sorted(after['rollout'].items()):
        lines.append(f'Rollout ceiling: {release_id} {percent}%')
    if not after['rollout']:
        lines.append('Rollout ceilings: none, so no Ring updates itself.')
    return '\n'.join(lines)


def policy(product, withdraw=(), reason=None, floors=(), rollouts=(), out=None, dry_run=False, push=False,
           signer=None, keys=None):
    """Sign `product`'s next policy and commit it with the catalog's copy and
    the unsigned fields builds before the policy read: a policy withdrawal is
    also `withdrawn: true`, and a ceiling the entry's `rollout`. `floors` are
    (generation, revision) pairs, `rollouts` (release ID, percent). `dry_run`
    signs and changes nothing; it prints, and with `out` writes, the unsigned
    statement and what it would do."""
    catalog.require(product in catalog.POLICY_PRODUCTS, f'{product} has no signed policy')
    keys = keys or catalog.load_keys()
    current = catalog.read(product)
    envelope = catalog.read_policy(product)
    catalog.require(envelope == current.get('policy'), "policy-v1.json and the catalog's policy differ")
    before = catalog.verify_policy(product, envelope, keys)[0] if envelope else None
    floor = dict(before['minimumRevision']) if before else {}
    withdrawn = {w['id']: w for w in before['withdrawn']} if before else {}
    ceilings = dict(before['rollout']) if before else {}
    entries = {e['id']: e for e in current['releases']}
    signed = {i: json.loads(base64.b64decode(e['statement'])) for i, e in entries.items()}
    for release_id in withdraw:
        catalog.require(release_id in entries, f'{release_id} is not in the {product} catalog')
        withdrawn[release_id] = {'id': release_id, 'sha256': signed[release_id]['asset']['sha256']}
        if not entries[release_id]['withdrawn']:
            catalog.require(reason, f'{release_id} is offered: give the withdrawal a --reason')
            entries[release_id]['withdrawn'] = True; entries[release_id]['withdrawnReason'] = reason
        ceilings.pop(release_id, None); entries[release_id].pop('rollout', None)
    for generation, revision in floors:
        floor[str(generation)] = revision
    for release_id, percent in rollouts:
        catalog.require(release_id in entries, f'{release_id} is not in the {product} catalog')
        catalog.require(release_id not in withdrawn, f'{release_id} is withdrawn')
        ceilings[release_id] = percent
        entries[release_id]['rollout'] = {'percent': percent, 'since': datetime.now(timezone.utc).strftime('%Y-%m-%d')}
    after = catalog.make_policy(product, (before['sequence'] if before else 0) + 1, utc_seconds(), floor,
                                withdrawn.values(), ceilings)
    unchanged = lambda s: {k: v for k, v in s.items() if k not in ('sequence', 'issuedAt')}  # noqa: E731
    catalog.require(before is None or unchanged(after) != unchanged(before), 'the policy would not change')
    catalog.check_policy_statement(after, product)
    catalog.check_policy_against_catalog(product, after, current['releases'], keys)
    catalog.check_policy_history(before, after)
    # Signed now, so stricter than the catalog check: something is still
    # offered at the floor, and each ceiling admits an offered release.
    offered = [s for i, s in signed.items() if s['installable'] and not entries[i]['withdrawn'] and i not in withdrawn]
    catalog.require(catalog.floor_cut(after) is None or any(not catalog.below_floor(after, s) for s in offered),
                    'the floor is above every release still offered')
    for release_id in ceilings:
        catalog.require(signed[release_id] in offered and not catalog.below_floor(after, signed[release_id]),
                        f'rollout {release_id}: withdrawn or below the floor; drop its ceiling')
    raw = catalog.encode_statement(after)
    catalog.require(len(raw) <= catalog.POLICY_STATEMENT_BYTES, f'the policy is over {catalog.POLICY_STATEMENT_BYTES} bytes')
    summary = policy_summary(product, before, after, current['releases'])
    print(summary)
    if out:
        out.mkdir(parents=True, exist_ok=False)
        (out / 'statement.json').write_bytes(raw)
        (out / 'summary.txt').write_text(summary + '\n')
    if dry_run:
        return after
    with tempfile.TemporaryDirectory() as folder:
        statement_path, der_path = Path(folder) / 'statement.json', Path(folder) / 'signature.der'
        statement_path.write_bytes(raw)
        sign(product, statement_path, der_path, signer)
        der = der_path.read_bytes()
    key_id = catalog.PRODUCTS[product]['keys'][0]
    catalog.require(p256.verify(keys[key_id], raw, der), 'fresh signature does not verify with the published key')
    envelope = {'schemaVersion': 1, 'product': product, 'hardware': catalog.PRODUCTS[product]['hardware'],
                'statement': base64.b64encode(raw).decode(),
                'signature': {'alg': 'ES256', 'keyId': key_id, 'der': base64.b64encode(der).decode()}}
    releases = current.pop('releases')
    current['policy'] = envelope
    current['releases'] = releases
    catalog.write(product, current)
    catalog.policy_path(product).write_text(json.dumps(envelope, indent=2) + '\n')
    commit([catalog.catalog_path(product), catalog.policy_path(product)],
           f"Policy {product} {after['sequence']}", push)
    print(f"signed and committed policy {after['sequence']}")
    return after


def record_images(product, packages=(), download=False, import_from=None):
    """Record the application image of catalog packages: from local copies, by
    downloading those without a record, or from another record (ShopItalic/sudo's
    tools/firmware-hosting/package-images.json). Each package is checked
    against its signed statement first; a record never changes."""
    catalog.require(product in DUAL_BANK, f'{product} has no dual-bank check')
    current = catalog.read(product)
    statements = {json.loads(base64.b64decode(e['statement']))['asset']['sha256']: e for e in current['releases']}
    images = load_images(product)
    rows = images['packages']
    def add(digest, row):
        catalog.require(rows.get(digest, row) == row, f'{digest[:12]}: a different record exists')
        rows[digest] = row
    for digest, row in ((import_from and json.loads(Path(import_from).read_text())['packages']) or {}).items():
        catalog.require(catalog.SHA.fullmatch(digest) and type(row.get('imageBytes')) is int
                        and type(row.get('packageBytes')) is int, f'{digest[:12]}: bad imported record')
        add(digest, row)
    for path in packages:
        entry = statements.get(sha256(path))
        catalog.require(entry is not None, f'{path}: not a package in the {product} catalog')
        s = json.loads(base64.b64decode(entry['statement']))
        add(s['asset']['sha256'], image_record(entry['tag'], s, path))
    if download:
        for digest, entry in statements.items():
            if digest in rows:
                continue
            s = json.loads(base64.b64decode(entry['statement']))
            with tempfile.TemporaryDirectory() as folder:
                path = Path(folder) / s['asset']['name']
                path.write_bytes(anonymous_get(entry['asset']['url']))
                catalog.require(record(path) == s['asset'], f"{s['id']}: the download is not the signed package")
                add(digest, image_record(entry['tag'], s, path))
    write_images(product, images)
    missing = [e['id'] for d, e in statements.items() if d not in rows]
    print(f'{product}: {len(rows)} images recorded' + (f'; no record for {", ".join(missing)}' if missing else ''))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest='command', required=True)
    s = sub.add_parser('stage')
    s.add_argument('--product', required=True, choices=sorted(catalog.PRODUCTS))
    s.add_argument('--id', required=True); s.add_argument('--version', required=True)
    s.add_argument('--revision', type=int, default=1)
    s.add_argument('--channel', required=True, choices=catalog.CHANNELS)
    s.add_argument('--installable', action='store_true')
    s.add_argument('--asset', type=Path, required=True)
    s.add_argument('--extra', type=Path, action='append', default=[])
    s.add_argument('--source-version', action='append')
    s.add_argument('--notes', help='release notes shown to users')
    s.add_argument('--out', type=Path, required=True)
    p = sub.add_parser('publish'); p.add_argument('directory', type=Path)
    p.add_argument('--push', action='store_true'); p.add_argument('--dry-run', action='store_true')
    p.add_argument('--firmware-version', help='Sudo display version: major.release.increment; increment must match the signed revision')
    m = sub.add_parser('promote', help='sign a published release again for beta or stable (version 2)')
    m.add_argument('--product', required=True, choices=sorted(catalog.PRODUCTS))
    m.add_argument('--id', required=True)
    m.add_argument('--channel', required=True, choices=('beta', 'stable'))
    m.add_argument('--asset', type=Path, required=True, help='a copy of the published package')
    m.add_argument('--minimum-app-build', type=int, required=True)
    m.add_argument('--erases-storage', required=True, choices=('yes', 'no'),
                   help="whether the release's first boot formats the recording storage")
    m.add_argument('--auto', action='store_true', help='the release may install itself (stable only)')
    m.add_argument('--customer-version', help='the name people see, such as 1.0.124: its increment is the revision')
    m.add_argument('--change-note', help='one line of what people will feel or see')
    m.add_argument('--minimum-source-revision', type=int)
    m.add_argument('--source-version', action='append')
    m.add_argument('--settings-evidence', type=Path, help='settingsCompatibility JSON for the source versions (beta)')
    m.add_argument('--qualification', type=Path,
                   help="the release's ShopItalic/sudo qualification record: a stable release's settings evidence")
    m.add_argument('--notes', help='release notes for the people who install it (required for stable)')
    m.add_argument('--notice', help='a notice shown under the notes; a test build\'s is dropped otherwise')
    m.add_argument('--out', type=Path, required=True)
    w = sub.add_parser('withdraw'); w.add_argument('--product', required=True); w.add_argument('--id', required=True)
    w.add_argument('--reason', required=True)
    r = sub.add_parser('rollout'); r.add_argument('--product', required=True); r.add_argument('--id', required=True)
    r.add_argument('--percent', type=int, required=True); r.add_argument('--since')
    a = sub.add_parser('pause-automatic'); a.add_argument('--product', required=True)
    a.add_argument('--background', action='store_true', help='pause only installs started in the background')
    u = sub.add_parser('resume-automatic'); u.add_argument('--product', required=True)
    o = sub.add_parser('policy', help="sign the product's next policy (floor, withdrawals, rollout ceilings)")
    o.add_argument('--product', required=True, choices=catalog.POLICY_PRODUCTS)
    o.add_argument('--withdraw', action='append', default=[], metavar='ID', help='withdraw a release for good')
    o.add_argument('--reason', help="a new withdrawal's reason, shown in the catalog")
    o.add_argument('--floor', action='append', default=[], metavar='GENERATION:REVISION',
                   help='nothing ranked below this installs, such as 21:124; it only rises')
    o.add_argument('--rollout', action='append', default=[], metavar='ID:PERCENT',
                   help="a release's signed rollout ceiling, also written as its entry's rollout")
    o.add_argument('--out', type=Path, help='also write the statement and the summary here')
    o.add_argument('--dry-run', action='store_true', help='sign nothing and change nothing')
    o.add_argument('--push', action='store_true')
    i = sub.add_parser('record-images'); i.add_argument('--product', required=True)
    i.add_argument('packages', type=Path, nargs='*'); i.add_argument('--download', action='store_true')
    i.add_argument('--import', dest='import_from', type=Path)
    args = parser.parse_args(argv)
    if args.command == 'stage':
        entry = stage(args.product, args.id, args.version, args.revision, args.channel, args.installable,
                      args.asset, args.extra, args.out, args.source_version,
                      display={'releaseNotes': args.notes} if args.notes else None)
        print(json.dumps({'staged': str(args.out), 'tag': entry['tag'], 'asset': entry['asset']}, indent=2))
    elif args.command == 'publish':
        publish(args.directory, push=args.push, dry_run=args.dry_run, firmware_version=args.firmware_version)
    elif args.command == 'promote':
        catalog.require(args.channel != 'stable' or args.notes, 'a stable release needs --notes for its customers')
        entry = promote(args.product, args.id, args.channel, args.asset, args.out, args.minimum_app_build,
                        args.erases_storage == 'yes', auto_install=args.auto, customer_version=args.customer_version,
                        change_note=args.change_note, minimum_source_revision=args.minimum_source_revision,
                        source_versions=args.source_version,
                        settings_compatibility=json.loads(args.settings_evidence.read_text()) if args.settings_evidence else None,
                        qualification=args.qualification.read_bytes() if args.qualification else None,
                        notes=args.notes, notice=args.notice)
        print(json.dumps({'staged': str(args.out), 'tag': entry['tag'], 'channel': entry['channel']}, indent=2))
    elif args.command == 'rollout':
        set_rollout(args.product, args.id, args.percent, args.since)
    elif args.command == 'pause-automatic':
        set_pause(args.product, 'background' if args.background else 'all')
    elif args.command == 'resume-automatic':
        set_pause(args.product, None)
    elif args.command == 'record-images':
        record_images(args.product, args.packages, args.download, args.import_from)
    elif args.command == 'policy':
        def pair(text, name):
            left, sep, right = text.rpartition(':')
            catalog.require(sep and left and right.isdigit(), f'--{name} takes {name.upper()}:NUMBER, got {text!r}')
            return left, int(right)
        floors = [(int(g), r) for g, r in (pair(text, 'floor') for text in args.floor) if g.isdigit()]
        catalog.require(len(floors) == len(args.floor), '--floor takes GENERATION:REVISION, such as 21:124')
        policy(args.product, args.withdraw, args.reason, floors, [pair(text, 'rollout') for text in args.rollout],
               out=args.out, dry_run=args.dry_run, push=args.push)
    else:
        withdraw(args.product, args.id, args.reason)


if __name__ == '__main__':
    sys.exit(main())
