#!/usr/bin/env python3
"""Stage (sign locally) and publish firmware releases to ShopItalic/firmware.

  stage    Copy the package and extra assets into a new staging directory,
           write the canonical release statement and sign it with the product's
           Keychain key. No network access.
  publish  Create an immutable GitHub prerelease/release for a staged
           directory, verify every asset anonymously, then add the signed entry
           to products/<product>/catalog-v1.json and commit. Order matters:
           assets are public and verified before the catalog offers them.

Qualification gates live in each product's source repo; this tool refuses
anything that is not signed, hashed and uniquely tagged.
"""
import argparse
import base64
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import catalog
import device_index
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


def stage(product, release_id, version, revision, channel, installable, asset, extras, out,
          source_versions=None, display=None, details=None, key_id=None, signer=None, keys=None):
    catalog.require(product in catalog.PRODUCTS, 'unknown product')
    key_id = key_id or catalog.PRODUCTS[product]['keys'][0]
    keys = keys or catalog.load_keys()
    names = [asset.name] + [p.name for p in extras]
    catalog.require(len(set(names)) == len(names), 'duplicate asset names')
    catalog.require(not {'statement.json', 'signature.der', 'SHA256SUMS'} & set(names),
                    'asset name collides with a release-level file')
    out.mkdir(parents=True, exist_ok=False)
    files = out / 'assets'; files.mkdir()
    for path in [asset, *extras]:
        catalog.require(path.is_file() and not path.is_symlink(), f'not a regular file: {path}')
        shutil.copyfile(path, files / path.name)
        catalog.require(sha256(files / path.name) == sha256(path), f'copy changed {path.name}')
    statement = catalog.make_statement(product, release_id, version, revision, channel, installable,
                                       record(files / asset.name), utc_seconds(), source_versions)
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


def publish(directory, notes=None, push=False, dry_run=False):
    product, entry, s = load_stage(directory)
    current = catalog.read(product) if catalog.catalog_path(product).exists() else catalog.empty(product)
    catalog.require(all(e['id'] != s['id'] for e in current['releases']), f"{s['id']} already in catalog")
    release_tag = entry['tag']
    existing = subprocess.run(['gh', 'release', 'view', release_tag, '--repo', catalog.OWNER_REPO],
                              capture_output=True, text=True)
    catalog.require(existing.returncode != 0, f'tag {release_tag} already exists; tags are never reused')
    files = sorted((directory / 'assets').iterdir()) + [directory / 'SHA256SUMS', directory / 'statement.json',
                                                         directory / 'signature.der']
    title = f"{product.capitalize()} {s['id']}"
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
    paths = [catalog.catalog_path(product)] + device_index.write(product, current)
    subprocess.run(['git', '-C', str(catalog.ROOT), 'add', *map(str, paths)], check=True)
    subprocess.run(['git', '-C', str(catalog.ROOT), 'commit', '-q', '-m', f'Publish {product} {s["id"]}'], check=True)
    if push:
        subprocess.run(['git', '-C', str(catalog.ROOT), 'push', '-q'], check=True)
    print(f'published {release_tag}: {entry["asset"]["url"]}')
    return entry


def withdraw(product, release_id, reason):
    """Unsigned withdrawal is honoured by clients because it only removes an offer."""
    current = catalog.read(product)
    entry = next(e for e in current['releases'] if e['id'] == release_id)
    entry['withdrawn'] = True; entry['withdrawnReason'] = reason
    catalog.write(product, current)
    device_index.write(product, current)


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
    w = sub.add_parser('withdraw'); w.add_argument('--product', required=True); w.add_argument('--id', required=True)
    w.add_argument('--reason', required=True)
    args = parser.parse_args(argv)
    if args.command == 'stage':
        entry = stage(args.product, args.id, args.version, args.revision, args.channel, args.installable,
                      args.asset, args.extra, args.out, args.source_version,
                      display={'releaseNotes': args.notes} if args.notes else None)
        print(json.dumps({'staged': str(args.out), 'tag': entry['tag'], 'asset': entry['asset']}, indent=2))
    elif args.command == 'publish':
        publish(args.directory, push=args.push, dry_run=args.dry_run)
    else:
        withdraw(args.product, args.id, args.reason)


if __name__ == '__main__':
    sys.exit(main())
