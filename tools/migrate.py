#!/usr/bin/env python3
"""One-time migration of existing firmware into signed staging directories.

  sudo   Mirror every release in the live curated Sudo catalog
         (ShopItalic/sudo tools/firmware-hosting/releases-v9.json): download all
         assets of its GitHub release, verify the package against the catalog
         and the upstream SHA256SUMS, and stage it as sudo-<version>-r<revision>.
  glyph  Stage each factory-derived P-series bundle from the private Glyph
         checkout that passes glyph_release.verify and is not withdrawn. Only the
         UFW, release notes, test plan and a generated public summary are
         published: private manifests/provenance name build hosts, and ELF/map
         files carry vendor symbols. Their hashes are pinned in release.json.

Nothing is uploaded here; publish each directory with tools/release.py.
"""
import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

import catalog
import release

SUDO_CATALOG = 'https://raw.githubusercontent.com/ShopItalic/sudo/main/tools/firmware-hosting/releases-v9.json'
GLYPH = Path('/Users/jeremy/Projects/glyph')


def sudo(out):
    raw = release.anonymous_get(SUDO_CATALOG)
    source = {'catalog': SUDO_CATALOG, 'catalogSHA256': hashlib.sha256(raw).hexdigest()}
    staged = []
    for item in json.loads(raw)['releases']:
        # Download-only test entries carry downloadPackage instead of otaPackage.
        package = item.get('otaPackage') or item['downloadPackage']
        old_tag, name = package['url'].split('/releases/download/', 1)[1].split('/')
        revision = item.get('packageRevision') or 1
        release_id = f"{item['version']}-r{revision}"
        if (out / f'sudo-{release_id}').exists():
            print('already staged', release_id); continue
        work = Path(tempfile.mkdtemp(prefix='sudo-migrate-'))
        subprocess.run(['gh', 'release', 'download', old_tag, '--repo', 'ShopItalic/sudo', '-D', str(work)],
                       check=True, capture_output=True)
        main = work / name
        catalog.require(release.record(main) == {'name': name, 'bytes': package['bytes'], 'sha256': package['sha256']},
                        f'{old_tag}: package does not match the live catalog')
        upstream = work / 'SHA256SUMS'
        if upstream.exists():
            for line in upstream.read_text().splitlines():
                digest, filename = line.split(maxsplit=1)
                catalog.require(release.sha256(work / filename.lstrip('*')) == digest, f'{old_tag}: {filename} mismatch')
            upstream.rename(work / 'upstream-SHA256SUMS')
        extras = sorted(p for p in work.iterdir() if p.name != name)
        compat = item.get('settingsCompatibility') or {}
        details = {k: v for k, v in item.items() if k not in ('otaPackageURL', 'otaPackage', 'downloadPackage')}
        details['migratedFrom'] = {**source, 'repository': 'ShopItalic/sudo', 'tag': old_tag, 'url': package['url']}
        display = {k: item[k] for k in ('releaseNotes', 'notice', 'qualification') if item.get(k)}
        entry = release.stage('sudo', release_id, item['version'], revision, 'test',
                              bool(item.get('otaAvailable') and item.get('otaPackage')) and not item.get('withdrawn'),
                              main, extras,
                              out / f'sudo-{release_id}', compat.get('sourceVersions'), display, details)
        staged.append(entry['tag'])
        print('staged', entry['tag'], flush=True)
    return staged


def glyph(out):
    sys.path.insert(0, str(GLYPH / 'tools'))
    import glyph_release
    states = {r['id']: r for r in json.loads((GLYPH / 'firmware/releases/catalog.json').read_text())['releases']}
    staged = []
    for directory in sorted((GLYPH / 'dist/releases').glob('P*'), key=lambda p: [int(x) if x.isdigit() else x
                            for x in p.name.replace('-rc.', '.').replace('P', '').split('.')]):
        manifest = glyph_release.verify(directory)
        state = states.get(manifest['id'], {})
        if (out / f"glyph-{manifest['id']}").exists():
            print('already staged', manifest['id']); continue
        if state.get('status') == 'withdrawn':
            print('skip withdrawn', manifest['id']); continue
        files = {f['role']: f for f in manifest['files']}
        ufw = directory / files['firmware']['path']
        work = Path(tempfile.mkdtemp(prefix='glyph-migrate-'))
        summary = {
            'schema': 'glyph-public-release/1', 'id': manifest['id'], 'hardware': manifest['hardware'],
            'lineage': manifest['lineage'], 'baseRelease': manifest['baseRelease'],
            'purpose': manifest.get('purpose'), 'changes': manifest.get('changes', []),
            'deviceModelExpected': manifest.get('deviceModelExpected'),
            'deviceVersionExpected': manifest.get('deviceVersionExpected'),
            'status': state.get('status', manifest['status']),
            'firmware': {'name': ufw.name, 'bytes': files['firmware']['bytes'], 'sha256': files['firmware']['sha256']},
            'privateManifestSHA256': release.sha256(directory / 'manifest.json'),
            'privateArtifacts': [{'role': f['role'], 'bytes': f['bytes'], 'sha256': f['sha256']}
                                 for f in manifest['files'] if f['role'] != 'firmware'],
            'baseArtifacts': [{'name': Path(a['path']).name, 'bytes': a['bytes'], 'sha256': a['sha256']}
                              for a in manifest.get('baseArtifacts', [])],
        }
        (work / 'release.json').write_text(json.dumps(summary, indent=2) + '\n')
        extras = [work / 'release.json'] + [directory / files[r]['path'] for r in ('release-notes', 'test-plan') if r in files]
        notes = ' '.join(manifest.get('changes', []))[:2000] or None
        display = {'releaseNotes': notes, 'notice': 'Staged test build; physical qualification varies by release. '
                   'Not offered for automatic installation.'}
        details = {'status': summary['status'], 'purpose': summary['purpose'], 'baseRelease': summary['baseRelease'],
                   'deviceVersionExpected': summary['deviceVersionExpected'],
                   'privateManifestSHA256': summary['privateManifestSHA256']}
        entry = release.stage('glyph', manifest['id'], manifest['id'], 1, 'test', False, ufw, extras,
                              out / f"glyph-{manifest['id']}", None, display, details)
        staged.append(entry['tag'])
        print('staged', entry['tag'], flush=True)
    return staged


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('product', choices=['sudo', 'glyph'])
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    {'sudo': sudo, 'glyph': glyph}[args.product](args.out)
