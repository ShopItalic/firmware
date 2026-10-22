#!/usr/bin/env python3
"""Write tests/fixtures/sudo-stable-v2.json: two stable version 2 releases,
1.0 (revision 117) and 1.1 (revision 118), staged, published and promoted by
these tools with a throwaway key over made-up packages. ShopItalic/app's
RingFirmwareReleaseTests decode the same file. Run it again only when the
statement format changes, then copy the file into the app's tests."""
import base64
import contextlib
import hashlib
import io
import json
import sys
import tempfile
import zipfile
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import catalog  # noqa: E402
import p256  # noqa: E402
import release  # noqa: E402

OUT = Path(__file__).parent / 'fixtures' / 'sudo-stable-v2.json'


def package(path, fill):
    path.parent.mkdir(parents=True)
    with zipfile.ZipFile(path, 'w') as archive:
        for name, data in (('manifest.json', json.dumps({'manifest': {'application': {
                'bin_file': 'app.bin', 'dat_file': 'app.dat'}}}).encode()),
                           ('app.bin', bytes([fill]) * 4096), ('app.dat', b'\0' * 141)):
            archive.writestr(zipfile.ZipInfo(name, (2026, 10, 22, 0, 0, 0)), data)
    return path


def main():
    private, public = p256.generate()
    keys = {'sudo-release-1': public}
    sign = lambda raw: p256.sign(private, raw)  # noqa: E731
    with tempfile.TemporaryDirectory() as folder, mock.patch.object(catalog, 'ROOT', Path(folder)), \
            mock.patch.object(release, 'commit'), contextlib.redirect_stdout(io.StringIO()):
        root = Path(folder)
        (root / 'keys').mkdir(); (root / 'keys' / 'sudo-release-1.x963').write_bytes(public)
        (root / 'products' / 'sudo').mkdir(parents=True)
        releases = [(117, '1.0', None, 0x17, 10), (118, '1.1', 'shorter start and stop buzzes', 0x18, 100)]
        for revision, name, note, fill, percent in releases:
            zip_path = package(root / str(revision) / 'BCL603S2P_6.0.3.3P21.zip', fill)
            identity = {'generation': 21, 'revision': revision, 'codec': 1, 'settingsSchema': 6,
                        'buildID': f'{revision:032x}'}
            details = {'schemaVersion': 1, 'hardware': '603V1.23.2', 'version': '6.0.3.3P21',
                       'packageRevision': revision, 'buildIdentity': identity, 'status': 'signed-test-ota',
                       'otaAvailable': True, 'notice': f'P21 revision {revision} tester update'}
            out = root / 'stage' / str(revision)
            entry = release.stage('sudo', f'6.0.3.3P21-r{revision}', '6.0.3.3P21', revision, 'test', True, zip_path,
                                  [], out, details=details, display={'notice': details['notice']}, signer=sign, keys=keys)
            entry['asset']['apiURL'] = f'{catalog.ASSET_API}{660000000 + revision}'
            current = catalog.read('sudo') if catalog.catalog_path('sudo').exists() else catalog.empty('sudo')
            current['releases'].insert(0, entry)
            catalog.write('sudo', current)
            images = release.load_images('sudo')
            images['packages'][entry['asset']['sha256']] = json.loads((out / 'image.json').read_text())
            release.write_images('sudo', images)
            # A made-up qualification record (release.stable_evidence): the
            # committed fixture predates them, so its evidence digests differ.
            record = json.dumps({
                'wireVersion': '6.0.3.3P21', 'packageRevision': revision, 'generation': 21, 'buildID': identity['buildID'],
                'recipe': {'settingsContract': release.SETTINGS_CONTRACT},
                'checks': {'verifier': {'status': 'pass-source-and-binary-checks', 'pendingEvidence': [],
                                        'stackBudgetFailures': []}},
                'image': {'sha256': hashlib.sha256(bytes([fill]) * 4096).hexdigest(), 'dualBankMarginBytes': 0},
                'stableEvidence': {'rings': [{'ring': ring, 'buildID': identity['buildID'], 'settings': 'same',
                                              'bonds': 'kept'} for ring in ('Ring A', 'Ring B')]},
            }).encode()
            promoted = root / 'promote' / str(revision)
            release.promote('sudo', entry['id'], 'stable', zip_path, promoted, 263, True, auto_install=True,
                            customer_version=name, change_note=note, source_versions=['6.0.3.3P21'],
                            qualification=record, notes=f'Ring firmware {name} notes.', signer=sign, keys=keys)
            with mock.patch.object(release, 'anonymous_get', return_value=zip_path.read_bytes()):
                release.publish(promoted)
            release.set_rollout('sudo', entry['id'], percent, '2026-11-02')
        fixture = {'note': __doc__.split('\n\n')[0].replace('\n', ' '),
                   'publicKey': base64.b64encode(public).decode(), 'catalog': catalog.read('sudo')}
    OUT.write_text(json.dumps(fixture, indent=2) + '\n')
    print(f'wrote {OUT}')


if __name__ == '__main__':
    main()
