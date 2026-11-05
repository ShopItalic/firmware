#!/usr/bin/env python3
"""Catalog, signing and staging tests with throwaway keys. No Keychain or network."""
import base64
import contextlib
import copy
import hashlib
import io
import json
import shutil
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import catalog  # noqa: E402
import p256  # noqa: E402
import release  # noqa: E402


class CatalogTest(unittest.TestCase):
    def setUp(self):
        self.private, public = p256.generate()
        self.keys = {'glyph-release-1': public}
        self.tmp = tempfile.TemporaryDirectory(); root = Path(self.tmp.name)
        self.ufw = root / 'glyph-pks3-101-P12-rc.1.ufw'; self.ufw.write_bytes(b'\x5a' * 4096)
        self.notes = root / 'release-notes.md'; self.notes.write_text('notes\n')
        self.stage_dir = root / 'stage'
        self.entry = release.stage('glyph', 'P12-rc.1', 'P12-rc.1', 1, 'test', True, self.ufw, [self.notes],
                                   self.stage_dir, ['P11-rc.1'], {'releaseNotes': 'Wi-Fi updates'},
                                   signer=lambda raw: p256.sign(self.private, raw), keys=self.keys)

    def tearDown(self):
        self.tmp.cleanup()

    def catalog(self, *entries):
        return {**catalog.empty('glyph'), 'releases': list(entries)}

    def test_staged_entry_verifies_and_round_trips(self):
        product, entry, s = release.load_stage(self.stage_dir, self.keys)
        self.assertEqual((product, s['id'], s['sourceVersions'], s['installable']), ('glyph', 'P12-rc.1', ['P11-rc.1'], True))
        self.assertEqual(entry['asset']['url'],
                         'https://github.com/ShopItalic/firmware/releases/download/glyph-P12-rc.1/glyph-pks3-101-P12-rc.1.ufw')
        self.assertEqual(catalog.validate_catalog('glyph', self.catalog(entry), self.keys), 1)

    def test_unsigned_fields_cannot_grant_anything(self):
        for field, value in [('installable', False), ('channel', 'stable'), ('version', 'P13-rc.1')]:
            forged = copy.deepcopy(self.entry); forged[field] = value
            with self.assertRaises(catalog.CatalogError):
                catalog.verify_entry('glyph', forged, self.keys)
        forged = copy.deepcopy(self.entry); forged['asset']['sha256'] = '0' * 64
        with self.assertRaises(catalog.CatalogError):
            catalog.verify_entry('glyph', forged, self.keys)
        forged = copy.deepcopy(self.entry)
        forged['asset']['url'] = 'https://example.com/glyph-pks3-101-P12-rc.1.ufw'
        with self.assertRaises(catalog.CatalogError):
            catalog.verify_entry('glyph', forged, self.keys)

    def test_tampered_statement_or_wrong_key_fails(self):
        s = json.loads(base64.b64decode(self.entry['statement'])); s['installable'] = False
        forged = copy.deepcopy(self.entry); forged['installable'] = False
        forged['statement'] = base64.b64encode(catalog.encode_statement(s)).decode()
        with self.assertRaises(catalog.CatalogError):
            catalog.verify_entry('glyph', forged, self.keys)
        _, other = p256.generate()
        with self.assertRaises(catalog.CatalogError):
            catalog.verify_entry('glyph', self.entry, {'glyph-release-1': other})
        # A Glyph statement is not valid in the Sudo catalog, even with a trusted Sudo key.
        with self.assertRaises(catalog.CatalogError):
            catalog.verify_entry('sudo', self.entry, {'sudo-release-1': self.keys['glyph-release-1']})

    def test_withdrawal_is_allowed_without_resigning(self):
        entry = copy.deepcopy(self.entry); entry['withdrawn'] = True; entry['withdrawnReason'] = 'bad battery'
        self.assertEqual(catalog.validate_catalog('glyph', self.catalog(entry), self.keys), 1)

    def test_duplicate_ids_and_changed_staging_rejected(self):
        with self.assertRaises(catalog.CatalogError):
            catalog.validate_catalog('glyph', self.catalog(self.entry, self.entry), self.keys)
        (self.stage_dir / 'assets' / self.ufw.name).write_bytes(b'\0' * 4096)
        with self.assertRaises(catalog.CatalogError):
            release.load_stage(self.stage_dir, self.keys)

    def test_statement_validation(self):
        good = json.loads(base64.b64decode(self.entry['statement']))
        for field, value in [('schema', 'x'), ('hardware', '603V1.23.2'), ('packageRevision', 0),
                             ('issuedAt', '2026-09-24'), ('sourceVersions', []), ('extra', 1)]:
            bad = {**good, field: value}
            with self.assertRaises(catalog.CatalogError, msg=field):
                catalog.check_statement(bad, 'glyph')

    def test_signer_refuses_reserved_names_and_bad_signature(self):
        reserved = Path(self.tmp.name) / 'statement.json'; reserved.write_text('{}')
        with self.assertRaises(catalog.CatalogError):
            release.stage('glyph', 'P12-rc.2', 'P12-rc.2', 1, 'test', False, self.ufw, [reserved],
                          Path(self.tmp.name) / 's2', signer=lambda raw: p256.sign(self.private, raw), keys=self.keys)
        other, _ = p256.generate()
        with self.assertRaises(catalog.CatalogError):
            release.stage('glyph', 'P12-rc.3', 'P12-rc.3', 1, 'test', False, self.ufw, [],
                          Path(self.tmp.name) / 's3', signer=lambda raw: p256.sign(other, raw), keys=self.keys)


IDENTITY = {'generation': 21, 'revision': 117, 'codec': 1, 'settingsSchema': 6,
            'buildID': '4270004e53ba5b9c1da4e026411d4aa8'}


def qualification(revision, image, change=None):
    """A ShopItalic/sudo qualification record as a stable release needs it
    (option (a)): the verifier's settings contract, the dual-bank record and
    Rings A and B on the build with their settings and bonds intact."""
    build = IDENTITY['buildID']
    record = {
        'release': f'P21 revision {revision}', 'wireVersion': '6.0.3.3P21', 'packageRevision': revision,
        'generation': 21, 'buildID': build,
        'recipe': {'settingsContract': release.SETTINGS_CONTRACT + "; the receipt's source contract passes"},
        'checks': {'verifier': {'status': 'pass-source-and-binary-checks', 'pendingEvidence': [], 'stackBudgetFailures': []}},
        'image': {'sha256': hashlib.sha256(image).hexdigest(), 'dualBankMarginBytes': 57_896},
        'stableEvidence': {'rings': [
            {'ring': 'Ring A (C34A)', 'buildID': build, 'settings': 'same', 'bonds': 'kept'},
            {'ring': 'Ring B (5B31)', 'buildID': build, 'settings': 'same', 'bonds': 'kept'}]},
    }
    if change:
        change(record)
    return json.dumps(record).encode()


def migrated(record, settingsContract='a reviewed migration, not unchanged: app_factory_controls.c', **terms):
    """`record` as a reviewed settings migration's (Ring 119's touch area), with `terms` replacing its own."""
    record['recipe'] = {'settingsContract': settingsContract, 'settingsMigration': {
        'reviewedRevision': record['release'],
        'protectedSources': ['firmware/bc_ros/bc_application/app_factory_controls.c'],
        'fdsRecordsAdded': 0, 'readback': ['touchArea'], **terms}}


def sudo_package(path, image_bytes=2048, parts=None):
    """A Nordic DFU package as Sudo's: one application image and its init packet."""
    path.parent.mkdir(parents=True, exist_ok=True)
    manifest = parts or {'application': {'bin_file': 'app.bin', 'dat_file': 'app.dat'}}
    # Fixed entry times, so building one again gives the same package.
    with zipfile.ZipFile(path, 'w') as archive:
        for name, data in (('manifest.json', json.dumps({'manifest': manifest})), ('app.bin', b'\x11' * image_bytes),
                           ('app.dat', b'\x00' * 141)):
            archive.writestr(zipfile.ZipInfo(name, (2026, 10, 22, 0, 0, 0)), data)
    return path


def varint(number):
    out = b''
    while number > 0x7F:
        out += bytes([number & 0x7F | 0x80]); number >>= 7
    return out + bytes([number])


def length_field(number, data):
    return varint(number << 3 | 2) + varint(len(data)) + data


# An init command (the init packet's signed part) and two 64-byte signatures of it.
COMMAND = b'\x08\x01\x12\x36\x08\x01\x10\x34' + bytes(50)
SUPPLIER = b'\x5a' * 64
ITALIC = b'\xa5' * 64


def init_packet(signature, command=COMMAND):
    """A Nordic init packet (app.dat) as nrfutil writes it: Packet, field 2 its
    SignedCommand {command (1), signature type (2) ECDSA P-256, signature (3)}."""
    return length_field(2, length_field(1, command) + varint(2 << 3) + varint(0) + length_field(3, signature))


def signed_package(path, signature, image=b'\x11' * 2048, command=COMMAND, manifest=None, dat=None):
    """A Sudo package whose init packet is signed for one DFU key (`signature`)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    manifest = manifest or json.dumps({'manifest': {'application': {'bin_file': 'app.bin', 'dat_file': 'app.dat'}}})
    dat = init_packet(signature, command) if dat is None else dat
    with zipfile.ZipFile(path, 'w') as archive:
        for name, data in (('manifest.json', manifest), ('app.bin', image), ('app.dat', dat)):
            archive.writestr(zipfile.ZipInfo(name, (2026, 11, 5, 0, 0, 0)), data)
    return path


class SudoAutomaticTest(unittest.TestCase):
    """Version 2 statements, promotion, rollout, the pause switch and the
    dual-bank check, in a throwaway repository with a throwaway Sudo key."""

    def setUp(self):
        self.private, public = p256.generate()
        self.keys = {'sudo-release-1': public}
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / 'keys').mkdir()
        (self.root / 'keys' / 'sudo-release-1.x963').write_bytes(public)
        (self.root / 'products' / 'sudo').mkdir(parents=True)
        patch = mock.patch.object(catalog, 'ROOT', self.root); patch.start(); self.addCleanup(patch.stop)
        self.sign = lambda raw: p256.sign(self.private, raw)
        self.package = sudo_package(self.root / 'pkg' / 'BCL603S2P_6.0.3.3P21.zip')
        self.entry = self.publish_test_build('6.0.3.3P21-r117', 117, self.package, IDENTITY)

    def publish_test_build(self, release_id, revision, package, identity):
        """What `publish` leaves in the catalog, without GitHub."""
        out = self.root / 'stage' / release_id
        details = {'schemaVersion': 1, 'hardware': '603V1.23.2', 'version': '6.0.3.3P21',
                   'packageRevision': revision, 'buildIdentity': identity, 'status': 'signed-test-ota',
                   'otaAvailable': True, 'notice': f'P21 revision {revision} tester update'}
        entry = release.stage('sudo', release_id, '6.0.3.3P21', revision, 'test', True, package, [], out,
                              details=details, display={'notice': details['notice'], 'releaseNotes': 'tester notes'},
                              signer=self.sign, keys=self.keys)
        current = catalog.read('sudo') if catalog.catalog_path('sudo').exists() else catalog.empty('sudo')
        current['releases'].insert(0, entry)
        catalog.write('sudo', current)
        images = release.load_images('sudo')
        images['packages'][entry['asset']['sha256']] = json.loads((out / 'image.json').read_text())
        release.write_images('sudo', images)
        return entry

    def record(self, release_id='6.0.3.3P21-r117', package=None, change=None):
        """The release's qualification record, for the image in its package."""
        with zipfile.ZipFile(package or self.package) as archive:
            image = archive.read('app.bin')
        return qualification(int(release_id.rsplit('-r', 1)[1]), image, change)

    def promote(self, release_id='6.0.3.3P21-r117', package=None, **options):
        options = {'minimum_app_build': 263, 'erases_storage': True, 'auto_install': True,
                   'customer_version': f"1.0.{release_id.rsplit('-r', 1)[1]}", 'notes': 'The firmware Rings ship with.',
                   'source_versions': ['6.0.3.3P21'], 'qualification': self.record(release_id, package), **options}
        out = self.root / 'promote' / f'{release_id}-{len(list((self.root / "promote").glob("*"))) if (self.root / "promote").exists() else 0}'
        return release.promote('sudo', release_id, 'stable', package or self.package, out, signer=self.sign,
                               keys=self.keys, **options), out

    def test_promotion_signs_version_2_for_the_same_package_and_tag(self):
        entry, out = self.promote(change_note='shorter start and stop buzzes')
        s = catalog.verify_entry('sudo', entry, self.keys)
        self.assertEqual((s['schema'], s['channel'], s['id'], s['packageRevision']),
                         (catalog.SCHEMA_V2, 'stable', '6.0.3.3P21-r117', 117))
        self.assertEqual((s['autoInstall'], s['minimumAppBuild'], s['erasesStorage'], s['applicationOnly']),
                         (True, 263, True, True))
        self.assertEqual((s['buildIdentity'], s['customerVersion'], s['changeNote']),
                         (IDENTITY, '1.0.117', 'shorter start and stop buzzes'))
        self.assertEqual(s['asset'], json.loads(base64.b64decode(self.entry['statement']))['asset'])
        self.assertEqual((entry['tag'], entry['asset']['url']), (self.entry['tag'], self.entry['asset']['url']))
        # Apps read an installable release, not a test build, and customers no tester notice.
        self.assertEqual(entry['details']['status'], 'supplier-signed-ota')
        self.assertNotIn('notice', entry); self.assertNotIn('notice', entry['details'])
        self.assertEqual(entry['releaseNotes'], 'The firmware Rings ship with.')
        self.assertEqual(entry['details']['promotedFrom']['channel'], 'test')
        # Publishing replaces the entry in place once the public package still matches.
        with mock.patch.object(release, 'anonymous_get', return_value=self.package.read_bytes()), \
                mock.patch.object(release, 'commit') as commit:
            release.publish(out)
        current = catalog.read('sudo')
        self.assertEqual([e['channel'] for e in current['releases']], ['stable'])
        self.assertEqual(commit.call_args[0][1], 'Promote sudo 6.0.3.3P21-r117 to stable')

    def test_a_promotion_takes_no_github_title(self):
        _, out = self.promote()
        with mock.patch.object(release, 'anonymous_get') as download, mock.patch.object(release, 'commit') as commit:
            with self.assertRaisesRegex(catalog.CatalogError, 'no GitHub release'):
                release.publish(out, firmware_version='1.0.117')
        download.assert_not_called(); commit.assert_not_called()

    def test_customer_versions_have_three_parts_and_the_app_reads_two(self):
        entry, _ = self.promote()
        good = json.loads(base64.b64decode(entry['statement']))
        for name in ('1.0.117', '1.1.117', '1.117'):  # the app reads each; promote signs only the first two
            with self.subTest(name):
                catalog.check_statement({**good, 'customerVersion': name}, 'sudo')
        for name in ('1.0.117.0', '1.0.', 'v1.0.117', '1.0.1170', ''):
            with self.subTest(name), self.assertRaises(catalog.CatalogError):
                catalog.check_statement({**good, 'customerVersion': name}, 'sudo')

    def test_a_promotion_whose_public_package_changed_is_not_published(self):
        _, out = self.promote()
        with mock.patch.object(release, 'anonymous_get', return_value=b'not the package'), \
                mock.patch.object(release, 'commit') as commit:
            with self.assertRaises(catalog.CatalogError):
                release.publish(out)
        commit.assert_not_called()
        self.assertEqual(catalog.read('sudo')['releases'][0]['channel'], 'test')

    def test_promotion_refuses_what_it_cannot_vouch_for(self):
        other = sudo_package(self.root / 'other' / 'BCL603S2P_6.0.3.3P21.zip', image_bytes=4096)
        stable = dict(source_versions=['6.0.3.3P21'], qualification=self.record())
        cases = {
            'another package': dict(package=other, **stable),
            'automatic beta': dict(channel='beta'),
            'beta source versions without evidence': dict(channel='beta', auto=False, source_versions=['6.0.3.3P21']),
            'beta evidence without source versions': dict(channel='beta', auto=False,
                                                          settings_compatibility={'sourceVersions': ['6.0.3.3P21']}),
            'beta evidence for another package': dict(channel='beta', auto=False, source_versions=['6.0.3.3P21'],
                                                      settings_compatibility={'sourceVersions': ['6.0.3.3P21'],
                                                                              'packageSHA256': '0' * 64}),
            'a qualification record for beta': dict(channel='beta', auto=False, **stable),
            'a long change note': dict(change_note='x' * 61, **stable),
            'a two-line change note': dict(change_note='shorter\nbuzzes', **stable),
            'a bad customer version': dict(customer_version='v1.1', **stable),
            # People see "Sudo 1.0.117", as GitHub's title names it: three parts, the revision last.
            'a two-part customer version': dict(customer_version='1.117', **stable),
            'a customer version for another revision': dict(customer_version='1.0.118', **stable),
            'no app build': dict(minimum_app_build=0, **stable),
        }
        for name, options in cases.items():
            channel = options.pop('channel', 'stable')
            package = options.pop('package', self.package)
            build = options.pop('minimum_app_build', 263)
            auto = options.pop('auto', True)
            with self.subTest(name), self.assertRaises(catalog.CatalogError):
                release.promote('sudo', '6.0.3.3P21-r117', channel, package, self.root / 'x' / name.replace(' ', '-'),
                                build, True, auto_install=auto, signer=self.sign, keys=self.keys, **options)

    def test_a_stable_release_publishes_its_qualification_records_evidence(self):
        record = self.record()
        entry, _ = self.promote(qualification=record)
        self.assertEqual(entry['details']['settingsCompatibility'], {
            'contract': 'factory-settings-v1', 'packageSHA256': self.entry['asset']['sha256'],
            'evidenceSHA256': hashlib.sha256(record).hexdigest(), 'sourceVersions': ['6.0.3.3P21'],
            'preservesAllSettings': True})
        self.assertEqual(catalog.verify_entry('sudo', entry, self.keys)['sourceVersions'], ['6.0.3.3P21'])

    def test_a_reviewed_settings_migration_is_stable_evidence(self):
        """Jeremy, October 22, for Ring 119's touch area: a reviewed change to
        a protected source that adds no FDS record, with the app's readback
        comparing what it changes, counts as option (a)'s settings contract."""
        record = self.record(change=migrated)
        entry, _ = self.promote(qualification=record)
        self.assertEqual(entry['details']['settingsCompatibility']['evidenceSHA256'], hashlib.sha256(record).hexdigest())
        self.assertTrue(entry['details']['settingsCompatibility']['preservesAllSettings'])

    def test_a_stable_release_needs_option_a_evidence(self):
        """Jeremy, October 22: the verifier's settings contract, the dual-bank
        record and Rings A and B on the build with settings and bonds intact.
        A hand-written settingsCompatibility never stands in for it."""
        def change(edit):
            return dict(qualification=self.record(change=edit))
        rings = lambda q: q['stableEvidence']['rings']  # noqa: E731
        cases = {
            'no record': dict(qualification=None),
            'not JSON': dict(qualification=b'{'),
            'hand-written evidence': dict(settings_compatibility={
                'contract': 'factory-settings-v1', 'packageSHA256': self.entry['asset']['sha256'], 'evidenceSHA256': '0' * 64,
                'sourceVersions': ['6.0.3.3P21'], 'preservesAllSettings': True}),
            'no source versions': dict(source_versions=None),
            'another revision': change(lambda q: q.update(packageRevision=118)),
            'another build': change(lambda q: q.update(buildID='0' * 32)),
            'another image': change(lambda q: q['image'].update(sha256='0' * 64)),
            'a P20 record': change(lambda q: q.update(generation=20)),
            'a protected source edited': change(lambda q: q['recipe'].update(settingsContract='edited: bc_device_info.c')),
            'a migration without its terms': change(lambda q: q['recipe'].update(settingsContract='a reviewed migration')),
            'a migration reviewed for another release': change(lambda q: migrated(q, reviewedRevision='P21 revision 118')),
            'a migration adding a record': change(lambda q: migrated(q, fdsRecordsAdded=1)),
            'a migration naming no source': change(lambda q: migrated(q, protectedSources=[])),
            'a migration the readback never checks': change(lambda q: migrated(q, readback=[])),
            'migration terms under the unchanged form only': change(
                lambda q: migrated(q, settingsContract='edited: app_factory_controls.c')),
            'the verifier failing': change(lambda q: q['checks']['verifier'].update(status='fail')),
            'evidence pending': change(lambda q: q['checks']['verifier'].update(pendingEvidence=['codec probe'])),
            'no dual-bank record': change(lambda q: q['image'].pop('dualBankMarginBytes')),
            'one Ring': change(lambda q: rings(q).pop()),
            'one Ring twice': change(lambda q: rings(q)[1].update(ring=rings(q)[0]['ring'])),
            'a Ring on another build': change(lambda q: rings(q)[0].update(buildID='0' * 32)),
            'changed settings': change(lambda q: rings(q)[1].update(settings='changed')),
            'a lost bond': change(lambda q: rings(q)[0].update(bonds='lost')),
        }
        for name, options in cases.items():
            with self.subTest(name), self.assertRaises(catalog.CatalogError):
                self.promote(**options)

    def test_a_package_that_replaces_the_bootloader_never_installs_itself(self):
        parts = {'application': {'bin_file': 'app.bin', 'dat_file': 'app.dat'},
                 'bootloader': {'bin_file': 'app.bin', 'dat_file': 'app.dat'}}
        package = sudo_package(self.root / 'boot' / 'BCL603S2P_6.0.3.3P21.zip', parts=parts)
        with self.assertRaises(catalog.CatalogError):  # not even stageable: the record needs one image
            self.publish_test_build('6.0.3.3P21-r118', 118, package, {**IDENTITY, 'revision': 118})

    def test_version_2_is_sudos_only_and_its_fields_are_exact(self):
        entry, _ = self.promote()
        good = json.loads(base64.b64decode(entry['statement']))
        with self.assertRaises(catalog.CatalogError):
            catalog.check_statement({**good, 'product': 'glyph', 'hardware': 'PKS3-101'}, 'glyph')
        for field, value in [('autoInstall', 1), ('minimumAppBuild', 1_000_000), ('erasesStorage', None),
                             ('buildIdentity', {**IDENTITY, 'revision': 116}),
                             ('buildIdentity', {**IDENTITY, 'generation': 20}),
                             ('buildIdentity', {**IDENTITY, 'buildID': 'XYZ'}), ('minimumSourceRevision', 0),
                             ('unknown', True)]:
            with self.subTest(field), self.assertRaises(catalog.CatalogError):
                catalog.check_statement({**good, field: value}, 'sudo')
        for missing in catalog.V2_REQUIRED:
            with self.subTest(missing), self.assertRaises(catalog.CatalogError):
                catalog.check_statement({k: v for k, v in good.items() if k != missing}, 'sudo')
        # Automatic installs are for installable stable releases only; test builds have no customer name.
        for change in [{'channel': 'test'}, {'channel': 'beta'}, {'installable': False}, {'applicationOnly': False}]:
            with self.subTest(change), self.assertRaises(catalog.CatalogError):
                catalog.check_statement({**good, **change}, 'sudo')
        with self.assertRaises(catalog.CatalogError):  # a customer name on a test build
            catalog.check_statement({**good, 'autoInstall': False, 'channel': 'test'}, 'sudo')
        manual_test = {k: v for k, v in good.items() if k != 'customerVersion'}
        catalog.check_statement({**manual_test, 'autoInstall': False, 'channel': 'test'}, 'sudo')

    def test_unsigned_rollout_and_pause_can_only_narrow(self):
        with self.assertRaises(catalog.CatalogError):  # no signed autoInstall: a rollout would grant nothing
            release.set_rollout('sudo', '6.0.3.3P21-r117', 10)
        entry, out = self.promote()
        with mock.patch.object(release, 'anonymous_get', return_value=self.package.read_bytes()), \
                mock.patch.object(release, 'commit'):
            release.publish(out)
        release.set_rollout('sudo', '6.0.3.3P21-r117', 10, '2026-11-02')
        self.assertEqual(catalog.read('sudo')['releases'][0]['rollout'], {'percent': 10, 'since': '2026-11-02'})
        for percent in (-1, 101):
            with self.subTest(percent), self.assertRaises(catalog.CatalogError):
                release.set_rollout('sudo', '6.0.3.3P21-r117', percent)
        release.set_pause('sudo', 'background')
        current = catalog.read('sudo')
        self.assertEqual(list(current), ['schemaVersion', 'product', 'hardware', 'automaticUpdatesPaused', 'releases'])
        self.assertEqual(current['automaticUpdatesPaused'], 'background')
        release.set_pause('sudo', 'all'); self.assertEqual(catalog.read('sudo')['automaticUpdatesPaused'], 'all')
        release.set_pause('sudo', None); self.assertNotIn('automaticUpdatesPaused', catalog.read('sudo'))
        with self.assertRaises(catalog.CatalogError):
            release.set_pause('sudo', 'some')
        # A forged details build identity can't stand beside the signed one.
        forged = copy.deepcopy(catalog.read('sudo')['releases'][0])
        forged['details']['buildIdentity'] = {**IDENTITY, 'buildID': '0' * 32}
        with self.assertRaises(catalog.CatalogError):
            catalog.verify_entry('sudo', forged, self.keys)

    def test_publishing_a_promotion_keeps_the_rollout_the_catalog_has_now(self):
        """The rollout is the catalog's live control, not part of a promotion:
        one lowered after a promotion was staged stays lowered when it is published."""
        def publish(out):
            with mock.patch.object(release, 'anonymous_get', return_value=self.package.read_bytes()), \
                    mock.patch.object(release, 'commit'):
                release.publish(out)
        _, out = self.promote()
        publish(out)
        release.set_rollout('sudo', '6.0.3.3P21-r117', 100, '2026-11-02')
        _, again = self.promote(notes='Notes, signed again.')    # staged at 100%
        release.set_rollout('sudo', '6.0.3.3P21-r117', 0, '2026-11-03')  # stopped since
        publish(again)
        entry = catalog.read('sudo')['releases'][0]
        self.assertEqual((entry['releaseNotes'], entry['rollout']), ('Notes, signed again.', {'percent': 0, 'since': '2026-11-03'}))
        # Signed again without autoInstall, the release has nothing left to roll out.
        _, manual = self.promote(auto_install=False)
        publish(manual)
        self.assertNotIn('rollout', catalog.read('sudo')['releases'][0])

    def test_withdrawal_keeps_the_catalog_valid(self):
        release.withdraw('sudo', '6.0.3.3P21-r117', 'charger regression')
        entry = catalog.read('sudo')['releases'][0]
        self.assertEqual((entry['withdrawn'], entry['withdrawnReason']), (True, 'charger regression'))
        with self.assertRaises(catalog.CatalogError):
            self.promote()

    def test_dual_bank_refuses_a_package_that_cannot_stage_beside_every_image(self):
        limit = 0xE0000 - 0x27000
        # 376,832 bytes is the largest image that fits beside itself.
        self.publish_test_build('6.0.3.3P21-r118', 118,
                                sudo_package(self.root / 'big' / 'BCL603S2P_6.0.3.3P21.zip', image_bytes=376_832),
                                {**IDENTITY, 'revision': 118})
        with self.assertRaisesRegex(catalog.CatalogError, 'dual-bank'):
            self.publish_test_build('6.0.3.3P21-r119', 119,
                                    sudo_package(self.root / 'over' / 'BCL603S2P_6.0.3.3P21.zip', image_bytes=376_833),
                                    {**IDENTITY, 'revision': 119})
        # A Ring may still run a withdrawn or retired image: its record counts.
        images = release.load_images('sudo')
        images['packages']['f' * 64] = {'release': 'v6.0.3.3P20', 'version': '6.0.3.3P20', 'packageRevision': 1,
                                        'packageBytes': 1, 'image': 'app.bin', 'imageBytes': limit - 4096 + 1,
                                        'imageSha256': '0' * 64}
        release.write_images('sudo', images)
        with self.assertRaisesRegex(catalog.CatalogError, 'dual-bank'):
            self.promote('6.0.3.3P21-r118', sudo_package(self.root / 'big' / 'BCL603S2P_6.0.3.3P21.zip', 376_832))
        # A catalog package without a record leaves the check blind, so it refuses.
        release.write_images('sudo', {'schema': 1, 'note': '', 'packages': {}})
        with self.assertRaisesRegex(catalog.CatalogError, 'no recorded image'):
            self.promote()
        # Every stable release is checked, a manual one too; a manual beta isn't.
        with self.assertRaisesRegex(catalog.CatalogError, 'no recorded image'):
            self.promote(auto_install=False)
        entry = release.promote('sudo', '6.0.3.3P21-r117', 'beta', self.package, self.root / 'beta', 263, True,
                                signer=self.sign, keys=self.keys)
        self.assertFalse(json.loads(base64.b64decode(entry['statement']))['autoInstall'])

    def test_record_images_checks_each_package_against_its_statement(self):
        release.write_images('sudo', {'schema': 1, 'note': '', 'packages': {}})
        with mock.patch.object(release, 'anonymous_get', return_value=self.package.read_bytes()):
            release.record_images('sudo', download=True)
        row = release.load_images('sudo')['packages'][self.entry['asset']['sha256']]
        self.assertEqual((row['release'], row['imageBytes']), ('sudo-6.0.3.3P21-r117', 2048))
        release.write_images('sudo', {'schema': 1, 'note': '', 'packages': {}})
        with mock.patch.object(release, 'anonymous_get', return_value=b'PK not it'), \
                self.assertRaises(catalog.CatalogError):
            release.record_images('sudo', download=True)


class DfuPackageTest(unittest.TestCase):
    """A Sudo release's second package: the same application signed for
    italic-dfu-1, which production Rings trust, in `dfuPackages` with its own
    package statement (ShopItalic/app and ShopItalic/sudo read the same format)."""

    def setUp(self):
        self.private, public = p256.generate()
        self.keys = {'sudo-release-1': public}
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / 'keys').mkdir()
        (self.root / 'keys' / 'sudo-release-1.x963').write_bytes(public)
        (self.root / 'products' / 'sudo').mkdir(parents=True)
        patch = mock.patch.object(catalog, 'ROOT', self.root); patch.start(); self.addCleanup(patch.stop)
        self.signed = []
        self.sign = lambda raw: self.signed.append(raw) or p256.sign(self.private, raw)
        self.main = signed_package(self.root / 'pkg' / 'BCL603S2P_6.0.3.3P21.zip', SUPPLIER)
        self.italic = signed_package(self.root / 'pkg' / 'BCL603S2P_6.0.3.3P21-italic-dfu-1.zip', ITALIC)

    def stage(self, release_id='6.0.3.3P21-r139', main=None, packages=None, product='sudo', keys=None):
        revision = int(release_id.rsplit('-r', 1)[1])
        out = self.root / 'stage' / f'{release_id}-{len(list((self.root / "stage").glob("*"))) if (self.root / "stage").exists() else 0}'
        details = {'schemaVersion': 1, 'hardware': '603V1.23.2', 'version': '6.0.3.3P21', 'packageRevision': revision,
                   'buildIdentity': {**IDENTITY, 'revision': revision}, 'status': 'signed-test-ota'}
        with contextlib.redirect_stdout(io.StringIO()):
            entry = release.stage(product, release_id, '6.0.3.3P21', revision, 'test', True, main or self.main, [], out,
                                  details=details, signer=self.sign, keys=keys or self.keys,
                                  dfu_packages={'italic-dfu-1': self.italic} if packages is None else packages)
        return entry, out

    def test_from_revision_139_an_installable_release_carries_the_twin(self):
        """Factory-run Rings trust only italic-dfu-1 and are offered no supplier-only release: from P21 revision 139
        an installable Sudo release can't be staged or verified without its twin. Earlier ones stay as published."""
        with self.assertRaisesRegex(catalog.CatalogError, 'from P21 revision 139 an installable release carries the italic-dfu-1'):
            self.stage('6.0.3.3P21-r139', packages={})
        self.assertEqual(self.signed, [], 'refused before anything is signed')
        entry, _ = self.stage('6.0.3.3P21-r138', packages={})
        self.assertNotIn('dfuPackages', entry)
        s = {'version': '6.0.3.3P21', 'packageRevision': 139, 'installable': True}
        self.assertEqual(catalog.required_dfu_keys('sudo', s), ('italic-dfu-1',))
        self.assertEqual(catalog.required_dfu_keys('sudo', {**s, 'installable': False}), (), 'a download only')
        self.assertEqual(catalog.required_dfu_keys('sudo', {**s, 'packageRevision': 138}), ())
        self.assertEqual(catalog.required_dfu_keys('sudo', {**s, 'version': '6.0.3.3P22', 'packageRevision': 1}),
                         ('italic-dfu-1',), 'a later generation too')
        self.assertEqual(catalog.required_dfu_keys('sudo', {**s, 'version': '6.0.3.3Z62', 'packageRevision': 1}), ())
        self.assertEqual(catalog.required_dfu_keys('glyph', {**s, 'version': 'P21-rc.1'}), ())

    def publish(self, release_id='6.0.3.3P21-r139'):
        """What `publish` leaves in the catalog, without GitHub: the entry with
        both asset API URLs, and the main package's image record."""
        entry, out = self.stage(release_id)
        entry['asset']['apiURL'] = catalog.ASSET_API + '700000001'
        entry['dfuPackages'][0]['asset']['apiURL'] = catalog.ASSET_API + '700000002'
        current = catalog.read('sudo') if catalog.catalog_path('sudo').exists() else catalog.empty('sudo')
        current['releases'].insert(0, entry)
        catalog.write('sudo', current)
        images = release.load_images('sudo')
        images['packages'][entry['asset']['sha256']] = json.loads((out / 'image.json').read_text())
        release.write_images('sudo', images)
        return entry

    def sign_package(self, entry, **changes):
        """`entry`'s package object with its statement changed and signed again with the release key."""
        package = copy.deepcopy(entry['dfuPackages'][0])
        p = json.loads(base64.b64decode(package['statement']))
        for field, value in changes.items():
            p[field] = value
        raw = catalog.encode_statement(p)
        package['statement'] = base64.b64encode(raw).decode()
        package['signature']['der'] = base64.b64encode(p256.sign(self.private, raw)).decode()
        package['asset'].update(p['asset'])
        package['asset']['url'] = catalog.DOWNLOAD + entry['tag'] + '/' + p['asset']['name']
        return package

    def test_the_init_command_reader_reads_nrfutils_layout(self):
        # app.dat of the published sudo-6.0.3.3P21-r138 package: its SignedCommand is 128 bytes long.
        dat = bytes.fromhex(
            '1280010a3a08011236080110341a028002200038c0e6104224080312208a3ed62e9d4565e98ce345e6fd31ea632afdac029e'
            '94a45fa5af9478ee2ef261480010001a406270a4c32d538d58bea23fdd56c69dcf17fa861665f2ca2ea5c5d886c2c463126c'
            '45a0e36403f7d8d087704c63ba31de64d602e44aa84d4a3c5d7779be67f361')
        command = release.init_command(dat)
        self.assertEqual((len(command), command[:4]), (58, b'\x08\x01\x12\x36'))
        self.assertEqual(release.init_command(init_packet(ITALIC)), COMMAND)
        for bad in (b'', bytes(141), b'init', b'\x0a\x02\x08\x01', b'\x12\x05abc', b'\x13', b'\x12\x02\x10\x00',
                    init_packet(ITALIC) * 2):
            with self.subTest(bad), self.assertRaises(catalog.CatalogError):
                release.init_command(bad)

    def test_a_package_for_italic_dfu_1_is_staged_and_verifies(self):
        entry, out = self.stage()
        image = json.loads((out / 'image.json').read_text())
        p = catalog.dfu_package_statements('sudo', entry, self.keys)['italic-dfu-1']
        self.assertEqual({k: v for k, v in p.items() if k != 'issuedAt'}, {
            'schema': 'italic-firmware-package/1', 'product': 'sudo', 'hardware': '603V1.23.2',
            'id': '6.0.3.3P21-r139', 'dfuKey': 'italic-dfu-1', 'asset': release.record(self.italic),
            'imageSha256': hashlib.sha256(b'\x11' * 2048).hexdigest()})
        self.assertEqual(p['imageSha256'], image['imageSha256'])  # the main package's record covers it
        package = entry['dfuPackages'][0]
        self.assertEqual(list(package), ['dfuKey', 'asset', 'statement', 'signature'])
        self.assertEqual(package['asset'], {
            **release.record(self.italic), 'md5': hashlib.md5(self.italic.read_bytes()).hexdigest(),
            'url': 'https://github.com/ShopItalic/firmware/releases/download/sudo-6.0.3.3P21-r139/'
                   'BCL603S2P_6.0.3.3P21-italic-dfu-1.zip'})
        self.assertEqual(package['signature']['keyId'], 'sudo-release-1')
        self.assertEqual(base64.b64decode(package['statement']), (out / 'statement-italic-dfu-1.json').read_bytes())
        self.assertEqual(base64.b64decode(package['statement']), catalog.encode_statement(p))
        # The release statement and its asset are the supplier package's, as before.
        s = catalog.verify_entry('sudo', entry, self.keys)
        self.assertEqual((s['schema'], s['asset']), (catalog.SCHEMA, release.record(self.main)))
        self.assertEqual(release.load_stage(out, self.keys)[2], s)
        self.assertIn('BCL603S2P_6.0.3.3P21-italic-dfu-1.zip', (out / 'SHA256SUMS').read_text())
        self.assertEqual(catalog.validate_catalog('sudo', {**catalog.empty('sudo'), 'releases': [entry]}, self.keys), 1)

    def test_staging_refuses_a_package_that_is_not_the_same_application(self):
        named = lambda folder: self.root / folder / self.italic.name  # noqa: E731
        boot = {'manifest': {'application': {'bin_file': 'app.bin', 'dat_file': 'app.dat'},
                             'bootloader': {'bin_file': 'app.bin', 'dat_file': 'app.dat'}}}
        cases = {
            'another image': signed_package(named('image'), ITALIC, image=b'\x22' * 2048),
            'another manifest': signed_package(named('manifest'), ITALIC, manifest=json.dumps(
                {'manifest': {'application': {'dat_file': 'app.dat', 'bin_file': 'app.bin'}}})),
            'another init command': signed_package(named('command'), ITALIC, command=COMMAND[:-1] + b'\x01'),
            'not only the application': signed_package(named('boot'), ITALIC, manifest=json.dumps(boot)),
            'the main package itself': signed_package(named('same'), SUPPLIER),
            'an unreadable init packet': signed_package(named('dat'), ITALIC, dat=bytes(141)),
            'no init packet': signed_package(named('nodat'), ITALIC, manifest=json.dumps(
                {'manifest': {'application': {'bin_file': 'app.bin', 'dat_file': 'missing.dat'}}})),
        }
        for name, path in cases.items():
            with self.subTest(name), self.assertRaises(catalog.CatalogError):
                self.stage(packages={'italic-dfu-1': path})
        self.assertEqual(self.signed, [], 'nothing is signed for a package that is not the same application')
        renamed = self.root / 'renamed' / 'BCL603S2P_6.0.3.3P21-italic.zip'; renamed.parent.mkdir()
        shutil.copyfile(self.italic, renamed)
        with self.assertRaisesRegex(catalog.CatalogError, 'must be named BCL603S2P_6.0.3.3P21-italic-dfu-1.zip'):
            self.stage(packages={'italic-dfu-1': renamed})
        other = self.root / 'other' / 'BCL603S2P_6.0.3.3P21-italic-dfu-2.zip'; other.parent.mkdir()
        shutil.copyfile(self.italic, other)
        with self.assertRaisesRegex(catalog.CatalogError, 'unknown DFU key'):
            self.stage(packages={'italic-dfu-2': other})
        ufw = self.root / 'glyph-pks3-101-P12-rc.9.ufw'; ufw.write_bytes(b'\x5a' * 4096)
        _, glyph = p256.generate()
        with self.assertRaisesRegex(catalog.CatalogError, 'glyph releases carry no packages'):
            release.stage('glyph', 'P12-rc.9', 'P12-rc.9', 1, 'test', True, ufw, [], self.root / 'glyph',
                          signer=self.sign, keys={'glyph-release-1': glyph}, dfu_packages={'italic-dfu-1': self.italic})
        self.assertFalse((self.root / 'glyph').exists())
        self.assertEqual(self.signed, [])

    def test_the_catalog_refuses_a_forged_or_moved_package(self):
        entry, _ = self.stage()
        other, _ = self.stage('6.0.3.3P21-r140')
        good = entry['dfuPackages'][0]
        s = json.loads(base64.b64decode(entry['statement']))
        p = json.loads(base64.b64decode(good['statement']))

        def changed(**fields):
            package = copy.deepcopy(good)
            for path, value in fields.items():
                target = package
                *parents, last = path.split('__')
                for part in parents:
                    target = target[part]
                if value is None:
                    target.pop(last)
                else:
                    target[last] = value
            return package
        tampered = base64.b64encode(catalog.encode_statement({**p, 'imageSha256': '0' * 64})).decode()
        cases = {
            'a tampered statement': [changed(statement=tampered)],
            'a statement moved from another release': other['dfuPackages'],
            'a statement moved, its URL fixed': [{**copy.deepcopy(other['dfuPackages'][0]),
                                                 'asset': copy.deepcopy(good['asset'])}],
            'a statement for another release, signed': [self.sign_package(entry, id='6.0.3.3P21-r140')],
            'another URL': [changed(asset__url='https://example.com/' + good['asset']['name'])],
            'another tag in the URL': [changed(asset__url=good['asset']['url'].replace('r139', 'r140'))],
            'another name': [changed(asset__name='BCL603S2P_6.0.3.3P21-italic.zip')],
            'another size': [changed(asset__bytes=good['asset']['bytes'] + 1)],
            'another SHA-256': [changed(asset__sha256='0' * 64)],
            'a noncanonical name, signed': [self.sign_package(entry, asset={**p['asset'], 'name': 'italic-dfu-1.zip'})],
            "the main package's SHA-256, signed": [self.sign_package(entry, asset={**p['asset'], 'sha256': s['asset']['sha256']})],
            'an unknown key, signed': [self.sign_package(entry, dfuKey='italic-dfu-2')],
            'an unknown object key': [changed(dfuKey='supplier')],
            'the same key twice': [good, good],
            'an extra object key': [{**good, 'notes': 'x'}],
            'no signature': [changed(signature=None)],
            'an extra asset field': [changed(asset__size=1)],
            'no URL': [changed(asset__url=None)],
            'a bad md5': [changed(asset__md5='x')],
            'a bad apiURL': [changed(asset__apiURL='https://example.com/1')],
            'another signing key': [changed(signature__keyId='glyph-release-1')],
            'another algorithm': [changed(signature__alg='ES384')],
            'an extra statement field, signed': [self.sign_package(entry, channel='stable')],
            'the release statement in its place': [changed(statement=entry['statement'], signature=entry['signature'])],
            'an empty list': [],
        }
        for name, packages in cases.items():
            forged = {**copy.deepcopy(entry), 'dfuPackages': packages}
            with self.subTest(name), self.assertRaises(catalog.CatalogError):
                catalog.verify_entry('sudo', forged, self.keys)
        for name, value in (('not a list', good), ('null', None)):
            with self.subTest(name), self.assertRaises(catalog.CatalogError):
                catalog.verify_entry('sudo', {**entry, 'dfuPackages': value}, self.keys)
        with self.subTest('also an extra asset'), self.assertRaises(catalog.CatalogError):
            catalog.verify_entry('sudo', {**entry, 'extraAssets': [good['asset']['name']]}, self.keys)
        with self.subTest('a package statement as the release statement'), self.assertRaises(catalog.CatalogError):
            catalog.verify_entry('sudo', {**entry, 'statement': good['statement'], 'signature': good['signature']}, self.keys)
        # The object names one key and its statement another.
        with mock.patch.dict(catalog.PRODUCTS['sudo'], {'dfuKeys': ('italic-dfu-1', 'italic-dfu-2')}), \
                self.assertRaisesRegex(catalog.CatalogError, 'statement is for italic-dfu-1'):
            catalog.verify_entry('sudo', {**entry, 'dfuPackages': [changed(dfuKey='italic-dfu-2')]}, self.keys)
        # A Glyph entry carries none.
        ufw = self.root / 'glyph-pks3-101-P12-rc.9.ufw'; ufw.write_bytes(b'\x5a' * 4096)
        glyph_private, glyph_public = p256.generate()
        glyph_entry = release.stage('glyph', 'P12-rc.9', 'P12-rc.9', 1, 'test', True, ufw, [], self.root / 'glyph',
                                    signer=lambda raw: p256.sign(glyph_private, raw), keys={'glyph-release-1': glyph_public})
        with self.assertRaisesRegex(catalog.CatalogError, 'glyph releases carry no dfuPackages'):
            catalog.verify_entry('glyph', {**glyph_entry, 'dfuPackages': [good]}, {'glyph-release-1': glyph_public})
        # What still verifies: the object as staged, withdrawn, and with an asset API URL.
        withdrawn = {**copy.deepcopy(entry), 'withdrawn': True}
        withdrawn['dfuPackages'][0]['asset']['apiURL'] = catalog.ASSET_API + '700000002'
        self.assertEqual(catalog.dfu_package_statements('sudo', withdrawn, self.keys), {'italic-dfu-1': p})

    def test_load_stage_notices_a_changed_staged_package(self):
        def staged(change):
            _, out = self.stage()
            change(out)
            return out
        def edit_entry(out, change):
            data = json.loads((out / 'entry.json').read_text()); change(data['entry'])
            (out / 'entry.json').write_text(json.dumps(data))
        name = self.italic.name
        cases = {
            'staged italic-dfu-1 package changed': lambda out: (out / 'assets' / name).write_bytes(b'PK changed'),
            'staged asset set changed': lambda out: (out / 'assets' / name).unlink(),
            'staged italic-dfu-1 md5 mismatch': lambda out: edit_entry(
                out, lambda e: e['dfuPackages'][0]['asset'].update(md5='0' * 32)),
            'italic-dfu-1 package statement file differs': lambda out: (out / 'statement-italic-dfu-1.json').write_bytes(b'{}'),
        }
        for message, change in cases.items():
            out = staged(change)
            with self.subTest(message), self.assertRaisesRegex(catalog.CatalogError, message):
                release.load_stage(out, self.keys)
        # An r139 entry that lost its dfuPackages is refused: from 139 it must carry one.
        out = staged(lambda out: edit_entry(out, lambda e: e.pop('dfuPackages')))
        with self.assertRaisesRegex(catalog.CatalogError, 'from P21 revision 139 an installable release carries the italic-dfu-1'):
            release.load_stage(out, self.keys)

    def promote(self, out_name, **options):
        with zipfile.ZipFile(self.main) as archive:
            record = qualification(139, archive.read('app.bin'))
        options = {'auto_install': True, 'customer_version': '1.0.139', 'notes': 'The firmware Rings ship with.',
                   'source_versions': ['6.0.3.3P21'], 'qualification': record, **options}
        out = self.root / 'promote' / out_name
        with contextlib.redirect_stdout(io.StringIO()):
            entry = release.promote('sudo', '6.0.3.3P21-r139', 'stable', self.main, out, 263, True, signer=self.sign,
                                    keys=self.keys, **options)
        return entry, out

    def downloads(self, published, italic=None):
        """anonymous_get for the published entry's URLs, each package at its own."""
        packages = {published['asset']['url']: self.main, published['asset']['apiURL']: self.main,
                    published['dfuPackages'][0]['asset']['url']: italic or self.italic,
                    published['dfuPackages'][0]['asset']['apiURL']: italic or self.italic}
        return lambda url, accept=None: packages[url].read_bytes()

    def test_a_promotion_keeps_dfu_packages_and_publishing_refuses_a_changed_one(self):
        published = self.publish()
        entry, out = self.promote('stable')
        self.assertEqual(entry['dfuPackages'], published['dfuPackages'])
        self.assertEqual(catalog.dfu_package_statements('sudo', entry, self.keys),
                         catalog.dfu_package_statements('sudo', published, self.keys))
        self.assertEqual(json.loads(base64.b64decode(entry['statement']))['schema'], catalog.SCHEMA_V2)
        # A changed dfuPackages, or a public package that is no longer the signed one, is not published.
        for name, change, refusal in (
                ('dropped', lambda e: e.pop('dfuPackages'), 'from P21 revision 139 an installable release carries'),
                ('another apiURL', lambda e: e['dfuPackages'][0]['asset'].update(apiURL=catalog.ASSET_API + '700000003'),
                 "dfuPackages differ from the published entry's")):
            _, changed = self.promote(name)
            data = json.loads((changed / 'entry.json').read_text()); change(data['entry'])
            (changed / 'entry.json').write_text(json.dumps(data))
            with self.subTest(name), mock.patch.object(release, 'anonymous_get', side_effect=self.downloads(published)), \
                    mock.patch.object(release, 'commit') as commit, \
                    self.assertRaisesRegex(catalog.CatalogError, refusal):
                release.publish(changed)
            commit.assert_not_called()
        with mock.patch.object(release, 'anonymous_get', side_effect=self.downloads(published, italic=self.main)), \
                mock.patch.object(release, 'commit') as commit, \
                self.assertRaisesRegex(catalog.CatalogError, 'public download mismatch: .*italic-dfu-1'):
            release.publish(out)
        commit.assert_not_called()
        self.assertEqual(catalog.read('sudo')['releases'][0]['channel'], 'test')
        with mock.patch.object(release, 'anonymous_get', side_effect=self.downloads(published)) as download, \
                mock.patch.object(release, 'commit'), contextlib.redirect_stdout(io.StringIO()):
            release.publish(out)
        self.assertEqual(download.call_count, 4)
        promoted = catalog.read('sudo')['releases'][0]
        self.assertEqual((promoted['channel'], promoted['dfuPackages']), ('stable', published['dfuPackages']))


class AppFixtureTest(unittest.TestCase):
    """tests/fixtures/sudo-stable-v2.json was made by these tools with a
    throwaway key. The app's RingFirmwareReleaseTests decode the same bytes, so
    a change here that the app can't read fails in both repositories."""

    def test_the_apps_fixture_verifies(self):
        fixture = json.loads((Path(__file__).parent / 'fixtures' / 'sudo-stable-v2.json').read_text())
        keys = {'sudo-release-1': base64.b64decode(fixture['publicKey'])}
        self.assertEqual(catalog.validate_catalog('sudo', fixture['catalog'], keys), 2)
        statements = [json.loads(base64.b64decode(e['statement'])) for e in fixture['catalog']['releases']]
        self.assertEqual([(s['customerVersion'], s['autoInstall']) for s in statements], [('1.121', True), ('1.120', True)])


class P256Test(unittest.TestCase):
    def test_rejects_malformed_inputs(self):
        d, q = p256.generate(); sig = p256.sign(d, b'm')
        self.assertTrue(p256.verify(q, b'm', sig))
        self.assertFalse(p256.verify(q, b'm', sig + b'\0'))
        self.assertFalse(p256.verify(q[:-1] + bytes([q[-1] ^ 1]), b'm', sig))
        self.assertFalse(p256.verify(q, b'm', p256.encode_der(0, 1)))
        self.assertFalse(p256.verify(q, b'm', p256.encode_der(1, p256.N)))


class RepositoryTest(unittest.TestCase):
    def test_committed_keys_and_catalogs_verify(self):
        keys = catalog.load_keys()
        self.assertEqual(set(keys), {'glyph-release-1', 'sudo-release-1'})
        for product in catalog.PRODUCTS:
            path = catalog.catalog_path(product)
            if path.exists():
                catalog.validate_catalog(product, json.loads(path.read_text()), keys)

    def test_every_sudo_package_has_its_image_recorded(self):
        """promote's dual-bank check refuses while a catalog package has no record,
        so a publication that skipped record-images shows here, not at a stable release."""
        images = release.load_images('sudo')['packages']
        for entry in catalog.read('sudo')['releases']:
            s = json.loads(base64.b64decode(entry['statement']))
            with self.subTest(s['id']):
                row = images.get(s['asset']['sha256'])
                self.assertIsNotNone(row, 'no recorded image; run record-images')
                self.assertEqual(row['packageBytes'], s['asset']['bytes'])  # older rows keep sudo's own tags

    def test_every_dfu_package_carries_its_main_packages_image(self):
        """A package for another DFU key has no image record of its own: its
        signed imageSha256 must be the one recorded for the main package."""
        images = release.load_images('sudo')['packages']
        keys = catalog.load_keys()
        for entry in catalog.read('sudo')['releases']:
            s, packages = catalog.verify_release('sudo', entry, keys)
            for dfu_key, p in packages.items():
                with self.subTest(s['id'], key=dfu_key):
                    self.assertEqual(p['imageSha256'], images[s['asset']['sha256']]['imageSha256'])


if __name__ == '__main__':
    unittest.main()
