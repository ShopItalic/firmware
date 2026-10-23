#!/usr/bin/env python3
"""Catalog, signing and staging tests with throwaway keys. No Keychain or network."""
import base64
import copy
import hashlib
import json
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
    with zipfile.ZipFile(path, 'w') as archive:
        archive.writestr('manifest.json', json.dumps({'manifest': manifest}))
        archive.writestr('app.bin', b'\x11' * image_bytes)
        archive.writestr('app.dat', b'\x00' * 141)
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
                   'customer_version': '1.0', 'notes': 'The firmware Rings ship with.',
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
                         (IDENTITY, '1.0', 'shorter start and stop buzzes'))
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


if __name__ == '__main__':
    unittest.main()
