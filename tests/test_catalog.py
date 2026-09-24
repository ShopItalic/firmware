#!/usr/bin/env python3
"""Catalog, signing and staging tests with throwaway keys. No Keychain or network."""
import base64
import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import catalog  # noqa: E402
import p256  # noqa: E402
import release  # noqa: E402
import device_index  # noqa: E402


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


class DeviceIndexTest(unittest.TestCase):
    def setUp(self):
        self.private, public = p256.generate()
        self.keys = {'glyph-release-1': public}
        self.tmp = tempfile.TemporaryDirectory(); self.root = Path(self.tmp.name)
        self.signer = lambda raw: p256.sign(self.private, raw)

    def tearDown(self):
        self.tmp.cleanup()

    def staged(self, release_id, installable=True, sources=('P13-rc.1',), size=4096):
        ufw = self.root / f'glyph-pks3-101-{release_id}.ufw'; ufw.write_bytes(bytes([len(release_id)]) * size)
        return release.stage('glyph', release_id, release_id, 1, 'test', installable, ufw, [],
                             self.root / release_id, list(sources) if sources else None,
                             signer=self.signer, keys=self.keys)

    def build(self, *entries):
        original = catalog.load_keys
        catalog.load_keys = lambda: self.keys
        try:
            return device_index.build('glyph', {**catalog.empty('glyph'), 'releases': list(entries)})
        finally:
            catalog.load_keys = original

    def test_only_offerable_signed_entries_newest_first(self):
        offer = self.staged('P13-rc.3')
        download_only = self.staged('P13-rc.2', installable=False)
        no_grant = self.staged('P13-rc.4', sources=None)
        withdrawn = self.staged('P13-rc.5'); withdrawn['withdrawn'] = True
        older = self.staged('P13-rc.1', sources=('P12-rc.1',))
        index = self.build(withdrawn, no_grant, offer, download_only, older)
        self.assertEqual([json.loads(base64.b64decode(e['statement']))['id'] for e in index['releases']],
                         ['P13-rc.3', 'P13-rc.1'])
        first = index['releases'][0]
        self.assertEqual(first['md5'], offer['asset']['md5'])
        self.assertEqual((first['statement'], first['signature']), (offer['statement'], offer['signature']['der']))
        self.assertTrue(p256.verify(self.keys['glyph-release-1'], base64.b64decode(first['statement']),
                                    base64.b64decode(first['signature'])))

    def test_size_cap_drops_oldest(self):
        entries = [self.staged(f'P13-rc.{n}') for n in range(30, 10, -1)]
        index = self.build(*entries)
        self.assertLessEqual(len(device_index.encode(index)), 8192)
        self.assertGreater(len(index['releases']), 5)
        self.assertEqual(json.loads(base64.b64decode(index['releases'][0]['statement']))['id'], 'P13-rc.30')

    def test_committed_index_is_current(self):
        device_index.check('glyph')


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
