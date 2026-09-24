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
