#!/usr/bin/env python3
"""The signed policy: floor, withdrawals and rollout ceilings, with throwaway
keys in a throwaway repository. No Keychain or network."""
import base64
import contextlib
import copy
import io
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import catalog  # noqa: E402
import p256  # noqa: E402
import release  # noqa: E402
import test_catalog as helpers  # noqa: E402  (a module, so its test classes don't run twice)


class PolicyTest(unittest.TestCase):
    """r117 and r118 are test builds, r119 a stable release that installs
    itself; the first policy is made by release.policy as Jeremy would."""

    publish_test_build = helpers.SudoAutomaticTest.publish_test_build
    record = helpers.SudoAutomaticTest.record

    @classmethod
    def setUpClass(cls):
        """The repository is built once (P-256 in Python is slow) and copied for each test."""
        cls.private, public = p256.generate()
        cls.keys = {'sudo-release-1': public, 'glyph-release-1': p256.generate()[1]}
        cls.sign = staticmethod(lambda raw: p256.sign(cls.private, raw))
        cls.base = tempfile.TemporaryDirectory()
        cls.root = Path(cls.base.name)
        (cls.root / 'keys').mkdir()
        for key_id, raw in cls.keys.items():
            (cls.root / 'keys' / f'{key_id}.x963').write_bytes(raw)
        (cls.root / 'products' / 'sudo').mkdir(parents=True)
        with mock.patch.object(catalog, 'ROOT', cls.root), contextlib.redirect_stdout(io.StringIO()):
            builder = cls.__new__(cls)
            for revision in (117, 118, 119):
                package = helpers.sudo_package(cls.root / 'pkg' / str(revision) / 'BCL603S2P_6.0.3.3P21.zip',
                                               image_bytes=2048 + revision)
                builder.publish_test_build(f'6.0.3.3P21-r{revision}', revision, package,
                                           {**helpers.IDENTITY, 'revision': revision})
            out = cls.root / 'promote'
            package = cls.root / 'pkg' / '119' / 'BCL603S2P_6.0.3.3P21.zip'
            image = __import__('zipfile').ZipFile(package).read('app.bin')
            release.promote('sudo', '6.0.3.3P21-r119', 'stable', package, out, 270, True, auto_install=True,
                            customer_version='1.0.119', notes='The firmware Rings ship with.',
                            source_versions=['6.0.3.3P21'], qualification=helpers.qualification(119, image),
                            signer=cls.sign, keys=cls.keys)
            with mock.patch.object(release, 'anonymous_get', return_value=package.read_bytes()), \
                    mock.patch.object(release, 'commit'):
                release.publish(out)

    @classmethod
    def tearDownClass(cls):
        cls.base.cleanup()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / 'repo'
        shutil.copytree(type(self).root, self.root)
        patch = mock.patch.object(catalog, 'ROOT', self.root); patch.start(); self.addCleanup(patch.stop)
        self.commits = []

    def policy(self, **changes):
        """release.policy with the throwaway key; its commit is recorded, not run."""
        with mock.patch.object(release, 'commit', side_effect=lambda paths, message, push: self.commits.append(message)), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            statement = release.policy('sudo', signer=self.sign, keys=self.keys, **changes)
        return statement, output.getvalue()

    def entry(self, release_id):
        return next(e for e in catalog.read('sudo')['releases'] if e['id'] == release_id)

    def test_the_first_policy_is_signed_into_its_file_and_the_catalog(self):
        statement, summary = self.policy(withdraw=['6.0.3.3P21-r117'], reason='Touch fault', floors=[(21, 118)],
                                         rollouts=[('6.0.3.3P21-r119', 1)])
        self.assertEqual((statement['sequence'], statement['minimumRevision'], statement['rollout']),
                         (1, {'21': 118}, {'6.0.3.3P21-r119': 1}))
        self.assertEqual(statement['withdrawn'], [{'id': '6.0.3.3P21-r117', 'sha256': self.entry('6.0.3.3P21-r117')['asset']['sha256']}])
        envelope = catalog.read_policy('sudo')
        self.assertEqual(catalog.verify_policy('sudo', envelope, self.keys)[0], statement)
        self.assertNotIn('policy', catalog.read('sudo'))  # apps fetch the file
        # The unsigned fields builds before the policy read say the same.
        self.assertEqual((self.entry('6.0.3.3P21-r117')['withdrawn'], self.entry('6.0.3.3P21-r117')['withdrawnReason']),
                         (True, 'Touch fault'))
        self.assertEqual(self.entry('6.0.3.3P21-r119')['rollout']['percent'], 1)
        self.assertEqual(self.commits, ['Policy sudo 1'])
        self.assertIn('Policy sudo 1 (the first)', summary)
        self.assertIn('Floor: P21 revision 118', summary)
        self.assertIn('Withdrawn (new): 6.0.3.3P21-r117', summary)
        report, warnings = catalog.check_repository(self.keys)
        self.assertIn('sudo: policy 1 verified', report)
        self.assertEqual(warnings, [])

    def test_a_dry_run_signs_and_changes_nothing(self):
        before = catalog.catalog_path('sudo').read_bytes()
        out = self.root / 'review'
        sign = mock.Mock(side_effect=AssertionError('signed'))
        with contextlib.redirect_stdout(io.StringIO()) as output:
            statement = release.policy('sudo', floors=[(21, 118)], out=out, dry_run=True, signer=sign, keys=self.keys)
        sign.assert_not_called()
        self.assertEqual(catalog.catalog_path('sudo').read_bytes(), before)
        self.assertIsNone(catalog.read_policy('sudo'))
        self.assertEqual(json.loads((out / 'statement.json').read_bytes()), statement)
        self.assertEqual((out / 'summary.txt').read_text(), output.getvalue())

    def test_each_policy_follows_the_last(self):
        first, _ = self.policy(floors=[(21, 118)])
        second, summary = self.policy(rollouts=[('6.0.3.3P21-r119', 10)])
        self.assertEqual((second['sequence'], second['minimumRevision']), (2, {'21': 118}))
        self.assertNotIn('(the first)', summary)
        catalog.check_policy_history(first, second)
        cases = {
            'the same sequence': {**second, 'sequence': 1},
            'a lower floor': {**second, 'sequence': 3, 'minimumRevision': {'21': 117}},
            'no floor': {**second, 'sequence': 3, 'minimumRevision': {}},
        }
        for name, policy in cases.items():
            with self.subTest(name), self.assertRaises(catalog.CatalogError):
                catalog.check_policy_history(first, policy)
        withdrawn, _ = self.policy(withdraw=['6.0.3.3P21-r117'], reason='Touch fault')
        with self.assertRaisesRegex(catalog.CatalogError, "can't be undone"):
            catalog.check_policy_history(withdrawn, {**withdrawn, 'sequence': 4, 'withdrawn': []})
        with self.assertRaisesRegex(catalog.CatalogError, 'would not change'):
            self.policy(floors=[(21, 118)])
        with self.assertRaisesRegex(catalog.CatalogError, 'only rise'):
            self.policy(floors=[(21, 117)])

    def test_the_floor_follows_the_apps_ranking(self):
        policy = {'minimumRevision': {'20': 9, '21': 118}}
        ranked = {('6.0.3.3P21', 118): False, ('6.0.3.3P21', 119): False, ('6.0.3.3P21', 117): True,
                  ('6.0.3.3P21', 18): True,   # source revision 18, below its rebuild 118
                  ('6.0.3.3P21', 7): True, ('6.0.3.3P20', 9): True, ('6.0.3.3P22', 1): False,
                  ('6.0.3.3Z62', 1): True}
        for (version, revision), below in ranked.items():
            with self.subTest(version=version, revision=revision):
                self.assertEqual(catalog.below_floor(policy, {'version': version, 'packageRevision': revision}), below)
        self.assertFalse(catalog.below_floor({'minimumRevision': {}}, {'version': '6.0.3.3Z62', 'packageRevision': 1}))

    def test_the_policy_names_only_what_the_catalog_has(self):
        self.policy(floors=[(21, 118)])
        cases = {
            'a floor naming no release': dict(floors=[(21, 126)]),
            'a floor above everything offered': dict(floors=[(21, 119)], withdraw=['6.0.3.3P21-r119'], reason='x'),
            'a ceiling on a test build': dict(rollouts=[('6.0.3.3P21-r118', 5)]),
            'a ceiling on no release': dict(rollouts=[('6.0.3.3P21-r126', 5)]),
            'a new withdrawal without a reason': dict(withdraw=['6.0.3.3P21-r118']),
            'a withdrawal of no release': dict(withdraw=['6.0.3.3P21-r126'], reason='x'),
        }
        for name, changes in cases.items():
            with self.subTest(name), self.assertRaises((catalog.CatalogError, KeyError)):
                self.policy(**changes)
        self.assertEqual(catalog.verify_policy('sudo', catalog.read_policy('sudo'), self.keys)[0]['sequence'], 1)

    def test_the_catalog_check_refuses_a_policy_it_disagrees_with(self):
        self.policy(withdraw=['6.0.3.3P21-r117'], reason='Touch fault', rollouts=[('6.0.3.3P21-r119', 5)])
        current = catalog.read('sudo')
        good = catalog.current_policy('sudo', self.keys)

        def check(policy=None, edit=None):
            releases = copy.deepcopy(current['releases'])
            if edit:
                edit({e['id']: e for e in releases})
            catalog.check_policy_against_catalog('sudo', policy or good, releases, self.keys)
        check()
        cases = {
            'a withdrawn package that is another': (dict(good, withdrawn=[{'id': '6.0.3.3P21-r117', 'sha256': '0' * 64}]), None),
            'a withdrawal the entry dropped': (None, lambda e: e['6.0.3.3P21-r117'].update(withdrawn=False)),
            'an unsigned rollout above the ceiling': (None, lambda e: e['6.0.3.3P21-r119'].update(rollout={'percent': 6})),
            'an unsigned rollout with no ceiling': (dict(good, rollout={}), None),
        }
        for name, (policy, edit) in cases.items():
            with self.subTest(name), self.assertRaises(catalog.CatalogError):
                check(policy, edit)

    def test_unsigned_controls_only_narrow_under_a_policy(self):
        self.policy(floors=[(21, 118)], rollouts=[('6.0.3.3P21-r119', 10)])
        release.set_rollout('sudo', '6.0.3.3P21-r119', 5)
        self.assertEqual(self.entry('6.0.3.3P21-r119')['rollout']['percent'], 5)
        with self.assertRaisesRegex(catalog.CatalogError, 'above the signed ceiling'):
            release.set_rollout('sudo', '6.0.3.3P21-r119', 11)
        # An emergency withdrawal needs no signature, even of the release the
        # floor names or one with a ceiling.
        release.withdraw('sudo', '6.0.3.3P21-r119', 'charger regression')
        release.withdraw('sudo', '6.0.3.3P21-r118', 'charger regression')
        self.assertEqual(catalog.check_repository(self.keys)[0][-1], 'sudo: policy 1 verified')
        release.set_pause('sudo', 'all')
        self.assertEqual(catalog.read('sudo')['automaticUpdatesPaused'], 'all')

    def test_the_envelope_and_statement_are_exact(self):
        self.policy(floors=[(21, 118)])
        envelope = catalog.read_policy('sudo')
        statement = json.loads(base64.b64decode(envelope['statement']))

        def signed(s):
            raw = catalog.encode_statement(s)
            return {**envelope, 'statement': base64.b64encode(raw).decode(),
                    'signature': {**envelope['signature'], 'der': base64.b64encode(self.sign(raw)).decode()}}
        catalog.verify_policy('sudo', signed(statement), self.keys)
        cases = {
            'a tampered statement': {**envelope, 'statement': base64.b64encode(
                catalog.encode_statement({**statement, 'minimumRevision': {}})).decode()},
            'another key': signed(statement) | {'signature': {**envelope['signature'], 'keyId': 'glyph-release-1'}},
            'an extra envelope field': {**envelope, 'note': 'x'},
            'an extra statement field': signed({**statement, 'expires': '2027-01-01T00:00:00Z'}),
            'a missing statement field': signed({k: v for k, v in statement.items() if k != 'rollout'}),
            'a release statement': signed({**statement, 'schema': catalog.SCHEMA}),
            'another product': signed({**statement, 'product': 'glyph'}),
            'sequence 0': signed({**statement, 'sequence': 0}),
            'a sequence past the app\'s 2^31 - 1': signed({**statement, 'sequence': 2**31}),
            'a generation that is not a number': signed({**statement, 'minimumRevision': {'P21': 118}}),
            'withdrawals out of order': signed({**statement, 'withdrawn': [{'id': 'b', 'sha256': '1' * 64},
                                                                           {'id': 'a', 'sha256': '2' * 64}]}),
            'one package withdrawn twice': signed({**statement, 'withdrawn': [{'id': 'a', 'sha256': '1' * 64},
                                                                              {'id': 'b', 'sha256': '1' * 64}]}),
            'a ceiling over 100': signed({**statement, 'rollout': {'6.0.3.3P21-r119': 101}}),
            'a statement over 4096 bytes': signed({**statement, 'withdrawn': [
                {'id': f'6.0.3.3P21-r{i}', 'sha256': f'{i:064x}'} for i in range(100, 160)]}),
        }
        for name, bad in cases.items():
            with self.subTest(name), self.assertRaises(catalog.CatalogError):
                catalog.verify_policy('sudo', bad, self.keys)
        # Glyph has no policy, and no catalog carries one.
        with self.assertRaises(catalog.CatalogError):
            catalog.verify_policy('glyph', {**envelope, 'product': 'glyph', 'hardware': 'PKS3-101'}, self.keys)
        with self.assertRaisesRegex(catalog.CatalogError, 'lives in policy-v1.json'):
            catalog.validate_catalog('sudo', {**catalog.read('sudo'), 'policy': envelope}, self.keys)

    def test_every_catalog_change_is_checked_against_the_committed_policy(self):
        self.policy(withdraw=['6.0.3.3P21-r117'], reason='Touch fault')
        current = catalog.read('sudo')
        next(e for e in current['releases'] if e['id'] == '6.0.3.3P21-r117')['withdrawn'] = False
        with self.assertRaisesRegex(catalog.CatalogError, 'withdrawn: true too'):
            catalog.write('sudo', current)
        catalog.catalog_path('sudo').write_text(json.dumps(current, indent=2) + '\n')
        with self.assertRaisesRegex(catalog.CatalogError, 'withdrawn: true too'):
            catalog.check_repository(self.keys)

    def test_ci_checks_the_policy_against_the_base_commit(self):
        def git(*args):
            subprocess.run(['git', '-C', str(self.root), *args], check=True, capture_output=True)
        git('init', '-q'); git('config', 'user.email', 'ci@example.com'); git('config', 'user.name', 'CI')
        git('add', '-A'); git('commit', '-q', '-m', 'no policy')
        self.policy(floors=[(21, 118)])
        git('add', '-A'); git('commit', '-q', '-m', 'policy 1')
        self.assertIn('sudo: policy 1 verified', catalog.check_repository(self.keys, 'HEAD~1')[0])
        self.policy(rollouts=[('6.0.3.3P21-r119', 1)])
        self.assertIn('sudo: policy 2 verified', catalog.check_repository(self.keys, 'HEAD')[0])
        # The committed policy 1 again, over policy 2: an older state served again.
        git('add', '-A'); git('commit', '-q', '-m', 'policy 2')
        git('checkout', '-q', 'HEAD~1', '--', 'products')
        with self.assertRaisesRegex(catalog.CatalogError, 'must be above'):
            catalog.check_repository(self.keys, 'HEAD')
        # Or the policy removed.
        git('checkout', '-q', 'HEAD', '--', 'products')
        catalog.policy_path('sudo').unlink()
        with self.assertRaisesRegex(catalog.CatalogError, "can't be removed"):
            catalog.check_repository(self.keys, 'HEAD')
        with self.assertRaisesRegex(catalog.CatalogError, 'not a commit'):
            catalog.check_repository(self.keys, 'f' * 40)
        # A new branch's first push names no previous commit: main stands in.
        self.assertEqual((catalog.previous_ref('0' * 40), catalog.previous_ref(''), catalog.previous_ref(None),
                          catalog.previous_ref('abc123')), ('origin/main', 'origin/main', None, 'abc123'))


class CatalogSizeTest(unittest.TestCase):
    def test_apps_limits(self):
        limit = catalog.APP_LIMITS['sudo']['bytes']
        self.assertEqual(catalog.check_size('sudo', 231_095, 52), [])
        self.assertEqual(len(catalog.check_size('sudo', int(limit * 0.8), 52)), 1)
        self.assertEqual(len(catalog.check_size('sudo', 1000, 80)), 1)  # the app keeps 100
        for size, entries in ((limit + 1, 52), (1000, 201)):
            with self.subTest(size=size, entries=entries), self.assertRaises(catalog.CatalogError):
                catalog.check_size('sudo', size, entries)
        self.assertEqual(catalog.check_size('glyph', 1000, 300), [])


if __name__ == '__main__':
    unittest.main()
