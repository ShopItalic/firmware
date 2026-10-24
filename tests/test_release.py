#!/usr/bin/env python3
"""Publisher display names and release guards; all external operations are mocked."""
import base64
import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import catalog  # noqa: E402
import p256  # noqa: E402
import release  # noqa: E402


class ReleaseTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        private, public = p256.generate()
        self.keys = {'sudo-release-1': public}
        self.patch(catalog, 'ROOT', self.root)
        self.patch(catalog, 'load_keys', return_value=self.keys)
        self.run = self.patch(release.subprocess, 'run', side_effect=AssertionError('unexpected external process'))
        self.gh = self.patch(release, 'gh', side_effect=AssertionError('unexpected GitHub mutation'))
        self.download = self.patch(release, 'anonymous_get', side_effect=AssertionError('unexpected download'))
        self.asset = self.root / 'BCL603S2P_6.0.3.3P21.zip'
        self.asset.write_bytes(b'publisher-test-package')
        self.stage_dir = self.root / 'stage'
        self.entry = release.stage('sudo', '6.0.3.3P21-r123', '6.0.3.3P21', 123, 'test', True,
                                   self.asset, [], self.stage_dir, ['6.0.3.3P21'],
                                   signer=lambda raw: p256.sign(private, raw), keys=self.keys)
        _, _, self.statement = release.load_stage(self.stage_dir)
        self.catalog_path = catalog.catalog_path('sudo')
        self.catalog_path.parent.mkdir(parents=True)
        self.catalog_path.write_text(json.dumps(catalog.empty('sudo')))

    def patch(self, target, name, *args, **kwargs):
        patcher = mock.patch.object(target, name, *args, **kwargs)
        value = patcher.start()
        self.addCleanup(patcher.stop)
        return value

    def missing_tag(self, command, **kwargs):
        self.assertEqual(command, ['gh', 'release', 'view', self.entry['tag'], '--repo', catalog.OWNER_REPO])
        return SimpleNamespace(returncode=1)

    def assert_no_external_calls(self):
        self.run.assert_not_called()
        self.gh.assert_not_called()
        self.download.assert_not_called()

    def test_known_sudo_line_defaults_to_three_part_titles(self):
        for revision in (107, 120, 122, 123, 999):
            with self.subTest(revision=revision):
                statement = {**self.statement, 'id': f'6.0.3.3P21-r{revision}', 'packageRevision': revision}
                self.assertEqual(release.release_title(statement), f'Sudo 1.0.{revision}')

    def test_older_sudo_and_glyph_keep_existing_titles(self):
        for product, version, revision, release_id, expected in (
                ('sudo', '6.0.3.3P21', 7, '6.0.3.3P21-r7', 'Sudo 6.0.3.3P21-r7'),
                ('sudo', '6.0.3.3P21', 106, '6.0.3.3P21-r106', 'Sudo 6.0.3.3P21-r106'),
                ('sudo', '6.0.3.3P20', 9, '6.0.3.3P20-r9', 'Sudo 6.0.3.3P20-r9'),
                ('glyph', 'P12-rc.1', 1, 'P12-rc.1', 'Glyph P12-rc.1')):
            with self.subTest(product=product, release_id=release_id):
                statement = {**self.statement, 'product': product, 'version': version,
                             'packageRevision': revision, 'id': release_id}
                self.assertEqual(release.release_title(statement), expected)
                with self.assertRaisesRegex(catalog.CatalogError, 'canonical Sudo P21'):
                    release.release_title(statement, f'1.0.{revision}')

    def test_incoherent_identity_keeps_fallback_and_refuses_override(self):
        for changes in ({'id': '6.0.3.3P21-r124'}, {'id': 'candidate-123'},
                        {'version': '6.0.3.3P20'}, {'packageRevision': 122}):
            with self.subTest(changes=changes):
                statement = {**self.statement, **changes}
                self.assertEqual(release.release_title(statement), f"Sudo {statement['id']}")
                with self.assertRaisesRegex(catalog.CatalogError, 'canonical Sudo P21'):
                    release.release_title(statement, '1.0.123')

    def test_explicit_future_and_legacy_versions(self):
        for supplied, expected in (('1.0.123', '1.0.123'), ('1.123', '1.0.123'),
                                   ('1.1.123', '1.1.123'), ('2.0.123', '2.0.123')):
            with self.subTest(supplied=supplied):
                self.assertEqual(release.release_title(self.statement, supplied), f'Sudo {expected}')

    def test_invalid_versions_fail_before_github(self):
        for version in ('', '1.0.124', '1.0.123.0', '1.0.123\n', ' 1.0.123',
                        '0.0.123', '1000.0.123', '1.x.123', '1.0.１２３', 'Sudo 1.0.123', True):
            with self.subTest(version=version):
                with self.assertRaises(catalog.CatalogError):
                    release.publish(self.stage_dir, firmware_version=version)
                self.assert_no_external_calls()

    def test_unsigned_display_metadata_does_not_select_title(self):
        path = self.stage_dir / 'entry.json'
        data = json.loads(path.read_text())
        data['entry'].update(customerVersion='9.9.123', firmwareVersion='8.8.123', name='Sudo 7.7.123',
                             details={'firmwareVersion': '6.6.123'})
        path.write_text(json.dumps(data))
        self.run.side_effect = self.missing_tag
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = release.publish(self.stage_dir, dry_run=True)
        self.assertIn('--title Sudo 1.0.123 ', output.getvalue())
        self.assertEqual(result['statement'], self.entry['statement'])
        self.gh.assert_not_called()
        self.download.assert_not_called()
        self.assertEqual(catalog.read('sudo')['releases'], [])

    def test_cli_accepts_display_override_without_changing_stage(self):
        before = {p.relative_to(self.stage_dir): p.read_bytes() for p in self.stage_dir.rglob('*') if p.is_file()}
        self.run.side_effect = self.missing_tag
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            release.main(['publish', str(self.stage_dir), '--firmware-version', '2.0.123', '--dry-run'])
        self.assertIn('--title Sudo 2.0.123 ', output.getvalue())
        self.assertEqual(before, {p.relative_to(self.stage_dir): p.read_bytes()
                                  for p in self.stage_dir.rglob('*') if p.is_file()})
        self.gh.assert_not_called()
        self.download.assert_not_called()

    def allow_publication_stubs(self):
        def process(command, **kwargs):
            if command[0] == 'gh':
                return self.missing_tag(command, **kwargs)
            self.assertEqual(command[:3], ['git', '-C', str(self.root)])
            self.assertIn(command[3], ('add', 'commit'))
            return SimpleNamespace(returncode=0)

        def github(*args, **kwargs):
            if args[:2] == ('release', 'create'):
                return ''
            self.assertEqual(args, ('api', f"repos/{catalog.OWNER_REPO}/releases/tags/{self.entry['tag']}"))
            return json.dumps({'assets': [{'id': 12345, 'name': self.asset.name}]})

        def download(url, accept=None):
            if url == catalog.ASSET_API + '12345':
                self.assertEqual(accept, 'application/octet-stream')
                return self.asset.read_bytes()
            prefix = catalog.DOWNLOAD + self.entry['tag'] + '/'
            self.assertTrue(url.startswith(prefix))
            name = url.removeprefix(prefix)
            self.assertIn(name, (self.asset.name, 'SHA256SUMS', 'statement.json', 'signature.der'))
            path = self.stage_dir / ('assets/' + name if name == self.asset.name else name)
            return path.read_bytes()

        self.run.side_effect = process
        self.gh.side_effect = github
        self.download.side_effect = download

    def test_publish_preserves_identity_channel_and_verified_asset_order(self):
        before = {p.relative_to(self.stage_dir): p.read_bytes() for p in self.stage_dir.rglob('*') if p.is_file()}
        self.allow_publication_stubs()
        with mock.patch.object(catalog, 'write', wraps=catalog.write) as write:
            # All four release files plus the anonymous package API must verify before catalog.write.
            def checked_write(product, current):
                self.assertEqual(self.download.call_count, 5)
                return original_write(product, current)
            original_write = write._mock_wraps
            write.side_effect = checked_write
            with contextlib.redirect_stdout(io.StringIO()):
                published = release.publish(self.stage_dir)
            write.assert_called_once()
        command = self.gh.call_args_list[0].args
        self.assertEqual(command[:3], ('release', 'create', 'sudo-6.0.3.3P21-r123'))
        self.assertEqual(command[command.index('--title') + 1], 'Sudo 1.0.123')
        self.assertIn('--prerelease', command)
        self.assertEqual(published['statement'], self.entry['statement'])
        self.assertEqual(published['signature'], self.entry['signature'])
        self.assertEqual(published['tag'], self.entry['tag'])
        self.assertEqual(catalog.verify_entry('sudo', published, self.keys), self.statement)
        self.assertEqual(catalog.read('sudo')['releases'], [published])
        self.assertEqual(before, {p.relative_to(self.stage_dir): p.read_bytes()
                                  for p in self.stage_dir.rglob('*') if p.is_file()})

    def test_existing_tag_and_catalog_id_are_still_refused(self):
        self.run.side_effect = None
        self.run.return_value = SimpleNamespace(returncode=0)
        with self.assertRaisesRegex(catalog.CatalogError, 'tags are never reused'):
            release.publish(self.stage_dir)
        self.gh.assert_not_called()
        self.download.assert_not_called()
        self.run.reset_mock()
        self.catalog_path.write_text(json.dumps({**catalog.empty('sudo'), 'releases': [self.entry]}))
        with self.assertRaisesRegex(catalog.CatalogError, 'already in catalog'):
            release.publish(self.stage_dir)
        self.assert_no_external_calls()

    def test_changed_package_is_rejected_before_github(self):
        (self.stage_dir / 'assets' / self.asset.name).write_bytes(b'changed-package')
        with self.assertRaisesRegex(catalog.CatalogError, 'staged package changed'):
            release.publish(self.stage_dir)
        self.assert_no_external_calls()

    def test_bad_signature_is_rejected_before_github(self):
        path = self.stage_dir / 'entry.json'
        data = json.loads(path.read_text())
        raw = base64.b64decode(data['entry']['statement']) + b' '
        data['entry']['statement'] = base64.b64encode(raw).decode()
        path.write_text(json.dumps(data))
        with self.assertRaisesRegex(catalog.CatalogError, 'bad signature'):
            release.publish(self.stage_dir)
        self.assert_no_external_calls()

    def test_bad_public_copy_never_updates_catalog(self):
        self.allow_publication_stubs()
        self.download.side_effect = None
        self.download.return_value = b'wrong-public-copy'
        with mock.patch.object(catalog, 'write') as write:
            with self.assertRaisesRegex(catalog.CatalogError, 'public download mismatch'):
                release.publish(self.stage_dir)
            write.assert_not_called()
        self.assertEqual(catalog.read('sudo')['releases'], [])
        self.assertEqual(self.run.call_count, 1, 'Only the read-only tag lookup ran; no git commit')


if __name__ == '__main__':
    unittest.main()
