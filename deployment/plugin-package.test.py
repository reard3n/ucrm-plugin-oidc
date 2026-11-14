"""Artifact boundary tests; no Docker, package downloads or native runtime calls."""
import copy
import importlib.util
import io
from pathlib import Path
import unittest
import zipfile

spec = importlib.util.spec_from_file_location('plugin_package', Path(__file__).with_name('plugin-package.py'))
package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package)


class PackageTests(unittest.TestCase):
    def setUp(self):
        self.library = {'name': 'example/client', 'version': '1.0.0', 'type': 'library',
                        'source': {'reference': 'a' * 40}, 'dist': {'type': 'zip', 'reference': 'a' * 40}}
        self.lock = {'packages': [self.library]}
        self.timestamp = package.commit_zip_time(1794600001)

    def test_traversal_platform_alias_and_control_paths_rejected(self):
        for path in ['/manifest.json', '../private/key', 'src/../private/key', 'C:/key', 'src\\file.php',
                     'src/./file.php', 'src//file.php', 'src/file.php\n', 'src/file.php.', 'src/file.php ']:
            with self.subTest(path=path), self.assertRaises(ValueError):
                package.safe_path(path)

    def test_private_generated_and_test_source_cannot_enter_zip(self):
        for path in ['.env', 'data/config.json', 'ucrm.json', 'private/state.db', 'tests/fixture.php',
                     'vendor/autoload.php', 'public/data/key.json', 'src/private/config.php']:
            self.assertFalse(package.source_allowed(path), path)
        for path in ['manifest.json', 'composer.lock', 'NOTICE.md', 'hook_remove.php', 'src/NativeSession.php', 'public/login-button.js']:
            self.assertTrue(package.source_allowed(path), path)

    def test_portable_context_names_and_local_endpoints_only(self):
        for name in ['default', 'desktop-linux', 'local_builder.1']:
            self.assertEqual(package.docker_context(name), name)
        for name in ['', '--host=remote', 'name with spaces', 'x' * 65, None]:
            with self.assertRaises(ValueError):
                package.docker_context(name)
        for endpoint in ['unix:///var/run/docker.sock', 'unix:///run/user/1000/docker.sock',
                         'npipe:////./pipe/dockerDesktopLinuxEngine']:
            self.assertTrue(package.local_docker_endpoint(endpoint))
        for endpoint in ['ssh://operator@remote', 'tcp://127.0.0.1:2375', 'https://remote', None]:
            self.assertFalse(package.local_docker_endpoint(endpoint))

    def test_generated_build_arguments_preserve_selected_context_and_isolation(self):
        commands = package.composer_commands(Path('/new-build'), 'local-builder')
        for command in commands.values():
            self.assertEqual(command[:4], ['docker', '--context', 'local-builder', 'run'])
            self.assertIn('COMPOSER_AUTH={}', command)
            self.assertIn('--read-only', command)
            self.assertIn('--cap-drop', command)
            self.assertIn(str(Path('/new-build') / 'plugin'), next(arg for arg in command if arg.startswith('type=bind,source=') and 'target=/work/plugin' in arg))

    def test_installed_packages_must_match_exact_lock_references(self):
        self.assertEqual(package.validate_installed(self.lock, {'packages': [self.library]}), ['example/client'])
        changed = copy.deepcopy(self.library); changed['dist']['reference'] = 'b' * 40
        with self.assertRaises(ValueError):
            package.validate_installed(self.lock, {'packages': [changed]})
        changed = copy.deepcopy(self.library); changed['version'] = '1.0.1'
        with self.assertRaises(ValueError):
            package.validate_installed(self.lock, {'packages': [changed]})

    def test_extra_missing_duplicate_and_dev_dependencies_rejected(self):
        dev = copy.deepcopy(self.library); dev['dev_requirement'] = True
        for installed in [[], [self.library, self.library], [dev], [{**self.library, 'name': 'other/client'}]]:
            with self.subTest(installed=installed), self.assertRaises(ValueError):
                package.validate_installed(self.lock, {'packages': installed})

    def test_zip_is_deterministic_flat_and_preserves_exact_source_bytes(self):
        entries = {'manifest.json': b'{"name":"ucrm-oidc"}\n', 'public/login-button.js': b'// exact\r\n'}
        first = package.zip_bytes(entries, self.timestamp)
        self.assertEqual(first, package.zip_bytes(dict(reversed(list(entries.items()))), self.timestamp))
        with zipfile.ZipFile(io.BytesIO(first)) as archive:
            self.assertEqual(set(archive.namelist()), set(entries))
            for name, value in entries.items():
                self.assertEqual(archive.read(name), value)
                info = archive.getinfo(name)
                self.assertEqual(info.date_time, self.timestamp)
                self.assertEqual((info.external_attr >> 16) & 0o777, 0o644)

    def test_case_colliding_zip_entries_are_rejected(self):
        with self.assertRaises(ValueError):
            package.zip_bytes({'src/File.php': b'a', 'src/file.php': b'b'}, self.timestamp)

    def test_source_commit_timestamps_are_utc_and_dos_two_second_precision(self):
        self.assertEqual(package.commit_zip_time(1794600001), (2026, 11, 13, 20, 0, 0))
        self.assertEqual(package.commit_zip_time(1794600000), self.timestamp)
        with self.assertRaises(ValueError):
            package.commit_zip_time(0)
        with self.assertRaises(ValueError):
            package.commit_zip_time('1794600001')

    def test_new_release_preserves_bytes_but_changes_zip_mtime_for_native_opcache(self):
        entries = {'public.php': b'<?php echo "release";'}
        old = package.zip_bytes(entries, self.timestamp)
        new_time = package.commit_zip_time(1794600002)
        new = package.zip_bytes(entries, new_time)
        self.assertNotEqual(old, new)
        with zipfile.ZipFile(io.BytesIO(new)) as archive:
            self.assertEqual(archive.read('public.php'), entries['public.php'])
            self.assertGreater(archive.getinfo('public.php').date_time, self.timestamp)

    def test_published_runtime_test_utilities_are_retained_without_dev_suites(self):
        runtime = 'vendor/symfony/http-client/Test/HarFileResponseFactory.php'
        suite = 'vendor/example/client/tests/ClientTest.php'
        self.assertTrue(package.retain_vendor_path(runtime, {runtime}))
        self.assertFalse(package.retain_vendor_path(suite, {runtime}))
        self.assertFalse(package.retain_vendor_path('vendor/example/client/tests/fixtures/key.pem', {runtime}))


if __name__ == '__main__':
    unittest.main()
