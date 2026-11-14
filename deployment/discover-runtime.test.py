import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('discovery', Path(__file__).with_name('discover-runtime.py'))
discovery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(discovery)


class DiscoveryTests(unittest.TestCase):
    def test_real_effective_and_saved_ids_must_match(self):
        with self.assertRaises(ValueError):
            discovery.identity({'processes': [{'uid': [1, 2, 1, 1], 'gid': [3]*4}]}, {'uid': 4, 'gid': 5})

    def test_no_native_process_is_not_a_default_uid(self):
        with self.assertRaises(ValueError):
            discovery.identity({'processes': []}, {'uid': 4, 'gid': 5})

    def test_conflicting_worker_identity_is_refused(self):
        with self.assertRaises(ValueError):
            discovery.identity({'processes': [{'uid': [11]*4, 'gid': [12]*4}, {'uid': [13]*4, 'gid': [12]*4}]}, {'uid': 4, 'gid': 5})

    def test_actual_arbitrary_service_ids_are_preserved(self):
        result = discovery.identity({'processes': [{'uid': [17123]*4, 'gid': [17124]*4}]*3}, {'uid': 29876, 'gid': 29877})
        self.assertEqual(result, {'version': 1, 'api': {'uid': 17123, 'gid': 17124}, 'crm': {'uid': 29876, 'gid': 29877}})

    def test_root_and_non_numeric_owners_are_refused(self):
        for value in [0, -1, '1000', True, None]:
            with self.assertRaises(ValueError):
                discovery.identity({'processes': [{'uid': [1]*4, 'gid': [2]*4}]}, {'uid': value, 'gid': 3})


if __name__ == '__main__':
    unittest.main()
