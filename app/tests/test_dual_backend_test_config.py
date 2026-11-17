"""Verify that the test launcher shares credentials read-only, never app data."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[2] / 'scripts/prepare-dual-backend-test.py'
spec = importlib.util.spec_from_file_location('dual_test_config', SCRIPT)
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)


class DualTestConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root/'tls.cert').write_text('test certificate')
        (self.root/'admin.macaroon').write_text('do-not-copy-content')
        self.container = {
            'Config': {'Env': ['LND_REST_URL=https://192.0.2.1:8080', 'PAY_UI_PASSWORD=never-copy', 'OTHER_SECRET=never-copy']},
            'Mounts': [{'Type':'bind','Source':str(self.root),'Destination':'/secrets'},
                       {'Type':'volume','Source':'/production/data','Destination':'/data'}],
        }

    def test_only_lnd_settings_and_two_readonly_files(self):
        result = helper.configuration(self.container)
        service = result['services']['pay']
        self.assertEqual(set(service['environment']), {'LND_REST_URL','LND_REST_INSECURE','LND_TLS_CERT_PATH','LND_MACAROON_PATH'})
        self.assertEqual(len(service['volumes']),2)
        self.assertTrue(all(m['read_only'] and not m['bind']['create_host_path'] for m in service['volumes']))
        self.assertNotIn('never-copy',str(result))
        self.assertNotIn('/production/data',str(result))
        self.assertNotIn('do-not-copy-content',str(result))

    def test_missing_file_fails_instead_of_creating_directory(self):
        (self.root/'admin.macaroon').unlink()
        with self.assertRaises(ValueError): helper.configuration(self.container)

    def test_loopback_and_credential_urls_are_rejected(self):
        for url in ['http://127.0.0.1:8080','https://user:secret@example.com']:
            self.container['Config']['Env']=['LND_REST_URL='+url]
            with self.assertRaises(ValueError): helper.configuration(self.container)

    def test_named_volume_credentials_require_explicit_configuration(self):
        self.container['Mounts'][0]['Type']='volume'
        with self.assertRaises(ValueError): helper.configuration(self.container)


    def test_docker_desktop_vm_prefix_maps_to_existing_host_files(self):
        self.container['Mounts'][0]['Source'] = '/host_mnt' + str(self.root)
        result = helper.configuration(self.container)
        self.assertEqual(
            [mount['source'] for mount in result['services']['pay']['volumes']],
            [str(self.root/'tls.cert'), str(self.root/'admin.macaroon')],
        )

    def test_docker_desktop_missing_host_file_still_fails(self):
        self.container['Mounts'][0]['Source'] = '/host_mnt' + str(self.root)
        (self.root/'admin.macaroon').unlink()
        with self.assertRaises(ValueError): helper.configuration(self.container)

    def test_similar_prefix_is_not_rewritten(self):
        self.container['Mounts'][0]['Source'] = '/host_mnt_other' + str(self.root)
        with self.assertRaises(ValueError): helper.configuration(self.container)
