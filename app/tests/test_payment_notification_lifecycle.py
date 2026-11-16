import subprocess
import unittest
from pathlib import Path

class PaymentNotificationLifecycleTests(unittest.TestCase):
    def test_shared_module_across_authenticated_and_public_surfaces(self):
        result = subprocess.run(['node', str(Path(__file__).with_name('payment_notification_lifecycle.cjs'))],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
