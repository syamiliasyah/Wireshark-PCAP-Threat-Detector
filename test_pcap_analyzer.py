import unittest
from network_utils import is_unencrypted_port, format_alert

class TestNetworkUtils(unittest.TestCase):

    def test_unencrypted_port_detection(self):
        is_unencrypted, proto = is_unencrypted_port(80)
        self.assertTrue(is_unencrypted)
        self.assertEqual(proto, "HTTP")

    def test_encrypted_port(self):
        is_unencrypted, proto = is_unencrypted_port(443)
        self.assertFalse(is_unencrypted)
        self.assertIsNone(proto)

    def test_alert_formatting(self):
        alert = format_alert("Test", "Sample Message")
        self.assertEqual(alert, "[ALERT - TEST] Sample Message")

if __name__ == "__main__":
    unittest.main()
