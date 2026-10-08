import unittest

from netguard.devices import _parse_ip_neigh
from netguard.safe import valid_interface, valid_ip, valid_mac
from netguard.wifi import Network, _split_nmcli_row, assess_networks, password_feedback


class ValidationTests(unittest.TestCase):
    def test_validators(self):
        self.assertTrue(valid_interface("wlan0"))
        self.assertFalse(valid_interface("wlan0;id"))
        self.assertTrue(valid_ip("192.168.1.1"))
        self.assertFalse(valid_ip("192.168.1.999"))
        self.assertTrue(valid_mac("aa:bb:cc:dd:ee:ff"))
        self.assertFalse(valid_mac("not-a-mac"))


class ParsingTests(unittest.TestCase):
    def test_nmcli_escaped_separator(self):
        self.assertEqual(_split_nmcli_row(
            r"Coffee\: Guest:aa\:bb\:cc\:dd\:ee\:ff:6:72:WPA2"
        ), ["Coffee: Guest", "aa:bb:cc:dd:ee:ff", "6", "72", "WPA2"])

    def test_neighbor_table_parsing(self):
        rows = _parse_ip_neigh("192.168.1.8 dev wlan0 lladdr aa:bb:cc:dd:ee:ff REACHABLE\n")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].ip, "192.168.1.8")
        self.assertEqual(rows[0].status, "REACHABLE")
        self.assertEqual(rows[0].hostname, "not verified")

    def test_security_warning(self):
        warnings = assess_networks([Network("Cafe", security="Open / unsecured")])
        self.assertTrue(any("WPA2-AES or WPA3" in warning for warning in warnings))

    def test_password_feedback_does_not_echo_password(self):
        feedback = password_feedback("tiny")
        self.assertTrue(any("12 characters" in item for item in feedback))
        self.assertNotIn("tiny", " ".join(feedback))


if __name__ == "__main__":
    unittest.main()
