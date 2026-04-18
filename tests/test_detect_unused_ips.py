import unittest
from unittest.mock import patch

from detect_unused_ips import UnusedIPDetector


class TestDetectUnusedIPs(unittest.TestCase):
    def test_validate_network_populates_hosts(self):
        detector = UnusedIPDetector("192.168.1.0/30")
        valid = detector.validate_network()

        self.assertTrue(valid)
        self.assertEqual(detector.all_ips, ["192.168.1.1", "192.168.1.2"])

    @patch("detect_unused_ips.platform.system", return_value="Linux")
    def test_build_ping_command_linux(self, _mock_system):
        detector = UnusedIPDetector("10.0.0.0/24", timeout=2)
        cmd = detector._build_ping_command("10.0.0.10")

        self.assertEqual(cmd, ["ping", "-c", "1", "-W", "2", "10.0.0.10"])

    @patch("detect_unused_ips.platform.system", return_value="Windows")
    def test_build_ping_command_windows(self, _mock_system):
        detector = UnusedIPDetector("10.0.0.0/24", timeout=2)
        cmd = detector._build_ping_command("10.0.0.10")

        self.assertEqual(cmd, ["ping", "-n", "1", "-w", "2000", "10.0.0.10"])

    def test_identify_unused_ips(self):
        detector = UnusedIPDetector("192.168.1.0/30")
        detector.all_ips = ["192.168.1.1", "192.168.1.2"]
        detector.used_ips = {"192.168.1.1"}

        detector.identify_unused_ips()

        self.assertEqual(detector.unused_ips, {"192.168.1.2"})


if __name__ == "__main__":
    unittest.main()
