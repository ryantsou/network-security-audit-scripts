import unittest
from unittest.mock import patch

import detect_orphan_users
from detect_orphan_users import OrphanUserDetector


class TestDetectOrphanUsers(unittest.TestCase):
    def test_connect_ldap_handles_missing_dependency(self):
        detector = OrphanUserDetector("dc.example.com", "admin", "secret")
        detector._ldap_available = False
        detector._ldap_import_error = "ldap3 not installed"

        self.assertIsNone(detector.connect_ldap())

    def test_linux_only_mode_runs_without_ad_scan(self):
        argv = [
            "detect_orphan_users.py",
            "-lh", "192.168.1.10",
            "-lu", "root",
            "-lp", "password",
        ]

        with patch.object(detect_orphan_users.OrphanUserDetector, "detect_ad_orphans") as mock_ad, \
             patch.object(detect_orphan_users.OrphanUserDetector, "check_linux_orphans") as mock_linux, \
             patch.object(detect_orphan_users.OrphanUserDetector, "generate_report") as mock_report, \
             patch("sys.argv", argv):
            detect_orphan_users.main()

        mock_ad.assert_not_called()
        mock_linux.assert_called_once_with("192.168.1.10", "root", "password")
        mock_report.assert_called_once()

    def test_main_fails_without_any_target(self):
        with patch("sys.argv", ["detect_orphan_users.py"]):
            with self.assertRaises(SystemExit) as cm:
                detect_orphan_users.main()

        self.assertEqual(cm.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
