import io
import unittest
from unittest.mock import patch

from detect_open_ports import OpenPortScanner


class FakeSocket:
    def __init__(self, connect_result=0):
        self._connect_result = connect_result

    def settimeout(self, _timeout):
        return None

    def connect_ex(self, _target):
        return self._connect_result

    def close(self):
        return None


class TestDetectOpenPorts(unittest.TestCase):
    @patch("detect_open_ports.socket.socket", return_value=FakeSocket(connect_result=0))
    def test_scan_port_socket_detects_open_port(self, _mock_socket):
        scanner = OpenPortScanner(["127.0.0.1"], ports=[23], timeout=1)
        result = scanner.scan_port_socket("127.0.0.1", 23)

        self.assertIsNotNone(result)
        self.assertEqual(result["port"], 23)
        self.assertEqual(result["state"], "open")
        self.assertTrue(result["risky"])

    @patch("detect_open_ports.socket.socket", return_value=FakeSocket(connect_result=1))
    def test_check_host_alive_false_when_connect_fails(self, _mock_socket):
        scanner = OpenPortScanner(["127.0.0.1"], timeout=1)
        self.assertFalse(scanner.check_host_alive("127.0.0.1"))

    def test_generate_report_contains_summary(self):
        scanner = OpenPortScanner(["host1"], ports=[22, 80], timeout=1)
        scanner.scan_results = {
            "host1": [
                {"port": 22, "state": "open", "service": "SSH", "risky": True},
                {"port": 80, "state": "open", "service": "HTTP", "risky": False},
            ]
        }

        with patch("sys.stdout", new_callable=io.StringIO) as fake_out:
            scanner.generate_report()

        output = fake_out.getvalue()
        self.assertIn("OPEN PORT SCAN REPORT", output)
        self.assertIn("Total Open Ports Found: 2", output)
        self.assertIn("Total Risky Ports Found: 1", output)


if __name__ == "__main__":
    unittest.main()
