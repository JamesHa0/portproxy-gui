#!/usr/bin/env python3
"""Unit tests for netstat parsing and port matching (regression for :80 vs :8080)."""

import unittest
from unittest import mock

from portproxy_common import _extract_port, parse_netstat_listen, _check_listen

NETSTAT_SAMPLE = (
    "  TCP    0.0.0.0:8080          0.0.0.0:0              LISTENING       1234\n"
    "  TCP    [::]:80                [::]:0                  LISTENING       999\n"
    "  TCP    127.0.0.1:3306         0.0.0.0:0              LISTENING       4567\n"
)


class TestExtractPort(unittest.TestCase):
    def test_ipv4(self):
        self.assertEqual(_extract_port("0.0.0.0:8080"), 8080)

    def test_ipv6_bracketed(self):
        self.assertEqual(_extract_port("[::]:80"), 80)

    def test_ipv6_unbracketed(self):
        self.assertEqual(_extract_port("::1:443"), 443)

    def test_missing_port(self):
        self.assertIsNone(_extract_port("0.0.0.0"))


class TestParseNetstat(unittest.TestCase):
    def test_ports_are_exact(self):
        listen = parse_netstat_listen(NETSTAT_SAMPLE)
        self.assertEqual(listen[8080], {1234})
        self.assertEqual(listen[80], {999})
        # Port 80 and 8080 must be two distinct keys (no substring confusion).
        self.assertNotEqual(listen[80], listen[8080])


class TestCheckListen(unittest.TestCase):
    def test_prefix_ports_not_confused(self):
        # Rule on port 80 while only port 8080 is actually listening → error, not "ok".
        listen_map = {8080: {1234}}
        res = _check_listen(80, listen_map, iphlp_pid=None)
        self.assertIsInstance(res, dict)
        self.assertIn("error", res)

    def test_iphlp_only_is_ok(self):
        listen_map = {8080: {900}}
        self.assertEqual(_check_listen(8080, listen_map, iphlp_pid=900), "ok")

    def test_foreign_pid_reports_occupied(self):
        listen_map = {8080: {1234}}
        with mock.patch("portproxy_common._pid_name", return_value="nginx.exe"):
            res = _check_listen(8080, listen_map, iphlp_pid=900)
        self.assertIsInstance(res, dict)
        self.assertIn("nginx.exe", res["error"])


if __name__ == "__main__":
    unittest.main()
