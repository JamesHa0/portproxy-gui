#!/usr/bin/env python3
"""Unit tests for port/address validation."""

import unittest

from portproxy_common import validate_port, validate_ip, validate_connect_ip


class TestValidatePort(unittest.TestCase):
    def test_valid(self):
        ok, p = validate_port("8080")
        self.assertTrue(ok)
        self.assertEqual(p, 8080)

    def test_boundaries(self):
        self.assertTrue(validate_port("1")[0])
        self.assertTrue(validate_port("65535")[0])

    def test_zero_invalid(self):
        self.assertFalse(validate_port("0")[0])

    def test_too_large(self):
        self.assertFalse(validate_port("65536")[0])

    def test_nan(self):
        self.assertFalse(validate_port("abc")[0])

    def test_empty(self):
        self.assertFalse(validate_port("")[0])
        self.assertFalse(validate_port("  ")[0])


class TestValidateIp(unittest.TestCase):
    def test_ipv4(self):
        ok, v = validate_ip("192.168.1.100")
        self.assertTrue(ok)
        self.assertEqual(v, "192.168.1.100")

    def test_wildcard_and_empty(self):
        self.assertEqual(validate_ip(""), (True, ""))
        self.assertEqual(validate_ip("*"), (True, "*"))

    def test_ipv6(self):
        self.assertTrue(validate_ip("::1")[0])
        self.assertTrue(validate_ip("fe80::1")[0])
        # IPv6 is normalized to compressed form
        ok, v = validate_ip("0:0:0:0:0:0:0:1")
        self.assertTrue(ok)
        self.assertEqual(v, "::1")

    def test_ipv4_range(self):
        self.assertFalse(validate_ip("999.1.1.1")[0])
        self.assertFalse(validate_ip("1.2.3.999")[0])

    def test_hostname_rejected(self):
        self.assertFalse(validate_ip("example.com")[0])


class TestValidateConnectIp(unittest.TestCase):
    def test_valid_ipv4(self):
        self.assertTrue(validate_connect_ip("1.2.3.4")[0])

    def test_valid_ipv6(self):
        self.assertTrue(validate_connect_ip("::1")[0])

    def test_empty_rejected(self):
        self.assertFalse(validate_connect_ip("")[0])
        self.assertFalse(validate_connect_ip("  ")[0])

    def test_wildcard_rejected(self):
        self.assertFalse(validate_connect_ip("*")[0])

    def test_hostname_rejected(self):
        self.assertFalse(validate_connect_ip("example.com")[0])


if __name__ == "__main__":
    unittest.main()
