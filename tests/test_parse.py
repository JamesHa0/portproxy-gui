#!/usr/bin/env python3
"""Unit tests for CSV parsing."""

import unittest

from portproxy_common import parse_csv

HEADER = "type,listenaddress,listenport,connectaddress,connectport"


class TestParseCsv(unittest.TestCase):
    def test_empty(self):
        rules, errors = parse_csv("")
        self.assertEqual(rules, [])
        self.assertTrue(errors)

    def test_basic(self):
        text = HEADER + "\nv4tov4,0.0.0.0,8080,192.168.1.100,80\n"
        rules, errors = parse_csv(text)
        self.assertEqual(errors, [])
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0]["listenPort"], "8080")
        self.assertEqual(rules[0]["connectAddress"], "192.168.1.100")

    def test_wrong_header(self):
        text = "foo,bar,baz\nv4tov4,0.0.0.0,8080\n"
        rules, errors = parse_csv(text)
        self.assertEqual(rules, [])
        self.assertTrue(errors)

    def test_reordered_and_extra_columns(self):
        text = "listenport,type,connectaddress,connectport,listenaddress,extra\n" \
               "8080,v4tov4,192.168.1.100,80,0.0.0.0,ignored\n"
        rules, errors = parse_csv(text)
        self.assertEqual(errors, [])
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0]["listenAddress"], "0.0.0.0")
        self.assertEqual(rules[0]["type"], "v4tov4")

    def test_case_insensitive_header(self):
        text = "TYPE,ListenAddress,ListenPort,ConnectAddress,ConnectPort\n" \
               "v4tov4,0.0.0.0,8080,1.2.3.4,80\n"
        rules, errors = parse_csv(text)
        self.assertEqual(errors, [])
        self.assertEqual(len(rules), 1)

    def test_short_row_flagged(self):
        text = HEADER + "\nv4tov4,0.0.0.0,8080\n"
        rules, errors = parse_csv(text)
        self.assertEqual(rules, [])
        self.assertTrue(errors)


if __name__ == "__main__":
    unittest.main()
