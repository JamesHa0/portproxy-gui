#!/usr/bin/env python3
"""Unit tests for shared helpers: normalization, dedup, import, decode, firewall naming."""

import unittest
from unittest import mock

from portproxy_common import (
    normalize_addr, find_duplicate, import_rules, _decode, fw_rule_name,
    rules_to_csv_text, parse_csv,
)


def _rule(rtype="v4tov4", la="0.0.0.0", lp="8080", ca="1.2.3.4", cp="80"):
    return {
        "type": rtype, "listenAddress": la, "listenPort": lp,
        "connectAddress": ca, "connectPort": cp,
    }


class TestNormalizeAddr(unittest.TestCase):
    def test_wildcard_forms_equivalent(self):
        self.assertEqual(normalize_addr(""), "0.0.0.0")
        self.assertEqual(normalize_addr("*"), "0.0.0.0")
        self.assertEqual(normalize_addr("0.0.0.0"), "0.0.0.0")

    def test_specific_preserved(self):
        self.assertEqual(normalize_addr("192.168.1.1"), "192.168.1.1")
        self.assertEqual(normalize_addr("::1"), "::1")


class TestFindDuplicate(unittest.TestCase):
    def test_no_duplicate(self):
        rules = [_rule(la="127.0.0.1", lp="80")]
        self.assertIsNone(find_duplicate(rules, "v4tov4", "0.0.0.0", "8080"))

    def test_duplicate_wildcard_normalized(self):
        rules = [_rule(la="*", lp="8080")]
        dup = find_duplicate(rules, "v4tov4", "0.0.0.0", "8080")
        self.assertIsNotNone(dup)

    def test_exclude_skips_edited_rule(self):
        rules = [_rule(la="0.0.0.0", lp="8080")]
        # Editing the rule at 0.0.0.0:8080 → same point should be excluded.
        self.assertIsNone(
            find_duplicate(rules, "v4tov4", "0.0.0.0", "8080",
                           exclude=("v4tov4", "0.0.0.0", "8080")))

    def test_exclude_does_not_hide_other_rule(self):
        rules = [_rule(la="0.0.0.0", lp="8080"), _rule(la="127.0.0.1", lp="8080")]
        dup = find_duplicate(rules, "v4tov4", "127.0.0.1", "8080",
                             exclude=("v4tov4", "0.0.0.0", "8080"))
        self.assertIsNotNone(dup)


class TestImportRules(unittest.TestCase):
    def test_list_rules_called_once(self):
        with mock.patch("portproxy_common.list_rules", return_value=[]) as lst, \
             mock.patch("portproxy_common.do_netsh"):
            import_rules([_rule(), _rule(lp="8081"), _rule(lp="8082")])
        self.assertEqual(lst.call_count, 1)

    def test_invalid_type_skipped(self):
        with mock.patch("portproxy_common.list_rules", return_value=[]), \
             mock.patch("portproxy_common.do_netsh") as dn:
            added, skipped = import_rules([_rule(rtype="v9tov9")])
        self.assertEqual(added, [])
        self.assertEqual(len(skipped), 1)
        dn.assert_not_called()

    def test_duplicate_skipped(self):
        existing = [_rule(la="*", lp="8080")]
        with mock.patch("portproxy_common.list_rules", return_value=existing), \
             mock.patch("portproxy_common.do_netsh") as dn:
            added, skipped = import_rules([_rule(la="0.0.0.0", lp="8080")])
        self.assertEqual(added, [])
        self.assertEqual(len(skipped), 1)
        dn.assert_not_called()

    def test_valid_rule_added(self):
        with mock.patch("portproxy_common.list_rules", return_value=[]), \
             mock.patch("portproxy_common.do_netsh") as dn:
            added, skipped = import_rules([_rule()])
        self.assertEqual(len(added), 1)
        self.assertEqual(skipped, [])
        dn.assert_called_once()


class TestDecode(unittest.TestCase):
    def test_gbk(self):
        self.assertEqual(_decode("端口".encode("gbk")), "端口")

    def test_utf8(self):
        self.assertEqual(_decode("规则".encode("utf-8")), "规则")

    def test_empty(self):
        self.assertEqual(_decode(b""), "")


class TestCsvRoundTrip(unittest.TestCase):
    def test_round_trip(self):
        rules = [_rule(), _rule(rtype="v6tov4", la="::", lp="443", ca="10.0.0.1", cp="8443")]
        text = rules_to_csv_text(rules)
        parsed, errors = parse_csv(text)
        self.assertEqual(errors, [])
        self.assertEqual(len(parsed), 2)
        self.assertEqual(parsed[0]["listenPort"], "8080")
        self.assertEqual(parsed[1]["type"], "v6tov4")


class TestFwRuleName(unittest.TestCase):
    def test_includes_address(self):
        name = fw_rule_name("v4tov4", "0.0.0.0", "8080")
        self.assertEqual(name, "PortProxy_v4tov4_0_0_0_0_8080")

    def test_wildcard_normalized(self):
        self.assertEqual(fw_rule_name("v4tov4", "*", "80"),
                         fw_rule_name("v4tov4", "0.0.0.0", "80"))


if __name__ == "__main__":
    unittest.main()
