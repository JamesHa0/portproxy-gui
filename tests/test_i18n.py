#!/usr/bin/env python3
"""Unit tests for the i18n module."""

import unittest

import i18n
from i18n import tr, set_lang, get_lang, STRINGS


class TestI18n(unittest.TestCase):
    def tearDown(self):
        set_lang("zh")

    def test_default_lang(self):
        self.assertEqual(get_lang(), "zh")

    def test_switch_lang(self):
        set_lang("en")
        self.assertEqual(get_lang(), "en")
        self.assertEqual(tr("status_ok"), "Normal")

    def test_missing_key_returns_key(self):
        self.assertEqual(tr("no_such_key_xyz"), "no_such_key_xyz")

    def test_format_args(self):
        set_lang("zh")
        self.assertEqual(tr("status_rules_count", 5), "共 5 条规则")

    def test_zh_en_key_symmetry(self):
        self.assertEqual(set(STRINGS["zh"].keys()), set(STRINGS["en"].keys()))

    def test_status_keys_present(self):
        for key in ("st_listen_not", "st_occupied", "st_conn_refused",
                    "st_listen_ok", "st_conn_ok"):
            self.assertIn(key, STRINGS["zh"])
            self.assertIn(key, STRINGS["en"])

    def test_version_placeholder(self):
        self.assertIn("{}", STRINGS["zh"]["dlg_about_msg"])


if __name__ == "__main__":
    unittest.main()
