#!/usr/bin/env python3
"""Pytest configuration: make the repo root importable for tests/."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
