"""
RevLab Comprehensive Unit Tests
"""
import unittest
import os
import sys

# Add root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from tests.generate_samples import generate_all_samples
from revlab.parsers.loader import load_binary
from revlab.parsers.common import BinaryFormat, Architecture
from revlab.analysis.hashes import calculate_hashes
from revlab.analysis.entropy import calculate_shannon_entropy
from revlab.analysis.strings import extract_strings
from revlab.analysis.yara_engine import scan_yara
from revlab.analysis.deobfuscation import deobfuscate_strings
from revlab.analysis.resources import analyze_resources_and_rich
from revlab.analysis.cfg_web import generate_web_cfg_html

class TestRevLabProfessional(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.pe_path, cls.elf_path = generate_all_samples()

    def test_load_pe_binary(self):
        bin_obj = load_binary(self.pe_path)
        self.assertEqual(bin_obj.file_format, BinaryFormat.PE)
        self.assertEqual(bin_obj.architecture, Architecture.X64)

    def test_yara_scanner(self):
        bin_obj = load_binary(self.pe_path)
        matches = scan_yara(bin_obj)
        self.assertIsInstance(matches, list)

    def test_deobfuscation_engine(self):
        bin_obj = load_binary(self.pe_path)
        deob = deobfuscate_strings(bin_obj)
        self.assertIn("total_deobfuscated", deob)

    def test_resources_and_rich_header(self):
        bin_obj = load_binary(self.pe_path)
        res = analyze_resources_and_rich(bin_obj)
        self.assertIn("rich_header", res)
        self.assertIn("resources", res)

    def test_web_cfg_generation(self):
        bin_obj = load_binary(self.pe_path)
        html = generate_web_cfg_html(bin_obj)
        self.assertIn("vis-network", html)
        self.assertIn("mynetwork", html)

if __name__ == "__main__":
    unittest.main()
