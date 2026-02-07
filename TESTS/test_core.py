"""
ETHICAL Malware Analysis Toolkit (E-MAT)
Unit Tests for Core Modules

Tests hashing, PE/ELF analysis, string extraction, and YARA scanning
"""

import unittest
import sys
import tempfile
import os
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from CORE_ENGINE.utils.hashing import calculate_hashes, calculate_entropy, detect_file_type
from CORE_ENGINE.utils.safety_checker import SafetyChecker
from CORE_ENGINE.config.preferences import PreferencesManager


class TestHashing(unittest.TestCase):
    """Test hashing utilities"""
    
    def setUp(self):
        """Create a temporary test file"""
        self.test_file = tempfile.NamedTemporaryFile(mode='w', delete=False)
        self.test_file.write("This is a test file for E-MAT\n" * 100)
        self.test_file.close()
    
    def tearDown(self):
        """Clean up test file"""
        if os.path.exists(self.test_file.name):
            os.remove(self.test_file.name)
    
    def test_calculate_hashes(self):
        """Test hash calculation"""
        hashes = calculate_hashes(self.test_file.name)
        
        self.assertIn('md5', hashes)
        self.assertIn('sha256', hashes)
        self.assertEqual(len(hashes['md5']), 32)
        self.assertEqual(len(hashes['sha256']), 64)
    
    def test_calculate_entropy(self):
        """Test entropy calculation"""
        entropy = calculate_entropy(self.test_file.name)
        
        self.assertIsInstance(entropy, float)
        self.assertGreaterEqual(entropy, 0.0)
        self.assertLessEqual(entropy, 8.0)
    
    def test_detect_file_type(self):
        """Test file type detection"""
        file_type, description = detect_file_type(self.test_file.name)
        
        self.assertIsInstance(file_type, str)
        self.assertIsInstance(description, str)


class TestSafetyChecker(unittest.TestCase):
    """Test safety checker module"""
    
    def setUp(self):
        """Initialize safety checker"""
        self.checker = SafetyChecker()
        
        # Create test file
        self.test_file = tempfile.NamedTemporaryFile(mode='w', delete=False)
        self.test_file.write("Test content")
        self.test_file.close()
    
    def tearDown(self):
        """Clean up"""
        if os.path.exists(self.test_file.name):
            os.remove(self.test_file.name)
    
    def test_check_file_safety_valid(self):
        """Test file safety check with valid file"""
        is_safe, msg = self.checker.check_file_safety(self.test_file.name)
        
        self.assertTrue(is_safe)
        self.assertIsNone(msg)
    
    def test_check_file_safety_nonexistent(self):
        """Test file safety check with nonexistent file"""
        is_safe, msg = self.checker.check_file_safety("/nonexistent/file.txt")
        
        self.assertFalse(is_safe)
        self.assertIn("not found", msg.lower())
    
    def test_check_sandbox_safety_no_flag(self):
        """Test sandbox safety without explicit flag"""
        is_safe, msg = self.checker.check_sandbox_safety(False, True)
        
        self.assertFalse(is_safe)
        self.assertIn("explicit consent", msg.lower())
    
    def test_check_sandbox_safety_no_docker(self):
        """Test sandbox safety without Docker"""
        is_safe, msg = self.checker.check_sandbox_safety(True, False)
        
        self.assertFalse(is_safe)
        self.assertIn("docker", msg.lower())
    
    def test_check_sandbox_safety_valid(self):
        """Test sandbox safety with all requirements"""
        is_safe, msg = self.checker.check_sandbox_safety(True, True)
        
        self.assertTrue(is_safe)
        self.assertIsNone(msg)
    
    def test_validate_docker_config(self):
        """Test Docker configuration validation"""
        # Valid config
        is_safe, msg = self.checker.validate_docker_config("none")
        self.assertTrue(is_safe)
        
        # Invalid config
        is_safe, msg = self.checker.validate_docker_config("bridge")
        self.assertFalse(is_safe)
        self.assertIn("isolation", msg.lower())


class TestPreferencesManager(unittest.TestCase):
    """Test preferences manager"""
    
    def setUp(self):
        """Initialize preferences manager with temp config"""
        self.prefs = PreferencesManager()
        # Save original config path
        self.original_config = self.prefs.config_file
        # Use temp config for testing
        self.temp_config = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
        self.temp_config.close()
        self.prefs.config_file = Path(self.temp_config.name)
    
    def tearDown(self):
        """Clean up temp config"""
        if os.path.exists(self.temp_config.name):
            os.remove(self.temp_config.name)
    
    def test_set_preferred_component(self):
        """Test setting preferred component"""
        self.prefs.set_preferred_component('cli')
        self.assertEqual(self.prefs.get_preferred_component(), 'cli')
        
        self.prefs.set_preferred_component('desktop')
        self.assertEqual(self.prefs.get_preferred_component(), 'desktop')
    
    def test_first_run_detection(self):
        """Test first run detection"""
        # Should be first run initially
        self.assertTrue(self.prefs.is_first_run())
        
        # Mark as complete
        self.prefs.mark_first_run_complete()
        
        # Should no longer be first run
        self.assertFalse(self.prefs.is_first_run())
    
    def test_docker_availability(self):
        """Test Docker availability setting"""
        self.prefs.set_docker_available(True)
        self.assertTrue(self.prefs.is_docker_available())
        
        self.prefs.set_docker_available(False)
        self.assertFalse(self.prefs.is_docker_available())


class TestStringAnalyzer(unittest.TestCase):
    """Test string analyzer"""
    
    def setUp(self):
        """Create test file with various strings"""
        self.test_file = tempfile.NamedTemporaryFile(mode='wb', delete=False)
        
        # Write test strings
        test_data = b"""
        This is a test file
        http://example.com/test
        192.168.1.1
        C:\\Windows\\System32\\cmd.exe
        password123
        admin@example.com
        """
        
        self.test_file.write(test_data)
        self.test_file.close()
    
    def tearDown(self):
        """Clean up"""
        if os.path.exists(self.test_file.name):
            os.remove(self.test_file.name)
    
    def test_string_extraction(self):
        """Test string extraction"""
        from CORE_ENGINE.analyzers.static.string_analyzer import StringAnalyzer
        
        analyzer = StringAnalyzer(self.test_file.name)
        result = analyzer.analyze()
        
        self.assertIn('total_count', result)
        self.assertGreater(result['total_count'], 0)
        
        # Check categories
        categories = result.get('categories', {})
        self.assertIn('urls', categories)
        self.assertIn('ips', categories)
        self.assertIn('file_paths', categories)


def run_tests():
    """Run all tests"""
    print("="*70)
    print("E-MAT Unit Tests")
    print("="*70)
    print("\n[#] Testing ETHICAL Malware Analysis Toolkit components\n")
    
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add test classes
    suite.addTests(loader.loadTestsFromTestCase(TestHashing))
    suite.addTests(loader.loadTestsFromTestCase(TestSafetyChecker))
    suite.addTests(loader.loadTestsFromTestCase(TestPreferencesManager))
    suite.addTests(loader.loadTestsFromTestCase(TestStringAnalyzer))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    print("\n" + "="*70)
    print("Test Summary")
    print("="*70)
    print(f"Tests run: {result.testsRun}")
    print(f"Successes: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print("="*70 + "\n")
    
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
