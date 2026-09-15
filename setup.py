"""
NetGhost Setup and Quick Test Script
Verifies installation and runs basic tests
"""

import sys
import os
import subprocess

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')


def print_header(text):
    """Print a formatted header"""
    print("\n" + "=" * 70)
    print(text.center(70))
    print("=" * 70 + "\n")


def print_step(text):
    """Print a step message"""
    print(f"➤ {text}")


def print_success(text):
    """Print success message"""
    print(f"✓ {text}")


def print_error(text):
    """Print error message"""
    print(f"✗ {text}")


def check_python_version():
    """Check if Python version is compatible"""
    print_step("Checking Python version...")
    version = sys.version_info
    if version.major >= 3 and version.minor >= 8:
        print_success(f"Python {version.major}.{version.minor}.{version.micro}")
        return True
    else:
        print_error(f"Python {version.major}.{version.minor} is too old")
        print("   Required: Python 3.8 or higher")
        return False


def check_dependencies():
    """Check if dependencies are installed"""
    print_step("Checking dependencies...")
    
    required = ['flask', 'scapy', 'cryptography', 'numpy', 'sklearn', 'joblib', 'pytest']
    missing = []
    
    for package in required:
        try:
            if package == 'sklearn':
                __import__('sklearn')
            else:
                __import__(package)
            print_success(f"{package} is installed")
        except ImportError:
            print_error(f"{package} is NOT installed")
            missing.append(package)
    
    if missing:
        print("\n   Install missing packages with:")
        print("   pip install -r requirements.txt\n")
        return False
    
    return True


def test_crypto():
    """Test cryptography module"""
    print_step("Testing cryptography module...")
    try:
        from common.crypto import encrypt_message, decrypt_message
        
        plaintext = "Test message"
        passphrase = "test_password"
        
        encrypted = encrypt_message(plaintext, passphrase)
        decrypted = decrypt_message(encrypted, passphrase)
        
        if decrypted == plaintext:
            print_success("Cryptography module working correctly")
            return True
        else:
            print_error("Decryption mismatch")
            return False
    except Exception as e:
        print_error(f"Crypto test failed: {str(e)}")
        return False


def test_framing():
    """Test framing module"""
    print_step("Testing framing module...")
    try:
        from common.framing import create_frame, parse_frame
        
        payload = b"Test payload"
        frame = create_frame(payload)
        extracted, _ = parse_frame(frame)
        
        if extracted == payload:
            print_success("Framing module working correctly")
            return True
        else:
            print_error("Frame extraction mismatch")
            return False
    except Exception as e:
        print_error(f"Framing test failed: {str(e)}")
        return False


def test_ml():
    """Test ML module"""
    print_step("Testing ML module...")
    try:
        from ml.ml_profiler import TrafficProfiler
        import numpy as np
        
        profiler = TrafficProfiler(n_components=2)
        data = np.random.normal(100, 20, 500)
        data = data[data > 0]
        
        profiler.train_gmm(data)
        samples = profiler.sample_delay(10)
        
        if len(samples) == 10:
            print_success("ML module working correctly")
            return True
        else:
            print_error("ML sampling failed")
            return False
    except Exception as e:
        print_error(f"ML test failed: {str(e)}")
        return False


def create_directories():
    """Create necessary directories"""
    print_step("Creating directories...")
    
    dirs = ['ml/models', 'screenshots']
    
    for dir_path in dirs:
        os.makedirs(dir_path, exist_ok=True)
    
    print_success("Directories created")
    return True


def run_unit_tests():
    """Run pytest unit tests"""
    print_step("Running unit tests...")
    try:
        result = subprocess.run(
            ['pytest', '-v', '--tb=short'],
            capture_output=True,
            text=True
        )
        
        if result.returncode == 0:
            print_success("All unit tests passed")
            return True
        else:
            print_error("Some unit tests failed")
            print(result.stdout)
            return False
    except FileNotFoundError:
        print_error("pytest not found - skipping unit tests")
        return True
    except Exception as e:
        print_error(f"Test execution failed: {str(e)}")
        return False


def check_privileges():
    """Check if running with sufficient privileges"""
    print_step("Checking privileges...")
    
    if os.name == 'nt':  # Windows
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            if is_admin:
                print_success("Running as Administrator")
            else:
                print_error("Not running as Administrator")
                print("   Raw socket operations will require Administrator privileges")
        except:
            print_error("Could not check privileges")
    else:  # Linux/macOS
        if os.geteuid() == 0:
            print_success("Running as root")
        else:
            print_error("Not running as root")
            print("   Raw socket operations will require sudo")
    
    return True


def main():
    """Main setup and test routine"""
    print_header("NETGHOST SETUP AND VERIFICATION")
    
    print("This script will verify your installation and run basic tests.\n")
    
    # Run checks
    checks = [
        ("Python version", check_python_version),
        ("Dependencies", check_dependencies),
        ("Directories", create_directories),
        ("Cryptography", test_crypto),
        ("Framing", test_framing),
        ("ML Module", test_ml),
        ("Privileges", check_privileges),
    ]
    
    results = []
    for name, check_func in checks:
        try:
            result = check_func()
            results.append((name, result))
        except Exception as e:
            print_error(f"Unexpected error in {name}: {str(e)}")
            results.append((name, False))
    
    # Optional: Run unit tests
    print("\n")
    response = input("Run full unit test suite? (y/n): ").lower()
    if response == 'y':
        test_result = run_unit_tests()
        results.append(("Unit Tests", test_result))
    
    # Summary
    print_header("SETUP SUMMARY")
    
    all_passed = True
    for name, result in results:
        if result:
            print_success(f"{name:<20} : PASSED")
        else:
            print_error(f"{name:<20} : FAILED")
            all_passed = False
    
    print("\n")
    
    if all_passed:
        print_header("✓ SETUP COMPLETE - READY TO RUN")
        print("\nNext steps:")
        print("1. Train ML model (optional):")
        print("   python ml/train_model.py --create-synthetic")
        print("\n2. Start receiver (requires sudo/admin):")
        print("   sudo python receiver/receiver_app.py")
        print("\n3. Start sender (requires sudo/admin):")
        print("   sudo python sender/sender_app.py")
        print("\n4. Open browsers:")
        print("   Receiver: http://127.0.0.1:5001")
        print("   Sender: http://127.0.0.1:5000")
    else:
        print_header("⚠ SETUP INCOMPLETE")
        print("\nPlease fix the failed checks above before running the application.")
        print("\nCommon solutions:")
        print("- Install dependencies: pip install -r requirements.txt")
        print("- Use Python 3.8 or higher")
        print("- Run with sudo/admin for packet operations")
    
    print("\n")


if __name__ == "__main__":
    main()
