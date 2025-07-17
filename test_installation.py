#!/usr/bin/env python3
"""
Test Installation Script
Verifies that all dependencies are properly installed
"""

import sys
import importlib

def test_import(module_name, package_name=None):
    """Test if a module can be imported"""
    try:
        importlib.import_module(module_name)
        print(f"✅ {package_name or module_name} - OK")
        return True
    except ImportError as e:
        print(f"❌ {package_name or module_name} - FAILED: {e}")
        return False

def test_scapy_functionality():
    """Test basic Scapy functionality"""
    try:
        from scapy.all import sniff, IP, TCP, UDP
        from scapy.arch import get_if_list
        
        # Test interface listing
        interfaces = get_if_list()
        print(f"✅ Scapy interfaces - Found {len(interfaces)} interfaces")
        
        # Test basic packet creation
        from scapy.all import IP, TCP
        packet = IP(dst="8.8.8.8")/TCP(dport=80)
        print(f"✅ Scapy packet creation - OK")
        
        return True
    except Exception as e:
        print(f"❌ Scapy functionality test - FAILED: {e}")
        return False

def test_tkinter():
    """Test Tkinter availability"""
    try:
        import tkinter as tk
        root = tk.Tk()
        root.destroy()
        print("✅ Tkinter - OK")
        return True
    except Exception as e:
        print(f"❌ Tkinter - FAILED: {e}")
        return False

def main():
    print("Network Sniffer - Installation Test")
    print("=" * 50)
    
    # Test Python version
    python_version = sys.version_info
    if python_version.major >= 3 and python_version.minor >= 7:
        print(f"✅ Python {python_version.major}.{python_version.minor}.{python_version.micro} - OK")
    else:
        print(f"❌ Python {python_version.major}.{python_version.minor}.{python_version.micro} - Requires Python 3.7+")
        return False
    
    print()
    
    # Test required modules
    all_ok = True
    
    # Core modules
    all_ok &= test_import("scapy", "Scapy")
    all_ok &= test_import("argparse", "argparse")
    all_ok &= test_import("json", "json")
    all_ok &= test_import("datetime", "datetime")
    all_ok &= test_import("threading", "threading")
    all_ok &= test_import("queue", "queue")
    
    print()
    
    # Test optional modules
    print("Optional modules:")
    test_tkinter()  # GUI support
    
    print()
    
    # Test Scapy functionality
    print("Scapy functionality test:")
    all_ok &= test_scapy_functionality()
    
    print()
    print("=" * 50)
    
    if all_ok:
        print("🎉 All tests passed! Your installation is ready.")
        print("\nYou can now run:")
        print("  python sniffer.py -l                    # List interfaces")
        print("  python sniffer.py -c 10                 # Capture 10 packets")
        print("  python sniffer_gui.py                   # Launch GUI")
        print("  python examples/simple_sniffer.py       # Run simple example")
    else:
        print("❌ Some tests failed. Please check the errors above.")
        print("\nTo fix installation issues:")
        print("  pip install -r requirements.txt")
        print("  # On Windows, run as Administrator")
        print("  # On Linux/macOS, use sudo")
    
    return all_ok

if __name__ == "__main__":
    main() 