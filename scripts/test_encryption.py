#!/usr/bin/env python3
"""
Test script for the encryption tool
Run this to verify the encryption tool works correctly
"""

import os
import sys
import subprocess
import tempfile

def run_command(cmd):
    """Run command and return success status"""
    print(f"Running: {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        print(f"✅ Success: {result.stdout.strip()}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed: {e.stderr.strip()}")
        return False

def test_encryption_tool():
    """Test the encryption tool functionality"""
    print("🧪 Testing Port Assignment Encryption Tool")
    print("=" * 50)
    
    # Test 1: Create encrypted file
    print("\n1. Testing file creation...")
    success = run_command([
        sys.executable, "encrypt_tool.py", "create", "v1.0", 
        "--input", "port-assignments.txt"
    ])
    
    if not success:
        print("❌ Test failed: Could not create encrypted file")
        return False
    
    # Test 2: Verify encrypted file
    print("\n2. Testing file verification...")
    success = run_command([
        sys.executable, "encrypt_tool.py", "verify", 
        "student-port-assignments-v1.0.enc"
    ])
    
    if not success:
        print("❌ Test failed: Could not verify encrypted file")
        return False
    
    # Test 3: Test with invalid input
    print("\n3. Testing error handling...")
    
    # Create invalid port assignment file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        f.write("Emma,4000,3999,,\n")  # Invalid range (start > end)
        invalid_file = f.name
    
    try:
        success = run_command([
            sys.executable, "encrypt_tool.py", "create", "v1.1",
            "--input", invalid_file
        ])
        
        if success:
            print("❌ Test failed: Should have rejected invalid port range")
            return False
        else:
            print("✅ Correctly rejected invalid input")
    finally:
        os.unlink(invalid_file)
    
    print("\n🎉 All tests passed!")
    print("\nGenerated files:")
    print("  - student-port-assignments-v1.0.enc (encrypted port data)")
    
    return True

if __name__ == '__main__':
    # Change to admin directory
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    
    # Check if we have the required files
    if not os.path.exists('encrypt_tool.py'):
        print("❌ encrypt_tool.py not found")
        sys.exit(1)
    
    if not os.path.exists('port-assignments.txt'):
        print("❌ port-assignments.txt not found")
        sys.exit(1)
    
    # Run tests
    success = test_encryption_tool()
    sys.exit(0 if success else 1)