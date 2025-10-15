#!/usr/bin/env python3
"""
Port Assignment Encryption Tool

This tool encrypts student port assignment data for secure distribution.
Only administrators with root access should use this tool.

Usage:
    python encrypt_tool.py create v1.0 --input port-assignments.txt
    python encrypt_tool.py update v1.1 --input port-assignments-updated.txt
    python encrypt_tool.py verify student-port-assignments-v1.0.enc
"""

import argparse
import csv
import hashlib
import os
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from datetime import datetime
import json


class PortAssignmentEncryptor:
    """Handles encryption and decryption of port assignment data"""
    
    # System-wide encryption key (in production, this should be more secure)
    ENCRYPTION_KEY = b'multi_student_docker_compose_key_2024_secure_port_assignments'[:32]
    
    def __init__(self):
        self.backend = default_backend()
    
    def encrypt_data(self, data: str) -> bytes:
        """Encrypt string data using AES-256-CBC"""
        # Generate random IV
        iv = os.urandom(16)
        
        # Create cipher
        cipher = Cipher(algorithms.AES(self.ENCRYPTION_KEY), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        
        # Pad data to block size
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data.encode('utf-8'))
        padded_data += padder.finalize()
        
        # Encrypt
        encrypted_data = encryptor.update(padded_data)
        encrypted_data += encryptor.finalize()
        
        # Return IV + encrypted data
        return iv + encrypted_data
    
    def decrypt_data(self, encrypted_data: bytes) -> str:
        """Decrypt encrypted data back to string"""
        # Extract IV and encrypted content
        iv = encrypted_data[:16]
        encrypted_content = encrypted_data[16:]
        
        # Create cipher
        cipher = Cipher(algorithms.AES(self.ENCRYPTION_KEY), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        
        # Decrypt
        padded_data = decryptor.update(encrypted_content)
        padded_data += decryptor.finalize()
        
        # Remove padding
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(padded_data)
        data += unpadder.finalize()
        
        return data.decode('utf-8')


class PortAssignmentValidator:
    """Validates port assignment file format and data"""
    
    @staticmethod
    def validate_port_assignment_file(file_path: str) -> list:
        """
        Validate and parse port assignment file
        Expected format: login_id,segment1_start,segment1_end,segment2_start,segment2_end
        """
        assignments = []
        
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Port assignment file not found: {file_path}")
        
        with open(file_path, 'r') as f:
            reader = csv.reader(f)
            line_num = 0
            
            for row in reader:
                line_num += 1
                
                # Skip comments and empty lines
                if not row or row[0].strip().startswith('#'):
                    continue
                
                # Validate row format
                if len(row) < 3:
                    raise ValueError(f"Line {line_num}: Invalid format. Expected at least 3 columns (login_id,segment1_start,segment1_end)")
                
                login_id = row[0].strip()
                
                # Validate login ID format (case-sensitive, no spaces)
                if not login_id or ' ' in login_id:
                    raise ValueError(f"Line {line_num}: Invalid login ID '{login_id}'. Must be non-empty and contain no spaces.")
                
                try:
                    segment1_start = int(row[1].strip())
                    segment1_end = int(row[2].strip())
                except ValueError:
                    raise ValueError(f"Line {line_num}: Invalid port numbers for segment1. Must be integers.")
                
                # Validate segment1 range
                if segment1_start >= segment1_end:
                    raise ValueError(f"Line {line_num}: segment1_start ({segment1_start}) must be less than segment1_end ({segment1_end})")
                
                if segment1_start < 1024 or segment1_end > 65535:
                    raise ValueError(f"Line {line_num}: Port numbers must be between 1024 and 65535")
                
                # Handle optional segment2
                segment2_start = None
                segment2_end = None
                
                if len(row) >= 5 and row[3].strip() and row[4].strip():
                    try:
                        segment2_start = int(row[3].strip())
                        segment2_end = int(row[4].strip())
                    except ValueError:
                        raise ValueError(f"Line {line_num}: Invalid port numbers for segment2. Must be integers or empty.")
                    
                    # Validate segment2 range
                    if segment2_start >= segment2_end:
                        raise ValueError(f"Line {line_num}: segment2_start ({segment2_start}) must be less than segment2_end ({segment2_end})")
                    
                    if segment2_start < 1024 or segment2_end > 65535:
                        raise ValueError(f"Line {line_num}: Port numbers must be between 1024 and 65535")
                
                assignment = {
                    'login_id': login_id,
                    'segment1_start': segment1_start,
                    'segment1_end': segment1_end,
                    'segment2_start': segment2_start,
                    'segment2_end': segment2_end,
                    'line_number': line_num
                }
                
                assignments.append(assignment)
        
        # Check for duplicate login IDs
        login_ids = [a['login_id'] for a in assignments]
        duplicates = set([x for x in login_ids if login_ids.count(x) > 1])
        if duplicates:
            raise ValueError(f"Duplicate login IDs found: {', '.join(duplicates)}")
        
        # Check for port conflicts
        PortAssignmentValidator.check_port_conflicts(assignments)
        
        return assignments
    
    @staticmethod
    def check_port_conflicts(assignments: list):
        """Check for port range conflicts between students"""
        all_ports = {}  # port -> login_id mapping
        
        for assignment in assignments:
            login_id = assignment['login_id']
            
            # Check segment1 ports
            for port in range(assignment['segment1_start'], assignment['segment1_end'] + 1):
                if port in all_ports:
                    raise ValueError(f"Port conflict: Port {port} assigned to both '{login_id}' and '{all_ports[port]}'")
                all_ports[port] = login_id
            
            # Check segment2 ports if present
            if assignment['segment2_start'] is not None:
                for port in range(assignment['segment2_start'], assignment['segment2_end'] + 1):
                    if port in all_ports:
                        raise ValueError(f"Port conflict: Port {port} assigned to both '{login_id}' and '{all_ports[port]}'")
                    all_ports[port] = login_id


def create_encrypted_file(version: str, input_file: str, output_file: str = None):
    """Create encrypted port assignment file"""
    if not output_file:
        output_file = f"student-port-assignments-{version}.enc"
    
    print(f"Creating encrypted port assignment file version {version}")
    print(f"Input file: {input_file}")
    print(f"Output file: {output_file}")
    
    # Validate input file
    try:
        assignments = PortAssignmentValidator.validate_port_assignment_file(input_file)
        print(f"✅ Validated {len(assignments)} port assignments")
    except Exception as e:
        print(f"❌ Validation failed: {e}")
        return False
    
    # Create metadata
    metadata = {
        'version': version,
        'created_at': datetime.now().isoformat(),
        'total_assignments': len(assignments),
        'assignments': assignments
    }
    
    # Convert to JSON
    json_data = json.dumps(metadata, indent=2)
    
    # Encrypt data
    encryptor = PortAssignmentEncryptor()
    try:
        encrypted_data = encryptor.encrypt_data(json_data)
        
        # Write encrypted file
        with open(output_file, 'wb') as f:
            f.write(encrypted_data)
        
        print(f"✅ Successfully created encrypted file: {output_file}")
        print(f"   Version: {version}")
        print(f"   Students: {len(assignments)}")
        print(f"   File size: {len(encrypted_data)} bytes")
        
        return True
        
    except Exception as e:
        print(f"❌ Encryption failed: {e}")
        return False


def verify_encrypted_file(encrypted_file: str):
    """Verify encrypted port assignment file"""
    print(f"Verifying encrypted file: {encrypted_file}")
    
    if not os.path.exists(encrypted_file):
        print(f"❌ File not found: {encrypted_file}")
        return False
    
    try:
        # Read and decrypt file
        with open(encrypted_file, 'rb') as f:
            encrypted_data = f.read()
        
        encryptor = PortAssignmentEncryptor()
        decrypted_data = encryptor.decrypt_data(encrypted_data)
        
        # Parse JSON
        metadata = json.loads(decrypted_data)
        
        print(f"✅ File verification successful")
        print(f"   Version: {metadata['version']}")
        print(f"   Created: {metadata['created_at']}")
        print(f"   Students: {metadata['total_assignments']}")
        
        # Show sample assignments (first 3)
        assignments = metadata['assignments']
        print(f"\n📋 Sample assignments:")
        for i, assignment in enumerate(assignments[:3]):
            segment1 = f"{assignment['segment1_start']}-{assignment['segment1_end']}"
            segment2 = ""
            if assignment['segment2_start']:
                segment2 = f", {assignment['segment2_start']}-{assignment['segment2_end']}"
            print(f"   {assignment['login_id']}: {segment1}{segment2}")
        
        if len(assignments) > 3:
            print(f"   ... and {len(assignments) - 3} more")
        
        return True
        
    except Exception as e:
        print(f"❌ Verification failed: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Port Assignment Encryption Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python encrypt_tool.py create v1.0 --input port-assignments.txt
  python encrypt_tool.py update v1.1 --input port-assignments-updated.txt  
  python encrypt_tool.py verify student-port-assignments-v1.0.enc

Port Assignment File Format:
  login_id,segment1_start,segment1_end,segment2_start,segment2_end
  
  Examples:
    Emma,4000,4100,8000,8100     # Two segments
    Sue,4901,5100,,              # Single segment
    # Comments start with #
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Create command
    create_parser = subparsers.add_parser('create', help='Create new encrypted file')
    create_parser.add_argument('version', help='Version string (e.g., v1.0)')
    create_parser.add_argument('--input', required=True, help='Input port assignment file')
    create_parser.add_argument('--output', help='Output encrypted file (default: student-port-assignments-{version}.enc)')
    
    # Update command (alias for create)
    update_parser = subparsers.add_parser('update', help='Update encrypted file with new version')
    update_parser.add_argument('version', help='Version string (e.g., v1.1)')
    update_parser.add_argument('--input', required=True, help='Input port assignment file')
    update_parser.add_argument('--output', help='Output encrypted file (default: student-port-assignments-{version}.enc)')
    
    # Verify command
    verify_parser = subparsers.add_parser('verify', help='Verify encrypted file')
    verify_parser.add_argument('file', help='Encrypted file to verify')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    # Check root access (skip on Windows for testing)
    if hasattr(os, 'geteuid') and os.geteuid() != 0:
        print("❌ This tool requires root access for security reasons.")
        print("   Please run with sudo: sudo python encrypt_tool.py ...")
        return 1
    
    if args.command in ['create', 'update']:
        success = create_encrypted_file(args.version, args.input, args.output)
        return 0 if success else 1
    
    elif args.command == 'verify':
        success = verify_encrypted_file(args.file)
        return 0 if success else 1


if __name__ == '__main__':
    sys.exit(main())