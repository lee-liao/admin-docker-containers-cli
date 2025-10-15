#!/usr/bin/env python3
"""
Admin CLI for Multi-Student Docker Environment
Provides administrative tools for managing student Docker containers
Self-contained version with minimal dependencies
"""

import os
import sys
import argparse
import json
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class SimplePortAssignmentManager:
    """Simple port assignment manager for admin CLI"""
    
    def __init__(self):
        self.assignments = []
        # Must match the key used in encrypt_tool.py and CLI tool
        self.encryption_key = b'multi_student_docker_compose_key_2024_secure_port_assignments'[:32]
        self.backend = default_backend()
        
    def load_assignments(self):
        """Load encrypted port assignments"""
        try:
            # Find the encrypted file
            enc_files = [f for f in os.listdir('.') if f.startswith('student-port-assignments-') and f.endswith('.enc')]
            if not enc_files:
                print("No encrypted port assignment file found")
                return False
                
            # Use the latest version
            enc_file = sorted(enc_files)[-1]
            
            with open(enc_file, 'rb') as f:
                encrypted_data = f.read()
                
            # Decrypt the data using AES-CBC (same as encrypt_tool.py)
            # First 16 bytes are the IV
            iv = encrypted_data[:16]
            ciphertext = encrypted_data[16:]
            
            # Create cipher
            cipher = Cipher(algorithms.AES(self.encryption_key), modes.CBC(iv), backend=self.backend)
            decryptor = cipher.decryptor()
            
            # Decrypt and remove padding
            padded_data = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Remove PKCS7 padding
            padding_length = padded_data[-1]
            decrypted_data = padded_data[:-padding_length]
            
            # Parse the JSON data
            json_data = json.loads(decrypted_data.decode('utf-8'))
            self.assignments = []
            self.version = json_data.get('version', '1.0')
            
            # Extract assignments from JSON structure
            for assignment_data in json_data.get('assignments', []):
                try:
                    assignment = SimpleAssignment(
                        login_id=assignment_data['login_id'],
                        segment1_start=assignment_data['segment1_start'],
                        segment1_end=assignment_data['segment1_end'],
                        segment2_start=assignment_data.get('segment2_start'),
                        segment2_end=assignment_data.get('segment2_end')
                    )
                    self.assignments.append(assignment)
                except (KeyError, ValueError) as e:
                    print(f"Warning: Skipping invalid assignment: {assignment_data} ({e})")
                    continue
            
            return True
            
        except Exception as e:
            print(f"Error loading port assignments: {e}")
            return False
    
    def list_all_assignments(self):
        """Return all assignments"""
        return self.assignments
        
    def get_student_assignment(self, student_id):
        """Get assignment for specific student"""
        for assignment in self.assignments:
            if assignment.login_id == student_id:
                return assignment
        raise Exception(f"Student '{student_id}' not found in assignments")
        
    def get_metadata(self):
        """Get metadata about assignments"""
        return {
            'version': getattr(self, 'version', '1.0'),
            'total_students': len(self.assignments),
            'loaded': True
        }

class SimpleAssignment:
    """Simple assignment class"""
    
    def __init__(self, login_id, segment1_start, segment1_end, segment2_start=None, segment2_end=None):
        self.login_id = login_id
        self.segment1_start = segment1_start
        self.segment1_end = segment1_end
        self.segment2_start = segment2_start
        self.segment2_end = segment2_end
        
    @property
    def has_two_segments(self):
        return self.segment2_start is not None and self.segment2_end is not None
        
    @property
    def total_ports(self):
        count = self.segment1_end - self.segment1_start + 1
        if self.has_two_segments:
            count += self.segment2_end - self.segment2_start + 1
        return count
        
    @property
    def all_ports(self):
        ports = list(range(self.segment1_start, self.segment1_end + 1))
        if self.has_two_segments:
            ports.extend(list(range(self.segment2_start, self.segment2_end + 1)))
        return ports

class AdminCLI:
    """Main admin CLI class"""
    
    def __init__(self):
        self.port_manager = SimplePortAssignmentManager()
    
    def load_port_assignments(self):
        """Load encrypted port assignments"""
        try:
            return self.port_manager.load_assignments()
        except Exception as e:
            print(f"Error loading port assignments: {e}")
            return False
    
    def list_students(self):
        """List all students and their port assignments"""
        if not self.load_port_assignments():
            return
        
        print("\n📋 Student Port Assignments")
        print("=" * 50)
        
        assignments = self.port_manager.list_all_assignments()
        for assignment in sorted(assignments, key=lambda x: x.login_id):
            print(f"👤 {assignment.login_id}")
            print(f"   Ports: {assignment.segment1_start}-{assignment.segment1_end}")
            if assignment.has_two_segments:
                print(f"          {assignment.segment2_start}-{assignment.segment2_end}")
            print(f"   Total: {assignment.total_ports} ports")
            print()
    
    def check_student_ports(self, student_id):
        """Check specific student's port assignment"""
        if not self.load_port_assignments():
            return
        
        try:
            assignment = self.port_manager.get_student_assignment(student_id)
            print(f"\n🔍 Port Assignment for {student_id}")
            print("=" * 40)
            print(f"Segment 1: {assignment.segment1_start}-{assignment.segment1_end}")
            if assignment.has_two_segments:
                print(f"Segment 2: {assignment.segment2_start}-{assignment.segment2_end}")
            print(f"Total Ports: {assignment.total_ports}")
            print(f"All Ports: {', '.join(map(str, assignment.all_ports))}")
        except Exception as e:
            print(f"Error: {e}")
    
    def validate_system_security(self):
        """Run system security validation"""
        print("\n🔒 Running System Security Validation")
        print("=" * 40)
        
        try:
            # Basic security checks
            checks = [
                ("Port assignment file exists", self._check_port_file()),
                ("Port assignment file readable", self._check_port_file_readable()),
                ("Python dependencies available", self._check_dependencies()),
            ]
            
            for check_name, result in checks:
                status = "✓" if result else "✗"
                print(f"{status} {check_name}")
                
            print("\n✓ Security validation completed")
            
        except Exception as e:
            print(f"Error during security validation: {e}")
            
    def _check_port_file(self):
        """Check if port assignment file exists"""
        enc_files = [f for f in os.listdir('.') if f.startswith('student-port-assignments-') and f.endswith('.enc')]
        return len(enc_files) > 0
        
    def _check_port_file_readable(self):
        """Check if port assignment file is readable"""
        try:
            return self.port_manager.load_assignments()
        except:
            return False
            
    def _check_dependencies(self):
        """Check if required dependencies are available"""
        try:
            import cryptography
            return True
        except ImportError:
            return False
    
    def show_system_status(self):
        """Show overall system status"""
        print("\n📊 Multi-Student Docker System Status")
        print("=" * 45)
        
        if self.load_port_assignments():
            assignments = self.port_manager.list_all_assignments()
            print(f"👥 Total Students: {len(assignments)}")
            
            total_ports = sum(a.total_ports for a in assignments)
            print(f"🔌 Total Ports Assigned: {total_ports}")
            
            metadata = self.port_manager.get_metadata()
            if metadata.get('version'):
                print(f"📋 Assignment Version: {metadata['version']}")
        
        print(f"🕒 System Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    def run(self):
        """Main CLI entry point"""
        parser = argparse.ArgumentParser(
            description="Admin CLI for Multi-Student Docker Environment",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  %(prog)s list-students              # List all students and ports
  %(prog)s check-ports Alex           # Check Alex's port assignment
  %(prog)s system-status              # Show system overview
  %(prog)s security-check             # Run security validation
            """
        )
        
        subparsers = parser.add_subparsers(dest='command', help='Available commands')
        
        # List students command
        subparsers.add_parser('list-students', help='List all students and their port assignments')
        
        # Check ports command
        check_parser = subparsers.add_parser('check-ports', help='Check specific student port assignment')
        check_parser.add_argument('student_id', help='Student login ID')
        
        # System status command
        subparsers.add_parser('system-status', help='Show system status overview')
        
        # Security check command
        subparsers.add_parser('security-check', help='Run system security validation')
        
        args = parser.parse_args()
        
        if not args.command:
            parser.print_help()
            return
        
        try:
            if args.command == 'list-students':
                self.list_students()
            elif args.command == 'check-ports':
                self.check_student_ports(args.student_id)
            elif args.command == 'system-status':
                self.show_system_status()
            elif args.command == 'security-check':
                self.validate_system_security()
        except Exception as e:
            if "not found" in str(e).lower():
                print(f"Error: {e}")
            else:
                print(f"CLI Error: {e}")
        except KeyboardInterrupt:
            print("\n\nOperation cancelled by user")
        except Exception as e:
            print(f"Unexpected error: {e}")
            sys.exit(1)

if __name__ == "__main__":
    cli = AdminCLI()
    cli.run()
