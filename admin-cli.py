#!/usr/bin/env python3
"""
Admin CLI for Multi-Student Docker Environment
Provides administrative tools for managing student Docker containers
"""

import os
import sys
import argparse
import json
from datetime import datetime
from dataclasses import dataclass, field
from typing import List, Optional, Tuple, Dict
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

@dataclass
class PortAssignment:
    """Represents a student's port assignment with flexible segments"""
    
    login_id: str
    segment1_start: int
    segment1_end: int
    segment2_start: Optional[int] = None
    segment2_end: Optional[int] = None
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    
    @property
    def segment1_range(self) -> range:
        """Get segment1 as a range object"""
        return range(self.segment1_start, self.segment1_end + 1)
    
    @property
    def segment2_range(self) -> Optional[range]:
        """Get segment2 as a range object (None if not assigned)"""
        if self.segment2_start is not None and self.segment2_end is not None:
            return range(self.segment2_start, self.segment2_end + 1)
        return None
    
    @property
    def all_ports(self) -> List[int]:
        """Get all assigned ports as a flat sorted list"""
        ports = list(self.segment1_range)
        if self.segment2_range:
            ports.extend(list(self.segment2_range))
        return sorted(ports)
    
    @property
    def total_ports(self) -> int:
        """Get total number of assigned ports"""
        count = len(self.segment1_range)
        if self.segment2_range:
            count += len(self.segment2_range)
        return count
    
    @property
    def has_two_segments(self) -> bool:
        """Check if this assignment has two segments"""
        return self.segment2_start is not None and self.segment2_end is not None

class PortAssignmentDecryptor:
    """Handles decryption of encrypted port assignment files"""
    
    # Must match the key used in encrypt_tool.py
    ENCRYPTION_KEY = b'multi_student_docker_compose_key_2024_secure_port_assignments'[:32]
    
    def __init__(self):
        self.backend = default_backend()
    
    def decrypt_data(self, encrypted_data: bytes) -> str:
        """Decrypt encrypted data back to string"""
        try:
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
            
        except Exception as e:
            raise ValueError(f"Failed to decrypt port assignment data: {e}")

class PortAssignmentManager:
    """Manages port assignments for students"""
    
    def __init__(self, encrypted_file_path: str = None):
        """Initialize port assignment manager"""
        self.encrypted_file_path = encrypted_file_path
        self.assignments: Dict[str, PortAssignment] = {}
        self.metadata: Dict = {}
        self._loaded = False
    
    def find_latest_encrypted_file(self, search_dir: str = ".") -> Optional[str]:
        """Find the latest version of encrypted port assignment file"""
        import glob
        import re
        
        # Search for encrypted files
        pattern = os.path.join(search_dir, "student-port-assignments-v*.enc")
        files = glob.glob(pattern)
        
        if not files:
            return None
        
        # Extract version numbers and sort
        version_files = []
        for file_path in files:
            filename = os.path.basename(file_path)
            match = re.search(r'v(\d+)\.(\d+)', filename)
            if match:
                major, minor = int(match.group(1)), int(match.group(2))
                version_files.append((major, minor, file_path))
        
        if not version_files:
            return None
        
        # Sort by version (highest first)
        version_files.sort(key=lambda x: (x[0], x[1]), reverse=True)
        return version_files[0][2]
    
    def load_assignments(self) -> bool:
        """Load port assignments from encrypted file"""
        if self._loaded:
            return True
        
        # Auto-detect encrypted file if not specified
        if not self.encrypted_file_path:
            self.encrypted_file_path = self.find_latest_encrypted_file()
            if not self.encrypted_file_path:
                raise FileNotFoundError(
                    "No encrypted port assignment file found. "
                    "Expected file like 'student-port-assignments-v1.0.enc'"
                )
        
        if not os.path.exists(self.encrypted_file_path):
            raise FileNotFoundError(f"Encrypted port assignment file not found: {self.encrypted_file_path}")
        
        try:
            # Read encrypted file
            with open(self.encrypted_file_path, 'rb') as f:
                encrypted_data = f.read()
            
            # Decrypt data
            decryptor = PortAssignmentDecryptor()
            decrypted_data = decryptor.decrypt_data(encrypted_data)
            
            # Parse JSON
            data = json.loads(decrypted_data)
            self.metadata = {
                'version': data.get('version'),
                'created_at': data.get('created_at'),
                'total_assignments': data.get('total_assignments')
            }
            
            # Parse assignments
            self.assignments = {}
            for assignment_data in data.get('assignments', []):
                assignment = PortAssignment(
                    login_id=assignment_data['login_id'],
                    segment1_start=assignment_data['segment1_start'],
                    segment1_end=assignment_data['segment1_end'],
                    segment2_start=assignment_data.get('segment2_start'),
                    segment2_end=assignment_data.get('segment2_end')
                )
                self.assignments[assignment.login_id] = assignment
            
            self._loaded = True
            return True
            
        except Exception as e:
            raise RuntimeError(f"Failed to load port assignments: {e}")
    
    def get_student_assignment(self, login_id: str) -> PortAssignment:
        """Get complete port assignment for a student"""
        if not self._loaded:
            self.load_assignments()
        
        if login_id in self.assignments:
            return self.assignments[login_id]
        else:
            # Provide helpful error message for case sensitivity
            similar_ids = [uid for uid in self.assignments.keys() if uid.lower() == login_id.lower()]
            if similar_ids:
                raise ValueError(
                    f"Login ID '{login_id}' not found. Did you mean '{similar_ids[0]}'? "
                    f"Note: Login IDs are case-sensitive."
                )
            else:
                raise ValueError(f"Login ID '{login_id}' not authorized")
    
    def list_all_assignments(self) -> List[PortAssignment]:
        """Get list of all port assignments"""
        if not self._loaded:
            self.load_assignments()
        
        return list(self.assignments.values())
    
    def get_metadata(self) -> Dict:
        """Get metadata about the port assignment file"""
        if not self._loaded:
            self.load_assignments()
        
        return self.metadata.copy()

class AdminCLI:
    """Main admin CLI class"""
    
    def __init__(self):
        self.port_manager = None
    
    def load_port_assignments(self):
        """Load encrypted port assignments"""
        try:
            self.port_manager = PortAssignmentManager()
            self.port_manager.load_assignments()
            return True
        except Exception as e:
            print(f"❌ Error loading port assignments: {e}")
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
        
        print(f"📊 Summary: {len(assignments)} students, {sum(a.total_ports for a in assignments)} total ports")
    
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
            
            # Show service mapping for common template (7 ports)
            if assignment.total_ports >= 7:
                ports = assignment.all_ports[:7]
                services = ['PostgreSQL', 'MongoDB', 'Redis', 'ChromaDB', 'Jaeger UI', 'Prometheus', 'Grafana']
                print(f"\nService Mapping:")
                for i, (port, service) in enumerate(zip(ports, services)):
                    print(f"  {service}: {port}")
                    
        except Exception as e:
            print(f"❌ Error: {e}")
    
    def show_system_status(self):
        """Show overall system status"""
        print("\n📊 Multi-Student Docker System Status")
        print("=" * 45)
        
        if self.load_port_assignments():
            assignments = self.port_manager.list_all_assignments()
            print(f"👥 Total Students: {len(assignments)}")
            
            total_ports = sum(a.total_ports for a in assignments)
            print(f"🔌 Total Ports Assigned: {total_ports}")
            
            # Port range analysis
            if assignments:
                all_ports = []
                for a in assignments:
                    all_ports.extend(a.all_ports)
                
                print(f"📈 Port Range: {min(all_ports)} - {max(all_ports)}")
                
                # Check for overlaps (shouldn't happen but good to verify)
                port_counts = {}
                for port in all_ports:
                    port_counts[port] = port_counts.get(port, 0) + 1
                
                conflicts = [port for port, count in port_counts.items() if count > 1]
                if conflicts:
                    print(f"⚠️  Port Conflicts: {conflicts}")
                else:
                    print("✅ No Port Conflicts")
            
            metadata = self.port_manager.get_metadata()
            if metadata.get('version'):
                print(f"📋 Assignment Version: {metadata['version']}")
            if metadata.get('created_at'):
                print(f"📅 Created: {metadata['created_at']}")
        
        print(f"🕒 System Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    def find_student_by_port(self, port):
        """Find which student is assigned a specific port"""
        if not self.load_port_assignments():
            return
        
        try:
            port = int(port)
            assignments = self.port_manager.list_all_assignments()
            
            for assignment in assignments:
                if port in assignment.all_ports:
                    print(f"\n🔍 Port {port} is assigned to: {assignment.login_id}")
                    print(f"   Port range: {assignment.segment1_start}-{assignment.segment1_end}")
                    if assignment.has_two_segments:
                        print(f"                {assignment.segment2_start}-{assignment.segment2_end}")
                    return
            
            print(f"\n❌ Port {port} is not assigned to any student")
            
        except ValueError:
            print(f"❌ Invalid port number: {port}")
        except Exception as e:
            print(f"❌ Error: {e}")
    
    def run(self):
        """Main CLI entry point"""
        parser = argparse.ArgumentParser(
            description="Admin CLI for Multi-Student Docker Environment",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  %(prog)s list-students              # List all students and ports
  %(prog)s check-ports Alex           # Check Alex's port assignment
  %(prog)s find-port 4501             # Find who owns port 4501
  %(prog)s system-status              # Show system overview
            """
        )
        
        subparsers = parser.add_subparsers(dest='command', help='Available commands')
        
        # List students command
        subparsers.add_parser('list-students', help='List all students and their port assignments')
        
        # Check ports command
        check_parser = subparsers.add_parser('check-ports', help='Check specific student port assignment')
        check_parser.add_argument('student_id', help='Student login ID')
        
        # Find port command
        find_parser = subparsers.add_parser('find-port', help='Find which student owns a specific port')
        find_parser.add_argument('port', help='Port number to search for')
        
        # System status command
        subparsers.add_parser('system-status', help='Show system status overview')
        
        args = parser.parse_args()
        
        if not args.command:
            parser.print_help()
            return
        
        try:
            if args.command == 'list-students':
                self.list_students()
            elif args.command == 'check-ports':
                self.check_student_ports(args.student_id)
            elif args.command == 'find-port':
                self.find_student_by_port(args.port)
            elif args.command == 'system-status':
                self.show_system_status()
        except KeyboardInterrupt:
            print("\n\n⚠️  Operation cancelled by user")
        except Exception as e:
            print(f"❌ Unexpected error: {e}")
            sys.exit(1)

if __name__ == "__main__":
    cli = AdminCLI()
    cli.run()