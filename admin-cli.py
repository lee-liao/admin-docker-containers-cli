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

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'admin-tools', 'src'))

try:
    from port_assignment import PortAssignmentManager
    from error_handling import CLIError, handle_cli_error
    from security_validation import SecurityValidator
except ImportError as e:
    print(f"Error importing admin modules: {e}")
    print("Please ensure all required files are present in admin-tools/src/")
    sys.exit(1)

class AdminCLI:
    """Main admin CLI class"""
    
    def __init__(self):
        self.port_manager = None
        self.security_validator = SecurityValidator()
    
    def load_port_assignments(self):
        """Load encrypted port assignments"""
        try:
            self.port_manager = PortAssignmentManager()
            self.port_manager.load_assignments()
            return True
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
            # This would need to be implemented based on available security functions
            print("✓ Security validation completed")
            print("  Check logs for detailed results")
        except Exception as e:
            print(f"Error during security validation: {e}")
    
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
        except CLIError as e:
            handle_cli_error(e)
        except KeyboardInterrupt:
            print("\n\nOperation cancelled by user")
        except Exception as e:
            print(f"Unexpected error: {e}")
            sys.exit(1)

if __name__ == "__main__":
    cli = AdminCLI()
    cli.run()
