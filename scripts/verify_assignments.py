#!/usr/bin/env python3
"""
Administrative Verification Tools

Tools for administrators to verify port assignments, detect conflicts,
and generate reports about the port allocation system.
"""

import argparse
import json
import os
import sys
from collections import defaultdict
from typing import Dict, List, Set, Tuple

# Import from CLI tool (add path)
import os
cli_tool_path = os.path.join(os.path.dirname(__file__), '..', 'cli-tool')
sys.path.insert(0, cli_tool_path)
from port_assignment import PortAssignmentManager, PortAssignment


class PortAssignmentVerifier:
    """Administrative tools for verifying port assignments"""
    
    def __init__(self, encrypted_file: str = None):
        """Initialize verifier with encrypted port assignment file"""
        self.manager = PortAssignmentManager(encrypted_file)
        self.manager.load_assignments()
    
    def verify_file_integrity(self) -> bool:
        """
        Verify encrypted file integrity and basic validation
        
        Returns:
            True if file is valid, False otherwise
        """
        print("🔍 Verifying Port Assignment File Integrity")
        print("=" * 50)
        
        try:
            metadata = self.manager.get_metadata()
            assignments = self.manager.list_all_assignments()
            
            print(f"✅ File loaded successfully")
            print(f"   Version: {metadata['version']}")
            print(f"   Created: {metadata['created_at']}")
            print(f"   Expected assignments: {metadata['total_assignments']}")
            print(f"   Actual assignments: {len(assignments)}")
            
            if len(assignments) != metadata['total_assignments']:
                print(f"❌ Assignment count mismatch!")
                return False
            
            # Verify each assignment
            for assignment in assignments:
                if not self._validate_assignment(assignment):
                    return False
            
            print(f"✅ All {len(assignments)} assignments are valid")
            return True
            
        except Exception as e:
            print(f"❌ File integrity check failed: {e}")
            return False
    
    def _validate_assignment(self, assignment: PortAssignment) -> bool:
        """Validate a single port assignment"""
        # Check login ID format
        if not assignment.login_id or ' ' in assignment.login_id:
            print(f"❌ Invalid login ID: '{assignment.login_id}'")
            return False
        
        # Check port ranges
        if assignment.segment1_start >= assignment.segment1_end:
            print(f"❌ Invalid segment1 range for {assignment.login_id}: {assignment.segment1_start}-{assignment.segment1_end}")
            return False
        
        if assignment.has_two_segments:
            if assignment.segment2_start >= assignment.segment2_end:
                print(f"❌ Invalid segment2 range for {assignment.login_id}: {assignment.segment2_start}-{assignment.segment2_end}")
                return False
        
        # Check port number bounds
        all_ports = assignment.all_ports
        if any(port < 1024 or port > 65535 for port in all_ports):
            print(f"❌ Port numbers out of range (1024-65535) for {assignment.login_id}")
            return False
        
        return True
    
    def detect_port_conflicts(self) -> Dict[int, List[str]]:
        """
        Detect port conflicts across all student assignments
        
        Returns:
            Dictionary mapping conflicted ports to list of students using them
        """
        print("\n🔍 Detecting Port Conflicts")
        print("=" * 30)
        
        port_usage = defaultdict(list)
        assignments = self.manager.list_all_assignments()
        
        # Build port usage map
        for assignment in assignments:
            for port in assignment.all_ports:
                port_usage[port].append(assignment.login_id)
        
        # Find conflicts
        conflicts = {port: users for port, users in port_usage.items() if len(users) > 1}
        
        if conflicts:
            print(f"❌ Found {len(conflicts)} port conflicts:")
            for port, users in conflicts.items():
                print(f"   Port {port}: {', '.join(users)}")
        else:
            print("✅ No port conflicts detected")
        
        return conflicts
    
    def generate_allocation_report(self) -> Dict:
        """
        Generate comprehensive port allocation report
        
        Returns:
            Dictionary with allocation statistics and details
        """
        print("\n📊 Port Allocation Report")
        print("=" * 30)
        
        assignments = self.manager.list_all_assignments()
        metadata = self.manager.get_metadata()
        
        # Calculate statistics
        total_students = len(assignments)
        total_ports_allocated = sum(a.total_ports for a in assignments)
        
        single_segment_count = sum(1 for a in assignments if not a.has_two_segments)
        dual_segment_count = sum(1 for a in assignments if a.has_two_segments)
        
        port_distribution = [a.total_ports for a in assignments]
        min_ports = min(port_distribution) if port_distribution else 0
        max_ports = max(port_distribution) if port_distribution else 0
        avg_ports = sum(port_distribution) / len(port_distribution) if port_distribution else 0
        
        # Port range analysis
        all_ports = set()
        for assignment in assignments:
            all_ports.update(assignment.all_ports)
        
        port_ranges = self._analyze_port_ranges(all_ports)
        
        report = {
            'metadata': metadata,
            'statistics': {
                'total_students': total_students,
                'total_ports_allocated': total_ports_allocated,
                'single_segment_assignments': single_segment_count,
                'dual_segment_assignments': dual_segment_count,
                'min_ports_per_student': min_ports,
                'max_ports_per_student': max_ports,
                'avg_ports_per_student': round(avg_ports, 1)
            },
            'port_ranges': port_ranges,
            'assignments': [
                {
                    'login_id': a.login_id,
                    'segment1': f"{a.segment1_start}-{a.segment1_end}",
                    'segment2': f"{a.segment2_start}-{a.segment2_end}" if a.has_two_segments else None,
                    'total_ports': a.total_ports,
                    'is_continuous': a.is_continuous
                }
                for a in sorted(assignments, key=lambda x: x.login_id)
            ]
        }
        
        # Print summary
        print(f"📈 Summary:")
        print(f"   Total students: {total_students}")
        print(f"   Total ports allocated: {total_ports_allocated}")
        print(f"   Single segment assignments: {single_segment_count}")
        print(f"   Dual segment assignments: {dual_segment_count}")
        print(f"   Port range: {min_ports}-{max_ports} per student (avg: {avg_ports:.1f})")
        print(f"   Port number range: {min(all_ports)}-{max(all_ports)}")
        
        return report
    
    def _analyze_port_ranges(self, all_ports: Set[int]) -> Dict:
        """Analyze port number distribution"""
        if not all_ports:
            return {}
        
        sorted_ports = sorted(all_ports)
        
        # Find gaps in port allocation
        gaps = []
        for i in range(len(sorted_ports) - 1):
            current = sorted_ports[i]
            next_port = sorted_ports[i + 1]
            if next_port - current > 1:
                gap_start = current + 1
                gap_end = next_port - 1
                gap_size = gap_end - gap_start + 1
                gaps.append({
                    'start': gap_start,
                    'end': gap_end,
                    'size': gap_size
                })
        
        return {
            'min_port': min(all_ports),
            'max_port': max(all_ports),
            'total_unique_ports': len(all_ports),
            'gaps': gaps,
            'largest_gap': max(gaps, key=lambda x: x['size']) if gaps else None
        }
    
    def validate_case_sensitivity(self) -> List[str]:
        """
        Check for potential case sensitivity issues in login IDs
        
        Returns:
            List of potential case sensitivity issues
        """
        print("\n🔍 Checking Case Sensitivity Issues")
        print("=" * 40)
        
        assignments = self.manager.list_all_assignments()
        login_ids = [a.login_id for a in assignments]
        
        issues = []
        
        # Check for potential case conflicts
        lowercase_map = defaultdict(list)
        for login_id in login_ids:
            lowercase_map[login_id.lower()].append(login_id)
        
        for lowercase, variants in lowercase_map.items():
            if len(variants) > 1:
                issues.append(f"Potential case conflict: {', '.join(variants)}")
        
        # Check naming convention (should start with uppercase)
        non_uppercase = [login_id for login_id in login_ids if not login_id[0].isupper()]
        if non_uppercase:
            issues.append(f"Login IDs not following uppercase convention: {', '.join(non_uppercase)}")
        
        if issues:
            print("⚠️  Case sensitivity issues found:")
            for issue in issues:
                print(f"   {issue}")
        else:
            print("✅ No case sensitivity issues detected")
            print(f"   All {len(login_ids)} login IDs follow proper case convention")
        
        return issues
    
    def export_report(self, output_file: str, format: str = 'json') -> bool:
        """
        Export verification report to file
        
        Args:
            output_file: Output file path
            format: Export format ('json' or 'txt')
            
        Returns:
            True if successful
        """
        try:
            report = self.generate_allocation_report()
            conflicts = self.detect_port_conflicts()
            case_issues = self.validate_case_sensitivity()
            
            full_report = {
                'verification_timestamp': self.manager.get_metadata().get('created_at'),
                'allocation_report': report,
                'port_conflicts': {str(port): users for port, users in conflicts.items()},
                'case_sensitivity_issues': case_issues,
                'summary': {
                    'file_valid': len(conflicts) == 0 and len(case_issues) == 0,
                    'total_conflicts': len(conflicts),
                    'total_case_issues': len(case_issues)
                }
            }
            
            if format.lower() == 'json':
                with open(output_file, 'w') as f:
                    json.dump(full_report, f, indent=2)
            else:  # txt format
                with open(output_file, 'w') as f:
                    f.write("Port Assignment Verification Report\n")
                    f.write("=" * 40 + "\n\n")
                    f.write(f"File Version: {report['metadata']['version']}\n")
                    f.write(f"Created: {report['metadata']['created_at']}\n")
                    f.write(f"Total Students: {report['statistics']['total_students']}\n")
                    f.write(f"Total Ports: {report['statistics']['total_ports_allocated']}\n\n")
                    
                    if conflicts:
                        f.write("PORT CONFLICTS:\n")
                        for port, users in conflicts.items():
                            f.write(f"  Port {port}: {', '.join(users)}\n")
                        f.write("\n")
                    
                    if case_issues:
                        f.write("CASE SENSITIVITY ISSUES:\n")
                        for issue in case_issues:
                            f.write(f"  {issue}\n")
                        f.write("\n")
                    
                    f.write("STUDENT ASSIGNMENTS:\n")
                    for assignment in report['assignments']:
                        segment2_info = f", {assignment['segment2']}" if assignment['segment2'] else ""
                        f.write(f"  {assignment['login_id']}: {assignment['segment1']}{segment2_info} ({assignment['total_ports']} ports)\n")
            
            print(f"\n📄 Report exported to: {output_file}")
            return True
            
        except Exception as e:
            print(f"❌ Failed to export report: {e}")
            return False


def main():
    parser = argparse.ArgumentParser(
        description="Administrative Port Assignment Verification Tools",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python verify_assignments.py --file student-port-assignments-v1.0.enc
  python verify_assignments.py --conflicts-only
  python verify_assignments.py --report --export report.json
  python verify_assignments.py --full-check --export full-report.txt --format txt
        """
    )
    
    parser.add_argument('--file', help='Encrypted port assignment file (auto-detects if not specified)')
    parser.add_argument('--conflicts-only', action='store_true', help='Only check for port conflicts')
    parser.add_argument('--report', action='store_true', help='Generate allocation report')
    parser.add_argument('--case-check', action='store_true', help='Check case sensitivity issues')
    parser.add_argument('--full-check', action='store_true', help='Run all verification checks')
    parser.add_argument('--export', help='Export report to file')
    parser.add_argument('--format', choices=['json', 'txt'], default='json', help='Export format')
    
    args = parser.parse_args()
    
    if not any([args.conflicts_only, args.report, args.case_check, args.full_check]):
        args.full_check = True  # Default to full check
    
    try:
        verifier = PortAssignmentVerifier(args.file)
        
        success = True
        
        if args.full_check or not any([args.conflicts_only, args.report, args.case_check]):
            # Run all checks
            success &= verifier.verify_file_integrity()
            conflicts = verifier.detect_port_conflicts()
            case_issues = verifier.validate_case_sensitivity()
            report = verifier.generate_allocation_report()
            
            success &= len(conflicts) == 0 and len(case_issues) == 0
            
        else:
            # Run specific checks
            if args.conflicts_only:
                conflicts = verifier.detect_port_conflicts()
                success &= len(conflicts) == 0
            
            if args.case_check:
                case_issues = verifier.validate_case_sensitivity()
                success &= len(case_issues) == 0
            
            if args.report:
                verifier.generate_allocation_report()
        
        # Export report if requested
        if args.export:
            verifier.export_report(args.export, args.format)
        
        if success:
            print("\n✅ All verification checks passed!")
            return 0
        else:
            print("\n❌ Some verification checks failed!")
            return 1
            
    except Exception as e:
        print(f"❌ Verification failed: {e}")
        return 1


if __name__ == '__main__':
    sys.exit(main())