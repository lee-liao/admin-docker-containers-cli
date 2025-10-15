# Admin CLI Commands Reference

## Student Management Commands

### list-students
List all students and their port assignments.

```bash
python admin-cli.py list-students
```

**Output:**
```
📋 Student Port Assignments
==================================================
👤 Alex
   Ports: 4401-4407
   Total: 7 ports

👤 Lee  
   Ports: 4501-4507
   Total: 7 ports
```

### check-ports
Check specific student's port assignment details.

```bash
python admin-cli.py check-ports Alex
```

**Output:**
```
🔍 Port Assignment for Alex
========================================
Segment 1: 4401-4407
Total Ports: 7
All Ports: 4401, 4402, 4403, 4404, 4405, 4406, 4407
```

## System Administration Commands

### system-status
Show overall system status and statistics.

```bash
python admin-cli.py system-status
```

**Output:**
```
📊 Multi-Student Docker System Status
=============================================
👥 Total Students: 25
🔌 Total Ports Assigned: 175
📋 Assignment Version: 1.0
🕒 System Time: 2024-10-14 15:30:45
```

### security-check
Run comprehensive system security validation.

```bash
python admin-cli.py security-check
```

## Usage Examples

### Daily Admin Tasks
```bash
# Morning system check
python admin-cli.py system-status

# Check specific student issue
python admin-cli.py check-ports StudentName

# Weekly security audit
python admin-cli.py security-check
```

### Troubleshooting Student Issues
```bash
# Verify student has port assignment
python admin-cli.py check-ports Alex

# List all students to check for conflicts
python admin-cli.py list-students
```
