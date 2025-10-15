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

### scan-usage
Scan actual port usage across all students' dockeredServices directories.

```bash
python admin-cli.py scan-usage
```

**Output:**
```
🔍 Scanning Port Usage Across All Students
==================================================
📁 Found 3 active students
🔌 Total ports used: 15
📊 Total ports allocated: 600
📈 Usage rate: 2.5%

👤 Alex
   📁 Path: /home/Alex/dockeredServices
   📊 Usage: 5/200 ports (2.5%)
   📋 Projects: 2

👤 Emma  
   📁 Path: /home/Emma/dockeredServices
   📊 Usage: 10/202 ports (5.0%)
   📋 Projects: 3
```

**Detailed Report:**
```bash
python admin-cli.py scan-usage --detailed
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

# Check actual port usage
python admin-cli.py scan-usage
```

### Troubleshooting Student Issues
```bash
# Verify student has port assignment
python admin-cli.py check-ports Alex

# List all students to check for conflicts
python admin-cli.py list-students

# Check actual usage vs allocation
python admin-cli.py scan-usage --detailed
```
