# Admin CLI for Multi-Student Docker Environment

Administrative tools for managing multi-student Docker container environments.

## 🚀 Quick Start

### Installation
```bash
# Install dependencies
pip install -r requirements.txt

# Make CLI executable
chmod +x admin-cli.py
```

### Basic Usage
```bash
# List all students and their port assignments
python admin-cli.py list-students

# Check specific student's ports
python admin-cli.py check-ports Alex

# Show system status
python admin-cli.py system-status

# Run security validation
python admin-cli.py security-check

# Scan actual port usage
python admin-cli.py scan-usage

# Detailed usage report
python admin-cli.py scan-usage --detailed
```

## 📋 Available Commands

### Student Management
- **list-students** - List all students and their port assignments
- **check-ports <student_id>** - Check specific student's port assignment

### System Administration  
- **system-status** - Show overall system status and statistics
- **security-check** - Run system security validation
- **scan-usage** - Scan actual port usage across all students

## 🔧 Admin Tools

### Port Assignment Management
- View all student port assignments
- Validate port ranges and conflicts
- Check individual student allocations

### Security Validation
- System security checks
- File permission validation
- Docker access verification

### System Monitoring
- Overall system status
- Student activity overview
- Resource utilization

## 📁 Directory Structure

```
admin-docker-containers-cli/
├── admin-cli.py                    # Main admin CLI tool
├── requirements.txt                # Python dependencies
├── student-port-assignments-v1.0.enc  # Encrypted port data
├── admin-tools/
│   └── src/                       # Admin utility modules
├── scripts/                       # Additional admin scripts
└── docs/                         # Admin documentation
```

## 🔒 Security

- Port assignments are encrypted
- Admin tools require appropriate permissions
- Security validation built-in

## 📚 Documentation

- [Installation Guide](docs/installation.md)
- [Admin Commands](docs/commands.md)
- [Security Guide](docs/security.md)

## 🆘 Support

For administrative issues:
1. Check system status: python admin-cli.py system-status
2. Run security check: python admin-cli.py security-check
3. Review logs in system directories

---

**Version**: 1.0.0  
**For Administrators**: Manage multi-student Docker environments  
**Security**: Encrypted port assignments and validation
