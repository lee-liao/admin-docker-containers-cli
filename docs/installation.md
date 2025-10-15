# Admin CLI Installation Guide

## Prerequisites

- Python 3.8+
- Access to encrypted port assignment files
- Administrative permissions on the system

## Installation Steps

### 1. Download Admin CLI
```bash
# Clone or download the admin CLI distribution
cd /path/to/admin-cli
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Verify Installation
```bash
python admin-cli.py system-status
```

### 4. Set Permissions
```bash
chmod +x admin-cli.py
```

## Configuration

### Port Assignment File
Ensure student-port-assignments-v1.0.enc is present and accessible.

### Security Settings
The admin CLI includes built-in security validation.

## Troubleshooting

### Common Issues
1. **Import errors**: Ensure all dependencies are installed
2. **Permission errors**: Check file permissions
3. **Encryption errors**: Verify port assignment file integrity

### Getting Help
```bash
python admin-cli.py --help
```
