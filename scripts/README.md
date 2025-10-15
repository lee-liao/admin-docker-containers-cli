# Administrative Tools

This directory contains administrative tools for managing the multi-student Docker Compose system. These tools are **NOT** included in the GitHub repository distributed to students.

## Files

- `encrypt_tool.py` - Port assignment encryption tool (requires root access)
- `port-assignments.txt` - Sample port assignment file
- `test_encryption.py` - Test script for encryption tool
- `requirements.txt` - Python dependencies

## Setup

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Create your port assignment file following the format in `port-assignments.txt`

3. Test the encryption tool:
```bash
python test_encryption.py
```

## Usage

### Create Encrypted Port Assignment File

```bash
sudo python encrypt_tool.py create v1.0 --input port-assignments.txt
```

This creates `student-port-assignments-v1.0.enc` which can be safely distributed to students.

### Update Port Assignments

```bash
sudo python encrypt_tool.py update v1.1 --input port-assignments-updated.txt
```

### Verify Encrypted File

```bash
python encrypt_tool.py verify student-port-assignments-v1.0.enc
```

## Port Assignment File Format

```
# Comments start with #
login_id,segment1_start,segment1_end,segment2_start,segment2_end

# Examples:
Emma,4000,4100,8000,8100     # Two segments
Sue,4901,5100,,              # Single segment (empty segment2)
TestUser,5200,5250,6000,6050 # Non-continuous segments
```

### Rules:
- Login IDs must be exact (case-sensitive)
- Port numbers must be between 1024-65535
- segment1_start < segment1_end
- segment2 is optional (can be empty)
- No port conflicts between students
- No duplicate login IDs

## Security Notes

- The encryption tool requires root access for security
- The encryption key is embedded in the tool (change for production)
- Encrypted files can be safely distributed to students
- Students cannot decrypt other students' port assignments

## Distribution

1. Create encrypted port assignment file
2. Copy encrypted file to project root for GitHub distribution
3. **Never** commit admin/ directory to GitHub
4. Use `.gitignore` to exclude admin tools from student repository