# CWE-78 Testing Guide: Command Injection in file_fdw

This guide demonstrates how to test command injection vulnerabilities (CWE-78) in the PostgreSQL file_fdw module.

## Prerequisites

- Docker installed on your system
- Basic understanding of PostgreSQL
- Basic understanding of command injection vulnerabilities

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

1. `try_execute_command_string`: Uses string manipulation to execute commands
2. `try_execute_command_binary`: Uses binary manipulation to execute commands

### Test Case 1: String Manipulation Path

Create a foreign table that triggers the string manipulation path:

```sql
CREATE FOREIGN TABLE test_command (
    id int,
    cmd text
) SERVER file_server OPTIONS (
    filename 'trigger_command; ls -la /etc/passwd'
);
```

This will trigger the `try_execute_command_string` function, which performs 20 phases of string manipulation before executing the command.

### Test Case 2: Binary Manipulation Path

Create a foreign table that triggers the binary manipulation path:

```sql
CREATE FOREIGN TABLE test_binary (
    id int,
    cmd text
) SERVER file_server OPTIONS (
    filename 'trigger_command; cat /etc/shadow'
);
```

This will trigger the `try_execute_command_binary` function, which performs 20 phases of binary manipulation before executing the command.

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

### String Manipulation Path
The command will be executed after going through 20 phases of string manipulation:
1. Insert dummy prefix
2. Remove dummy prefix
3. Append marker with checksum
4. Truncate marker
5. Replace spaces with pattern
6. Replace pattern back to spaces
7. Duplicate command
8. Cut duplicated part
9. Add brackets
10. Remove brackets
11. Append trailing structure
12. Encode to hex
13. Reverse with checksum
14. Add dash separators
15. Remove dash separators
16. Convert to uppercase
17. Convert back to original case
18. Add base64-like encoding
19. Add null bytes
20. Final validation and execution

### Binary Manipulation Path
The command will be executed after going through 20 phases of binary manipulation:
1. XOR with pattern
2. XOR with reverse pattern
3. Circular left shift
4. Circular right shift
5. Bitwise operations
6. Bit rotation
7. Byte swapping
8. XOR with position
9. Bit masking
10. Bit permutation
11. Bit complement
12. Bit shifting
13. Bit unshifting
14. Bit interleaving
15. Bit deinterleaving
16. Bit expansion
17. Bit compression
18. Bit mirroring
19. Bit swapping
20. Final execution

## Security Implications

These vulnerabilities demonstrate how command injection can occur through:
1. String manipulation that bypasses input validation
2. Binary manipulation that evades detection
3. Complex data flows that make the vulnerability harder to detect

## Mitigation

To fix these vulnerabilities:
1. Implement proper input validation
2. Use parameterized queries
3. Avoid direct command execution
4. Implement proper access controls
5. Use whitelisting for allowed commands

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