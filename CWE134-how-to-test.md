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
4. Netcat or similar tool for socket testing

## Example 1: Simple Format String Vulnerability

This example demonstrates a basic format string vulnerability where user input from a socket is directly passed to a format string function after minimal processing.

### Test Steps

1. Start a netcat listener on port 8080:
```bash
nc -l 8080
```

2. Connect to your PostgreSQL database:
```sql
psql -d your_database
```

3. Create the xml2 extension if not already created:
```sql
CREATE EXTENSION xml2;
```

4. Test the vulnerability using the xpath_nodeset function:
```sql
SELECT xpath_nodeset(
    '<root>test</root>',
    '%n%s%x',  -- format string injection
    'tag',
    'sep'
);
```

5. In the netcat window, send the format string payload:
```
%n%s%x
```

The format string `%n%s%x` will:
- `%n`: Write the number of characters written so far to a memory location
- `%s`: Read a string from the stack
- `%x`: Print a hexadecimal value from the stack

### Expected Behavior

The function will:
1. Read the format string from the socket
2. Remove any trailing whitespace
3. Pass the input directly to printf()
4. May crash the PostgreSQL process or leak memory contents

## Example 2: Cross-function Format String Vulnerability

This example demonstrates a more complex format string vulnerability where user input passes through multiple transformation functions before reaching the vulnerable sink.

### Test Steps

1. Start a netcat listener on port 8081:
```bash
nc -l 8081
```

2. Connect to your PostgreSQL database:
```sql
psql -d your_database
```

3. Test the vulnerability using the xpath_nodeset function with XML content:
```sql
SELECT xpath_nodeset(
    '<root>test</root>',
    E'<script>alert(1)</script>',  -- XML injection attempt
    'tag',
    'sep'
);
```

4. In the netcat window, send the format string payload:
```
%n%s%x
```

The input will go through three transformations:
1. XML character sanitization (`<` → `[`, `>` → `]`, `&` → `+`)
2. XPath query preparation (wrapping in namespace)
3. Special character encoding (escaping single quotes)

### Expected Behavior

The function will:
1. Read the format string from the socket
2. Process it through multiple transformation functions
3. Pass the processed input to fprintf()
4. May crash the PostgreSQL process or leak memory contents

## Security Implications

These examples demonstrate:
1. Unsafe handling of user input in format strings
2. Lack of input validation
3. Potential for memory corruption
4. Information disclosure risks
5. Cross-function data flow vulnerabilities

## Mitigation

To prevent these vulnerabilities:
1. Always validate and sanitize user input
2. Use format string functions with proper format specifiers
3. Implement proper input validation for XML and XPath processing
4. Use parameterized queries instead of direct string concatenation
5. Avoid passing user input directly to format string functions

## Note

These examples are for educational purposes only. Do not use them in production environments. 