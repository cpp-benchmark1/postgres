#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <arpa/inet.h>

#define PORT 8080
#define BUFFER_SIZE 1024
#define MAX_QUERIES 50
#define MAX_QUERY_SIZE 512

typedef struct {
    char query[MAX_QUERY_SIZE];
    char user[32];
    char database[32];
    time_t timestamp;
    int execution_time;
} QueryStats;

typedef struct {
    QueryStats* queries[MAX_QUERIES];
    int count;
} QueryMonitor;

// Global query monitor
QueryMonitor query_monitor = {0};

// Function to initialize query monitor
void init_query_monitor() {
    query_monitor.count = 0;
    printf("📊 PostgreSQL Query Monitor initialized\n");
}

// Function to process query stats
void process_query_stats(QueryStats* stats) {
    printf("Processing query stats:\n");
    printf("User: %s\n", stats->user);
    printf("Database: %s\n", stats->database);
    printf("Timestamp: %ld\n", stats->timestamp);
    printf("Execution time: %d ms\n", stats->execution_time);
    printf("Query: %s\n", stats->query);
}

// Function to handle query message
void handle_query_message(int client_fd) {
    char buffer[BUFFER_SIZE] = {0};
    QueryStats* new_stats = malloc(sizeof(QueryStats));
    if (!new_stats) {
        printf("💥 Memory allocation failed!\n");
        return;
    }

    printf("\n=== New Query Stats ===\n");
    
    // SOURCE: Vulnerable to format string - receiving untrusted input from socket
    ssize_t bytes_read = read(client_fd, buffer, BUFFER_SIZE - 1);
    if (bytes_read <= 0) {
        printf("❌ Failed to read query stats\n");
        free(new_stats);
        return;
    }

    // Parse query metadata
    char* user = strtok(buffer, "|");
    char* database = strtok(NULL, "|");
    char* exec_time = strtok(NULL, "|");
    char* query = strtok(NULL, "|");
    
    if (!user || !database || !exec_time || !query) {
        printf("❌ Invalid query stats format\n");
        free(new_stats);
        return;
    }

    // Set query properties
    strncpy(new_stats->user, user, sizeof(new_stats->user) - 1);
    strncpy(new_stats->database, database, sizeof(new_stats->database) - 1);
    new_stats->timestamp = time(NULL);
    new_stats->execution_time = atoi(exec_time);

    // SINK: Vulnerable to format string - no validation of format specifiers
    snprintf(new_stats->query, MAX_QUERY_SIZE, query);  // VULNERABILITY: Format string injection

    // Add to monitor
    if (query_monitor.count < MAX_QUERIES) {
        query_monitor.queries[query_monitor.count++] = new_stats;
        printf("✅ Query stats added to monitor\n");
        process_query_stats(new_stats);
    } else {
        printf("🚫 Monitor full\n");
        free(new_stats);
    }
}

int main() {
    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    int opt = 1;
    socklen_t client_len = sizeof(client_addr);

    printf("\n📊 PostgreSQL Query Monitor v1.0\n");
    printf("===========================\n");
    
    init_query_monitor();

    // Create socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Set socket options
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    // Configure server address
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    // Bind socket
    if (bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    // Listen for connections
    if (listen(server_fd, 3) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    printf("\n✅ Server Ready\n");
    printf("==============\n");
    printf("\n📝 Test Commands:\n");
    printf("1. Normal query: echo -e \"postgres|mydb|100|SELECT * FROM users\" | nc localhost 8080\n");
    printf("2. Slow query: echo -e \"admin|prod|5000|SELECT * FROM large_table\" | nc localhost 8080\n");
    printf("3. Error query: echo -e \"user|test|50|SELECT %x FROM %x\" | nc localhost 8080\n");
    printf("\n👂 Listening for connections...\n");

    while(1) {
        // Accept connection
        if ((client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len)) < 0) {
            perror("accept");
            continue;
        }

        // Handle client
        handle_query_message(client_fd);
        close(client_fd);
    }

    close(server_fd);
    return 0;
}

/*
To test:
1. Compile: gcc -o vuln-cwe134-ex1 plant-vuln-cwe134-ex1.c
2. Run: ./vuln-cwe134-ex1
3. In another terminal, test with:

   # Test 1: Normal query
   echo -e "postgres|mydb|100|SELECT * FROM users" | nc localhost 8080

   # Test 2: Query with format string
   echo -e "admin|prod|5000|SELECT %d rows FROM table" | nc localhost 8080

   # Test 3: Query with malicious format string
   echo -e "user|test|50|SELECT %x FROM %x WHERE %x" | nc localhost 8080

   # Test 4: Query with format string attack
   echo -e "root|master|10|%n%n%n%n%n" | nc localhost 8080

   # Memory Leak Tests:

   # Test 5: Basic stack address leak
   echo -e "postgres|mydb|100|SELECT %x %x %x %x FROM users" | nc localhost 8080

   # Test 6: Padded stack address leak
   echo -e "postgres|mydb|100|SELECT %08x %08x %08x %08x FROM users" | nc localhost 8080

   # Test 7: String leak attempt
   echo -e "postgres|mydb|100|SELECT %s %s %s %s FROM users" | nc localhost 8080

   # Test 8: Pointer leak
   echo -e "postgres|mydb|100|SELECT %p %p %p %p FROM users" | nc localhost 8080

   # Test 9: Offset pointer leak
   echo -e "postgres|mydb|100|SELECT %1$p %2$p %3$p %4$p FROM users" | nc localhost 8080

   # Test 10: Binary data leak
   echo -e "postgres|mydb|100|SELECT %b %b %b %b FROM users" | nc localhost 8080

   # Test 11: Integer leak
   echo -e "postgres|mydb|100|SELECT %d %d %d %d FROM users" | nc localhost 8080

   # Test 12: Unsigned integer leak
   echo -e "postgres|mydb|100|SELECT %u %u %u %u FROM users" | nc localhost 8080

   # Test 13: Hexadecimal leak with offset
   echo -e "postgres|mydb|100|SELECT %1$x %2$x %3$x %4$x FROM users" | nc localhost 8080

   # Test 14: Padded hexadecimal leak
   echo -e "postgres|mydb|100|SELECT %08x %08x %08x %08x FROM users" | nc localhost 8080

   # Test 15: Right-aligned leak
   echo -e "postgres|mydb|100|SELECT %8x %8x %8x %8x FROM users" | nc localhost 8080

   # Test 16: Left-aligned leak
   echo -e "postgres|mydb|100|SELECT %-8x %-8x %-8x %-8x FROM users" | nc localhost 8080

Expected behavior:
- The program will process query stats
- Format string vulnerabilities will leak memory
- The program may crash with malicious format strings
- Memory corruption is possible

Note: This code is for educational purposes only.
DO NOT use in production environments.
The vulnerabilities demonstrated here can lead to:
- Memory leaks
- Information disclosure
- Program crashes
- Potential code execution
*/ 