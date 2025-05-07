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
#define MAX_CONNECTIONS 100
#define MAX_CONN_INFO_SIZE 256

typedef struct {
    char client_info[MAX_CONN_INFO_SIZE];
    char client_ip[16];
    char client_port[8];
    time_t connect_time;
    int connection_id;
} ConnectionInfo;

typedef struct {
    ConnectionInfo* connections[MAX_CONNECTIONS];
    int count;
} ConnectionMonitor;

// Global connection monitor
ConnectionMonitor conn_monitor = {0};

// Function to initialize connection monitor
void init_connection_monitor() {
    conn_monitor.count = 0;
    printf("🔌 PostgreSQL Connection Monitor initialized\n");
}

// Function to process connection info
void process_connection_info(ConnectionInfo* info) {
    printf("Processing connection info:\n");
    printf("Connection ID: %d\n", info->connection_id);
    printf("Client IP: %s\n", info->client_ip);
    printf("Client Port: %s\n", info->client_port);
    printf("Connect Time: %ld\n", info->connect_time);
    printf("Client Info: %s\n", info->client_info);
}

// Function to handle connection message
void handle_connection_message(int client_fd) {
    char buffer[BUFFER_SIZE] = {0};
    ConnectionInfo* new_conn = malloc(sizeof(ConnectionInfo));
    if (!new_conn) {
        printf("💥 Memory allocation failed!\n");
        return;
    }

    printf("\n=== New Connection Info ===\n");
    
    // SOURCE: Vulnerable to format string - receiving untrusted input from socket
    ssize_t bytes_read = recv(client_fd, buffer, BUFFER_SIZE - 1, 0);
    if (bytes_read <= 0) {
        printf("❌ Failed to read connection info\n");
        free(new_conn);
        return;
    }

    // Parse connection metadata
    char* conn_id = strtok(buffer, "|");
    char* client_ip = strtok(NULL, "|");
    char* client_port = strtok(NULL, "|");
    char* client_info = strtok(NULL, "|");
    
    if (!conn_id || !client_ip || !client_port || !client_info) {
        printf("❌ Invalid connection info format\n");
        free(new_conn);
        return;
    }

    // Set connection properties
    new_conn->connection_id = atoi(conn_id);
    strncpy(new_conn->client_ip, client_ip, sizeof(new_conn->client_ip) - 1);
    strncpy(new_conn->client_port, client_port, sizeof(new_conn->client_port) - 1);
    new_conn->connect_time = time(NULL);

    // SINK: Vulnerable to format string - no validation of format specifiers
    snprintf(new_conn->client_info, MAX_CONN_INFO_SIZE, client_info);  // VULNERABILITY: Format string injection

    // Add to monitor
    if (conn_monitor.count < MAX_CONNECTIONS) {
        conn_monitor.connections[conn_monitor.count++] = new_conn;
        printf("✅ Connection info added to monitor\n");
        process_connection_info(new_conn);
    } else {
        printf("🚫 Monitor full\n");
        free(new_conn);
    }
}

int main() {
    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    int opt = 1;
    socklen_t client_len = sizeof(client_addr);

    printf("\n🔌 PostgreSQL Connection Monitor v1.0\n");
    printf("================================\n");
    
    init_connection_monitor();

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
    printf("1. Normal connection: echo -e \"1|192.168.1.100|5432|PostgreSQL client\" | nc localhost 8080\n");
    printf("2. Admin connection: echo -e \"2|10.0.0.1|5432|Admin user\" | nc localhost 8080\n");
    printf("3. Error connection: echo -e \"3|127.0.0.1|5432|%x %x %x\" | nc localhost 8080\n");
    printf("\n👂 Listening for connections...\n");

    while(1) {
        // Accept connection
        if ((client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len)) < 0) {
            perror("accept");
            continue;
        }

        // Handle client
        handle_connection_message(client_fd);
        close(client_fd);
    }

    close(server_fd);
    return 0;
}

/*
To test:
1. Compile: gcc -o vuln-cwe134-ex2 plant-vuln-cwe134-ex2.c
2. Run: ./vuln-cwe134-ex2
3. In another terminal, test with:

   # Test 1: Normal connection
   echo -e "1|192.168.1.100|5432|PostgreSQL client" | nc localhost 8080

   # Test 2: Connection with format string
   echo -e "2|10.0.0.1|5432|Client %d connected" | nc localhost 8080

   # Test 3: Connection with malicious format string
   echo -e "3|127.0.0.1|5432|%x %x %x %x %x" | nc localhost 8080

   # Test 4: Connection with format string attack
   echo -e "4|localhost|5432|%n%n%n%n%n" | nc localhost 8080

   # Memory Leak Tests:

   # Test 5: Basic stack address leak
   echo -e "1|192.168.1.100|5432|%x %x %x %x" | nc localhost 8080

   # Test 6: Padded stack address leak
   echo -e "2|10.0.0.1|5432|%08x %08x %08x %08x" | nc localhost 8080

   # Test 7: String leak attempt
   echo -e "3|127.0.0.1|5432|%s %s %s %s" | nc localhost 8080

   # Test 8: Pointer leak
   echo -e "4|localhost|5432|%p %p %p %p" | nc localhost 8080

   # Test 9: Offset pointer leak
   echo -e "5|192.168.1.101|5432|%1$p %2$p %3$p %4$p" | nc localhost 8080

   # Test 10: Binary data leak
   echo -e "6|10.0.0.2|5432|%b %b %b %b" | nc localhost 8080

   # Test 11: Integer leak
   echo -e "7|127.0.0.2|5432|%d %d %d %d" | nc localhost 8080

   # Test 12: Unsigned integer leak
   echo -e "8|192.168.1.102|5432|%u %u %u %u" | nc localhost 8080

   # Test 13: Hexadecimal leak with offset
   echo -e "9|10.0.0.3|5432|%1$x %2$x %3$x %4$x" | nc localhost 8080

   # Test 14: Padded hexadecimal leak
   echo -e "10|127.0.0.3|5432|%08x %08x %08x %08x" | nc localhost 8080

   # Test 15: Right-aligned leak
   echo -e "11|192.168.1.103|5432|%8x %8x %8x %8x" | nc localhost 8080

   # Test 16: Left-aligned leak
   echo -e "12|10.0.0.4|5432|%-8x %-8x %-8x %-8x" | nc localhost 8080

Expected behavior:
- The program will process connection info
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