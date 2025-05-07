#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <time.h>

#define PORT 8080
#define BUFFER_SIZE 1024
#define MAX_COMPRESSED 100
#define MAX_CHUNK_SIZE 1024*1024  // 1MB

typedef struct {
    char* data;
    size_t original_size;
    size_t compressed_size;
    char algorithm[16];
    time_t timestamp;
} CompressedData;

typedef struct {
    CompressedData* chunks[MAX_COMPRESSED];
    int count;
} CompressionCache;

// Global compression cache
CompressionCache cache = {0};

// Function to initialize compression cache
void init_cache() {
    cache.count = 0;
    printf("🗜️ Compression Cache initialized\n");
}

// Function to process compressed data
void process_compressed_data(CompressedData* data) {
    printf("Processing compressed data:\n");
    printf("Original size: %zu bytes\n", data->original_size);
    printf("Compressed size: %zu bytes\n", data->compressed_size);
    printf("Algorithm: %s\n", data->algorithm);
    printf("Timestamp: %ld\n", data->timestamp);
}

// Function to handle data compression
void handle_compression(int socket_fd) {
    char buffer[BUFFER_SIZE] = {0};
    CompressedData* new_data = malloc(sizeof(CompressedData));
    if (!new_data) {
        printf("💥 Memory allocation failed!\n");
        return;
    }

    printf("\n=== New Compression Request ===\n");
    
    // SOURCE: Vulnerable to heap overflow - receiving untrusted input from socket
    ssize_t bytes_read = recv(socket_fd, buffer, BUFFER_SIZE - 1, 0);
    if (bytes_read <= 0) {
        printf("❌ Failed to read compression request\n");
        free(new_data);
        return;
    }

    // Parse compression metadata
    char* algorithm = strtok(buffer, "|");
    char* size_str = strtok(NULL, "|");
    
    if (!algorithm || !size_str) {
        printf("❌ Invalid compression format\n");
        free(new_data);
        return;
    }

    // SINK: Vulnerable to heap overflow - no size validation before allocation
    size_t data_size = atoi(size_str);
    new_data->data = malloc(data_size);  // VULNERABILITY: No size validation
    if (!new_data->data) {
        printf("💥 Failed to allocate data buffer\n");
        free(new_data);
        return;
    }

    // Read compressed data
    bytes_read = recv(socket_fd, new_data->data, data_size, 0);
    if (bytes_read <= 0) {
        printf("❌ Failed to read compressed data\n");
        free(new_data->data);
        free(new_data);
        return;
    }

    // Set compression properties
    strncpy(new_data->algorithm, algorithm, sizeof(new_data->algorithm) - 1);
    new_data->original_size = data_size;
    new_data->compressed_size = bytes_read;
    new_data->timestamp = time(NULL);

    // Add to cache
    if (cache.count < MAX_COMPRESSED) {
        cache.chunks[cache.count++] = new_data;
        printf("✅ Compressed data added to cache\n");
        process_compressed_data(new_data);
    } else {
        printf("🚫 Cache full\n");
        free(new_data->data);
        free(new_data);
    }
}

int main() {
    int server_fd, client_fd;
    struct sockaddr_in address;
    int opt = 1;
    socklen_t addrlen = sizeof(address);

    printf("\n🗜️ Data Compression Server v1.0\n");
    printf("============================\n");
    
    init_cache();

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
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // Bind socket
    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
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
    printf("1. Compress small data: (echo -e \"LZ4|1024\"; dd if=/dev/zero bs=1024 count=1) | nc localhost 8080\n");
    printf("2. Compress large data: (echo -e \"ZSTD|1048576\"; dd if=/dev/zero bs=1048576 count=1) | nc localhost 8080\n");
    printf("3. Compress huge data: (echo -e \"BZIP2|1073741824\"; dd if=/dev/zero bs=1073741824 count=1) | nc localhost 8080\n");
    printf("\n👂 Listening for compression requests...\n");

    while(1) {
        if ((client_fd = accept(server_fd, (struct sockaddr*)&address, &addrlen)) < 0) {
            perror("accept");
            continue;
        }

        printf("\n🔌 New connection from %s\n", inet_ntoa(address.sin_addr));
        handle_compression(client_fd);
        close(client_fd);
    }

    close(server_fd);
    return 0;
}

/*
To test:
1. Compile: gcc -o vuln-cwe122-ex2 plant-vuln-cwe122-ex2.c
2. Run: ./vuln-cwe122-ex2
3. In another terminal, test with:

   # Test 1: Normal compression (1KB)
   (echo -e "LZ4|1024"; dd if=/dev/zero bs=1024 count=1) | nc localhost 8080

   # Test 2: Large compression (1MB)
   (echo -e "ZSTD|1048576"; dd if=/dev/zero bs=1048576 count=1) | nc localhost 8080

   # Test 3: Huge compression (1GB)
   (echo -e "BZIP2|1073741824"; dd if=/dev/zero bs=1073741824 count=1) | nc localhost 8080

   # Test 4: Malicious size (2GB)
   (echo -e "BZIP2|2147483648"; dd if=/dev/zero bs=2147483648 count=1) | nc localhost 8080

Expected behavior:
- The program will attempt to allocate memory for the compressed data
- Heap overflow will occur with large sizes
- The program may crash or exhibit undefined behavior
- Memory corruption is possible

Note: This code is for educational purposes only.
DO NOT use in production environments.
The vulnerabilities demonstrated here can lead to:
- Heap corruption
- Memory leaks
- Program crashes
- Potential system compromise
*/ 