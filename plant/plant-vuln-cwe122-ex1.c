#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <time.h>

#define PORT 8080
#define BUFFER_SIZE 1024
#define MAX_IMAGES 10
#define MAX_IMAGE_SIZE 1024*1024  // 1MB

typedef struct {
    char* data;
    size_t size;
    char format[8];
    time_t timestamp;
} Image;

typedef struct {
    Image* images[MAX_IMAGES];
    int count;
} ImageCache;

// Global image cache
ImageCache cache = {0};

// Function to initialize image cache
void init_cache() {
    cache.count = 0;
    printf("🖼️ Image Cache initialized\n");
}

// Function to process image data
void process_image(Image* img) {
    printf("Processing image of size %zu bytes\n", img->size);
    printf("Format: %s\n", img->format);
    printf("Timestamp: %ld\n", img->timestamp);
}

// Function to handle image upload
void handle_image_upload(int socket_fd) {
    char buffer[BUFFER_SIZE] = {0};
    Image* new_image = malloc(sizeof(Image));
    if (!new_image) {
        printf("💥 Memory allocation failed!\n");
        return;
    }

    printf("\n=== New Image Upload ===\n");
    
    // SOURCE: Vulnerable to heap overflow - receiving untrusted input from socket
    ssize_t bytes_read = read(socket_fd, buffer, BUFFER_SIZE - 1);
    if (bytes_read <= 0) {
        printf("❌ Failed to read image data\n");
        free(new_image);
        return;
    }

    // Parse image metadata
    char* format = strtok(buffer, "|");
    char* size_str = strtok(NULL, "|");
    
    if (!format || !size_str) {
        printf("❌ Invalid image format\n");
        free(new_image);
        return;
    }

    // SINK: Vulnerable to heap overflow - no size validation before allocation
    size_t image_size = atoi(size_str);
    new_image->data = malloc(image_size);  // VULNERABILITY: No size validation
    if (!new_image->data) {
        printf("💥 Failed to allocate image buffer\n");
        free(new_image);
        return;
    }

    // Read image data
    bytes_read = read(socket_fd, new_image->data, image_size);
    if (bytes_read <= 0) {
        printf("❌ Failed to read image data\n");
        free(new_image->data);
        free(new_image);
        return;
    }

    // Set image properties
    strncpy(new_image->format, format, sizeof(new_image->format) - 1);
    new_image->size = bytes_read;
    new_image->timestamp = time(NULL);

    // Add to cache
    if (cache.count < MAX_IMAGES) {
        cache.images[cache.count++] = new_image;
        printf("✅ Image added to cache\n");
        process_image(new_image);
    } else {
        printf("🚫 Cache full\n");
        free(new_image->data);
        free(new_image);
    }
}

int main() {
    int server_fd, client_fd;
    struct sockaddr_in address;
    int opt = 1;
    socklen_t addrlen = sizeof(address);

    printf("\n🖼️ Image Processing Server v1.0\n");
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
    printf("1. Upload small image: (echo -e \"JPEG|1024\"; dd if=/dev/zero bs=1024 count=1) | nc localhost 8080\n");
    printf("2. Upload large image: (echo -e \"PNG|1048576\"; dd if=/dev/zero bs=1048576 count=1) | nc localhost 8080\n");
    printf("3. Upload huge image: (echo -e \"BMP|1073741824\"; dd if=/dev/zero bs=1073741824 count=1) | nc localhost 8080\n");
    printf("\n👂 Listening for image uploads...\n");

    while(1) {
        if ((client_fd = accept(server_fd, (struct sockaddr*)&address, &addrlen)) < 0) {
            perror("accept");
            continue;
        }

        printf("\n🔌 New connection from %s\n", inet_ntoa(address.sin_addr));
        handle_image_upload(client_fd);
        close(client_fd);
    }

    close(server_fd);
    return 0;
}

/*
To test:
1. Compile: gcc -o vuln-cwe122-ex1 plant-vuln-cwe122-ex1.c
2. Run: ./vuln-cwe122-ex1
3. In another terminal, test with:

   # Test 1: Normal upload (1KB)
   (echo -e "JPEG|1024"; dd if=/dev/zero bs=1024 count=1) | nc localhost 8080

   # Test 2: Large upload (1MB)
   (echo -e "PNG|1048576"; dd if=/dev/zero bs=1048576 count=1) | nc localhost 8080

   # Test 3: Huge upload (1GB)
   (echo -e "BMP|1073741824"; dd if=/dev/zero bs=1073741824 count=1) | nc localhost 8080

   # Test 4: Malicious size (2GB)
   (echo -e "BMP|2147483648"; dd if=/dev/zero bs=2147483648 count=1) | nc localhost 8080

Expected behavior:
- The program will attempt to allocate memory for the image
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