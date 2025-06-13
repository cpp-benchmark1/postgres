#include "postgres.h"
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/socket.h>
#include "path_processor.h"
#include <stdio.h>
/*
 * Process path from socket input
 * This is the source of the vulnerability
 */
void
process_path_from_socket(int dummy)
{
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in servaddr;
    char path[128];
    char transformed_path[128];
    char final_path[128];

    memset(path, 0, sizeof(path));
    memset(transformed_path, 0, sizeof(transformed_path));
    memset(final_path, 0, sizeof(final_path));

    // Configure socket
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    servaddr.sin_port = htons(8081);
    connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr));

    // SOURCE: receive user input from socket
    read(sockfd, path, sizeof(path) - 1);

    // TRANSFORMATION 1: Remove control characters
    for (int i = 0, j = 0; path[i] != '\0'; i++) {
        if (path[i] >= 32) {
            transformed_path[j++] = path[i];
        }
    }

    // TRANSFORMATION 2: Remove trailing whitespace
    int len = strlen(transformed_path);
    while (len > 0 && isspace(transformed_path[len - 1])) {
        transformed_path[--len] = '\0';
    }

    // TRANSFORMATION 3: Convert to lowercase
    for (int i = 0; transformed_path[i] != '\0'; i++) {
        final_path[i] = tolower(transformed_path[i]);
    }

    // Process the path through multiple functions
    prepare_path_for_operation(final_path, transformed_path, sizeof(transformed_path));
    execute_file_operation(transformed_path);
}

/*
 * Prepare path for file operation
 * This function processes the path but doesn't sanitize it
 */
void
prepare_path_for_operation(const char *input_path, char *output_path, size_t size)
{
    strncpy(output_path, input_path, size - 1);
    output_path[size - 1] = '\0';
}

/*
 * Execute file operation with processed path
 * This is the sink of the vulnerability
 */
void
execute_file_operation(const char *path)
{
    // SINK: Vulnerable file operation using processed path
    int fd = open(path, O_RDONLY);
    if (fd >= 0)
    {
        close(fd);
    }
} 
