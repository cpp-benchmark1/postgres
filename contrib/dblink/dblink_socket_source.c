#include "postgres.h"
#include "fmgr.h"
#include "libpq-fe.h"
#include "dblink.h"

PG_MODULE_MAGIC;

// Generic socket source for testing vulnerabilities
PG_FUNCTION_INFO_V1(dblink_socket_source);
Datum
dblink_socket_source(PG_FUNCTION_ARGS)
{
    char *host = text_to_cstring(PG_GETARG_TEXT_PP(0));
    int port = PG_GETARG_INT32(1);
    char *data = text_to_cstring(PG_GETARG_TEXT_PP(2));
    
    // Create socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        ereport(ERROR,
                (errcode(ERRCODE_CONNECTION_FAILURE),
                 errmsg("socket creation failed")));
    }

    // Set up server address
    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(port);
    inet_pton(AF_INET, host, &servaddr.sin_addr);

    // Connect to server
    if (connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0) {
        ereport(ERROR,
                (errcode(ERRCODE_CONNECTION_FAILURE),
                 errmsg("connection failed")));
    }

    // Send data
    if (send(sockfd, data, strlen(data), 0) < 0) {
        ereport(ERROR,
                (errcode(ERRCODE_CONNECTION_FAILURE),
                 errmsg("send failed")));
    }

    // Receive response
    char buffer[1024] = {0};
    if (recv(sockfd, buffer, sizeof(buffer), 0) < 0) {
        ereport(ERROR,
                (errcode(ERRCODE_CONNECTION_FAILURE),
                 errmsg("receive failed")));
    }

    close(sockfd);
    PG_RETURN_TEXT_P(cstring_to_text(buffer));
} 