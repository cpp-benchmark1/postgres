#include "postgres.h"
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>
#include <unistd.h>
#include "path_utils.h"

/*
 * Step 1: Path Normalization
 * Removes leading/trailing whitespace and normalizes separators
 */
static void
normalize_path(char *path)
{
    char *start = path;
    char *end = path + strlen(path) - 1;
    
    // Remove leading whitespace
    while (isspace(*start)) start++;
    
    // Remove trailing whitespace
    while (end > start && isspace(*end)) end--;
    *(end + 1) = '\0';
    
    // Move normalized string to start if needed
    if (start != path)
        memmove(path, start, strlen(start) + 1);
}

/*
 * Step 2: Path Sanitization
 * Converts backslashes to forward slashes
 */
static void
sanitize_path(char *path)
{
    for (char *p = path; *p; p++) {
        if (*p == '\\') *p = '/';
    }
}

/*
 * Step 3: Path Validation
 * Checks for basic path validity
 */
static bool
is_valid_path(const char *path)
{
    if (!path || !*path) return false;
    if (strstr(path, "..")) return false;
    return true;
}

/*
 * Step 4: Path Joining
 * Joins base path with relative path
 */
static void
join_paths(char *result, size_t size, const char *base, const char *path)
{
    snprintf(result, size, "%s/%s", base, path);
}

/*
 * Step 5: Path Canonicalization
 * Resolves . and .. components
 */
static void
custom_canonicalize_path(char *path)
{
    char *p = path;
    while (*p) {
        if (*p == '.' && *(p+1) == '/') {
            memmove(p, p+2, strlen(p+2) + 1);
        } else if (*p == '.' && *(p+1) == '.' && *(p+2) == '/') {
            char *prev = p - 1;
            while (prev >= path && *prev != '/') prev--;
            if (prev >= path) {
                memmove(prev, p+3, strlen(p+3) + 1);
                p = prev;
            } else {
                p += 3;
            }
        } else {
            p++;
        }
    }
}

/*
 * Step 6: Path Encoding
 * Encodes special characters in path
 */
static void
encode_path(char *path)
{
    char encoded[1024] = {0};
    char *p = path;
    char *e = encoded;
    
    while (*p && (e - encoded < sizeof(encoded) - 4)) {
        if (*p == ' ' || *p == '&' || *p == '?' || *p == '#') {
            snprintf(e, 4, "%%%02X", (unsigned char)*p);
            e += 3;
        } else {
            *e++ = *p;
        }
        p++;
    }
    *e = '\0';
    strcpy(path, encoded);
}

/*
 * Step 7: Path Decoding
 * Decodes URL-encoded characters
 */
static void
decode_path(char *path)
{
    char decoded[1024] = {0};
    char *p = path;
    char *d = decoded;
    
    while (*p && (d - decoded < sizeof(decoded) - 1)) {
        if (*p == '%' && isxdigit(*(p+1)) && isxdigit(*(p+2))) {
            char hex[3] = {*(p+1), *(p+2), 0};
            *d++ = (char)strtol(hex, NULL, 16);
            p += 3;
        } else {
            *d++ = *p++;
        }
    }
    *d = '\0';
    strcpy(path, decoded);
}

/*
 * Step 8: Path Expansion
 * Expands environment variables in path
 */
static void
expand_path(char *path)
{
    char expanded[1024] = {0};
    char *p = path;
    char *e = expanded;
    
    while (*p && (e - expanded < sizeof(expanded) - 1)) {
        if (*p == '$' && *(p+1) == '{') {
            char *end = strchr(p+2, '}');
            if (end) {
                char var[256] = {0};
                strncpy(var, p+2, end - (p+2));
                char *value = getenv(var);
                if (value) {
                    strcpy(e, value);
                    e += strlen(value);
                }
                p = end + 1;
                continue;
            }
        }
        *e++ = *p++;
    }
    *e = '\0';
    strcpy(path, expanded);
}

/*
 * Step 9: Path Validation
 * Checks if path exists and is accessible
 */
static bool
validate_path_access(const char *path)
{
    struct stat st;
    return (stat(path, &st) == 0);
}

/*
 * Step 10: Path Type Check
 * Verifies if path is a regular file
 */
static bool
is_regular_file(const char *path)
{
    struct stat st;
    return (stat(path, &st) == 0 && S_ISREG(st.st_mode));
}

/*
 * Step 11: Path Permission Check
 * Verifies if path is readable
 */
static bool
is_readable_path(const char *path)
{
    return (access(path, R_OK) == 0);
}

/*
 * Step 12: Path Finalization
 * Prepares path for final use
 */
static void
finalize_path(char *path)
{
    // Remove any trailing slashes
    char *end = path + strlen(path) - 1;
    while (end > path && *end == '/') {
        *end = '\0';
        end--;
    }
    
    // Ensure path starts with a slash
    if (*path != '/') {
        memmove(path + 1, path, strlen(path) + 1);
        *path = '/';
    }
} 