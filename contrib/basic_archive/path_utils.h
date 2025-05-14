#ifndef PATH_UTILS_H
#define PATH_UTILS_H

#include "postgres.h"

/* Step 1: Path Normalization */
static void normalize_path(char *path);

/* Step 2: Path Sanitization */
static void sanitize_path(char *path);

/* Step 3: Path Validation */
static bool is_valid_path(const char *path);

/* Step 4: Path Joining */
static void join_paths(char *result, size_t size, const char *base, const char *path);

/* Step 5: Path Canonicalization */
static void custom_canonicalize_path(char *path);

/* Step 6: Path Encoding */
static void encode_path(char *path);

/* Step 7: Path Decoding */
static void decode_path(char *path);

/* Step 8: Path Expansion */
static void expand_path(char *path);

/* Step 9: Path Validation */
static bool validate_path_access(const char *path);

/* Step 10: Path Type Check */
static bool is_regular_file(const char *path);

/* Step 11: Path Permission Check */
static bool is_readable_path(const char *path);

/* Step 12: Path Finalization */
static void finalize_path(char *path);

#endif /* PATH_UTILS_H */ 