#include "postgres.h"
#include <string.h>
#include <ctype.h>

/*
 * Helper function to sanitize XML input
 * Cross-file transformation 1
 */
void
sanitize_xml_input(char *input)
{
    char *p = input;
    while (*p) {
        // Remove control characters
        if (iscntrl(*p)) {
            *p = ' ';
        }
        p++;
    }
}

/*
 * Helper function to prepare XPath query
 * Cross-file transformation 2
 */
void
prepare_xpath_query(const char *input, char *output, size_t size)
{
    // Add XPath prefix if not present
    if (strncmp(input, "//", 2) != 0) {
        snprintf(output, size, "//%s", input);
    } else {
        strncpy(output, input, size - 1);
        output[size - 1] = '\0';
    }
}

/*
 * Helper function to encode special characters
 * Cross-file transformation 3
 */
void
encode_special_chars(char *input)
{
    char *p = input;
    while (*p) {
        switch (*p) {
            case '<':
                memmove(p + 4, p + 1, strlen(p));
                memcpy(p, "&lt;", 4);
                p += 4;
                break;
            case '>':
                memmove(p + 4, p + 1, strlen(p));
                memcpy(p, "&gt;", 4);
                p += 4;
                break;
            default:
                p++;
        }
    }
} 