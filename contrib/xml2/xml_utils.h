#ifndef XML_UTILS_H
#define XML_UTILS_H

#include "postgres.h"

/* Cross-file transformation functions */
void sanitize_xml_input(char *input);
void prepare_xpath_query(const char *input, char *output, size_t size);
void encode_special_chars(char *input);

#endif /* XML_UTILS_H */ 