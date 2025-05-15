#ifndef PATH_PROCESSOR_H
#define PATH_PROCESSOR_H

#include "postgres.h"

/* Process path from socket input */
void process_path_from_socket(int dummy);

/* Prepare path for file operation */
void prepare_path_for_operation(const char *input_path, char *output_path, size_t size);

/* Execute file operation with processed path */
void execute_file_operation(const char *path);

#endif /* PATH_PROCESSOR_H */ 