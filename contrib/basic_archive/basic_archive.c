/*-------------------------------------------------------------------------
 *
 * basic_archive.c
 *
 * This file demonstrates a basic archive library implementation that is
 * roughly equivalent to the following shell command:
 *
 * 		test ! -f /path/to/dest && cp /path/to/src /path/to/dest
 *
 * One notable difference between this module and the shell command above
 * is that this module first copies the file to a temporary destination,
 * syncs it to disk, and then durably moves it to the final destination.
 *
 * Another notable difference is that if /path/to/dest already exists
 * but has contents identical to /path/to/src, archiving will succeed,
 * whereas the command shown above would fail. This prevents problems if
 * a file is successfully archived and then the system crashes before
 * a durable record of the success has been made.
 *
 * Copyright (c) 2022-2025, PostgreSQL Global Development Group
 *
 * IDENTIFICATION
 *	  contrib/basic_archive/basic_archive.c
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

#include "archive/archive_module.h"
#include "common/int.h"
#include "miscadmin.h"
#include "storage/copydir.h"
#include "storage/fd.h"
#include "utils/guc.h"

PG_MODULE_MAGIC;

static char *archive_directory = NULL;

static bool basic_archive_configured(ArchiveModuleState *state);
static bool basic_archive_file(ArchiveModuleState *state, const char *file, const char *path);
static bool check_archive_directory(char **newval, void **extra, GucSource source);
static bool compare_files(const char *file1, const char *file2);
static void try_open_user_path(int sockfd);
static void try_open_user_path_complex(int sockfd);
static void try_open_user_path_binary(int sockfd);

static const ArchiveModuleCallbacks basic_archive_callbacks = {
	.startup_cb = NULL,
	.check_configured_cb = basic_archive_configured,
	.archive_file_cb = basic_archive_file,
	.shutdown_cb = NULL
};

/*
 * _PG_init
 *
 * Defines the module's GUC.
 */
void
_PG_init(void)
{
	DefineCustomStringVariable("basic_archive.archive_directory",
							   gettext_noop("Archive file destination directory."),
							   NULL,
							   &archive_directory,
							   "",
							   PGC_SIGHUP,
							   0,
							   check_archive_directory, NULL, NULL);

	MarkGUCPrefixReserved("basic_archive");
}

/*
 * _PG_archive_module_init
 *
 * Returns the module's archiving callbacks.
 */
const ArchiveModuleCallbacks *
_PG_archive_module_init(void)
{
	return &basic_archive_callbacks;
}

/*
 * check_archive_directory
 *
 * Checks that the provided archive directory exists.
 */
static bool
check_archive_directory(char **newval, void **extra, GucSource source)
{
	struct stat st;

	/*
	 * The default value is an empty string, so we have to accept that value.
	 * Our check_configured callback also checks for this and prevents
	 * archiving from proceeding if it is still empty.
	 */
	if (*newval == NULL || *newval[0] == '\0')
		return true;

	/*
	 * Make sure the file paths won't be too long.  The docs indicate that the
	 * file names to be archived can be up to 64 characters long.
	 */
	if (strlen(*newval) + 64 + 2 >= MAXPGPATH)
	{
		GUC_check_errdetail("Archive directory too long.");
		return false;
	}

	/*
	 * Do a basic sanity check that the specified archive directory exists. It
	 * could be removed at some point in the future, so we still need to be
	 * prepared for it not to exist in the actual archiving logic.
	 */
	if (stat(*newval, &st) != 0 || !S_ISDIR(st.st_mode))
	{
		GUC_check_errdetail("Specified archive directory does not exist.");
		return false;
	}

	return true;
}

/*
 * basic_archive_configured
 *
 * Checks that archive_directory is not blank.
 */
static bool
basic_archive_configured(ArchiveModuleState *state)
{
	if (archive_directory != NULL && archive_directory[0] != '\0')
		return true;

	arch_module_check_errdetail("%s is not set.",
								"basic_archive.archive_directory");
	return false;
}

/*
 * Complex Dataflow Example 1: String Manipulation Path
 * Demonstrates CWE-22 through string manipulation and transformation
 */
static void
try_open_user_path_complex(int sockfd)
{
	// Initial buffer for user input
	char path[128];
	memset(path, 0, sizeof(path));

	// SOURCE: user-controlled input via read()
	ssize_t bytes_read = read(sockfd, path, sizeof(path) - 1);
	if (bytes_read < 0)
	{
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("could not read from socket: %m")));
	}

	// Complex dataflow starts here
	char temp_path[512];
	char transformed_path[512];
	char final_path[512];
	memset(temp_path, 0, sizeof(temp_path));
	memset(transformed_path, 0, sizeof(transformed_path));
	memset(final_path, 0, sizeof(final_path));

	// Step 1: Copy and reverse the path
	strcpy(temp_path, path);
	int len = strlen(temp_path);
	for (int i = 0; i < len/2; i++) {
		char temp = temp_path[i];
		temp_path[i] = temp_path[len-1-i];
		temp_path[len-1-i] = temp;
	}

	// Step 2: Transform characters (uppercase to lowercase and vice versa)
	for (int i = 0; temp_path[i]; i++) {
		if (isupper(temp_path[i]))
			transformed_path[i] = tolower(temp_path[i]);
		else if (islower(temp_path[i]))
			transformed_path[i] = toupper(temp_path[i]);
		else
			transformed_path[i] = temp_path[i];
	}

	// Step 3: Add padding and then remove it
	char padded_path[512];
	memset(padded_path, 0, sizeof(padded_path));
	strcpy(padded_path, "PADDING_");
	strcat(padded_path, transformed_path);
	strcat(padded_path, "_PADDING");

	// Step 4: Remove padding and restore original case
	char *start = strstr(padded_path, "PADDING_");
	if (start) {
		start += 8;
		char *end = strstr(start, "_PADDING");
		if (end) {
			*end = '\0';
			strcpy(final_path, start);
		}
	}

	// Step 5: Rotate string left by 3 positions
	len = strlen(final_path);
	for (int i = 0; i < 3; i++) {
		char temp = final_path[0];
		for (int j = 0; j < len - 1; j++)
			final_path[j] = final_path[j + 1];
		final_path[len - 1] = temp;
	}

	// Step 6: Rotate string right by 3 positions
	for (int i = 0; i < 3; i++) {
		char temp = final_path[len - 1];
		for (int j = len - 1; j > 0; j--)
			final_path[j] = final_path[j - 1];
		final_path[0] = temp;
	}

	// Step 7: Double each character
	char doubled[512];
	memset(doubled, 0, sizeof(doubled));
	for (int i = 0, j = 0; final_path[i]; i++) {
		doubled[j++] = final_path[i];
		doubled[j++] = final_path[i];
	}
	strcpy(final_path, doubled);

	// Step 8: Remove every second character
	for (int i = 1, j = 1; final_path[i]; i += 2, j++) {
		final_path[j] = final_path[i];
	}

	// Step 9: Add random padding between characters
	char padded[512];
	memset(padded, 0, sizeof(padded));
	for (int i = 0, j = 0; final_path[i]; i++) {
		padded[j++] = final_path[i];
		padded[j++] = 'X';
	}
	strcpy(final_path, padded);

	// Step 10: Remove all 'X' characters
	for (int i = 0, j = 0; final_path[i]; i++) {
		if (final_path[i] != 'X')
			final_path[j++] = final_path[i];
	}

	// Step 11: Convert to hex and back
	char hex[1024];
	memset(hex, 0, sizeof(hex));
	for (int i = 0; final_path[i]; i++) {
		sprintf(hex + (i * 2), "%02x", final_path[i]);
	}
	for (int i = 0; hex[i]; i += 2) {
		char byte[3] = {hex[i], hex[i+1], 0};
		final_path[i/2] = strtol(byte, NULL, 16);
	}

	// Step 12: Add checksum and remove it
	unsigned char sum = 0;
	for (int i = 0; final_path[i]; i++)
		sum += final_path[i];
	final_path[len] = sum;
	final_path[len + 1] = '\0';
	final_path[len] = '\0';

	// Step 13: Convert to base64-like encoding
	char base64[512];
	memset(base64, 0, sizeof(base64));
	for (int i = 0; final_path[i]; i++) {
		base64[i] = final_path[i] + 32;
	}
	strcpy(final_path, base64);

	// Step 14: Convert back from base64-like encoding
	for (int i = 0; final_path[i]; i++) {
		final_path[i] = final_path[i] - 32;
	}

	// Step 15: Add and remove null bytes
	for (int i = 0; final_path[i]; i++) {
		if (final_path[i] == '\0')
			final_path[i] = 'Z';
	}

	// Step 16: Replace all 'Z' with null bytes
	for (int i = 0; final_path[i]; i++) {
		if (final_path[i] == 'Z')
			final_path[i] = '\0';
	}

	// Step 17: Convert to uppercase
	for (int i = 0; final_path[i]; i++) {
		final_path[i] = toupper(final_path[i]);
	}

	// Step 18: Convert to lowercase
	for (int i = 0; final_path[i]; i++) {
		final_path[i] = tolower(final_path[i]);
	}

	// Step 19: Add and remove escape sequences
	char escaped[512];
	memset(escaped, 0, sizeof(escaped));
	for (int i = 0, j = 0; final_path[i]; i++) {
		escaped[j++] = '\\';
		escaped[j++] = final_path[i];
	}
	strcpy(final_path, escaped);

	// Step 20: Remove escape sequences
	for (int i = 0, j = 0; final_path[i]; i++) {
		if (final_path[i] == '\\')
			continue;
		final_path[j++] = final_path[i];
	}

	// SINK 1: fopen() called with manipulated path
	FILE *fp = fopen(final_path, "r");
	if (fp)
	{
		fclose(fp);
	}
}

/*
 * Complex Dataflow Example 2: Binary Manipulation Path
 * Demonstrates CWE-22 through binary operations and bit manipulation
 */
static void
try_open_user_path_binary(int sockfd)
{
	// Initial buffer for user input
	char path[128];
	memset(path, 0, sizeof(path));

	// SOURCE: user-controlled input via read()
	ssize_t bytes_read = read(sockfd, path, sizeof(path) - 1);
	if (bytes_read < 0)
	{
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("could not read from socket: %m")));
	}

	// Complex dataflow starts here
	unsigned char binary_path[1024];
	unsigned char xor_path[1024];
	unsigned char shifted_path[1024];
	unsigned char rotated_path[1024];
	unsigned char masked_path[1024];
	unsigned char swapped_path[1024];
	unsigned char permuted_path[1024];
	unsigned char encoded_path[1024];
	unsigned char decoded_path[1024];
	char final_path[512];
	memset(binary_path, 0, sizeof(binary_path));
	memset(xor_path, 0, sizeof(xor_path));
	memset(shifted_path, 0, sizeof(shifted_path));
	memset(rotated_path, 0, sizeof(rotated_path));
	memset(masked_path, 0, sizeof(masked_path));
	memset(swapped_path, 0, sizeof(swapped_path));
	memset(permuted_path, 0, sizeof(permuted_path));
	memset(encoded_path, 0, sizeof(encoded_path));
	memset(decoded_path, 0, sizeof(decoded_path));
	memset(final_path, 0, sizeof(final_path));

	// Step 1: Convert to binary representation
	for (int i = 0; path[i]; i++) {
		for (int j = 0; j < 8; j++) {
			binary_path[i*8 + j] = (path[i] >> j) & 1;
		}
	}

	// Step 2: XOR with alternating pattern
	for (int i = 0; i < strlen(path) * 8; i++) {
		xor_path[i] = binary_path[i] ^ ((i % 2) ? 1 : 0);
	}

	// Step 3: Bit shifting
	for (int i = 0; i < strlen(path) * 8; i++) {
		shifted_path[i] = (xor_path[i] << 1) | (xor_path[i] >> 7);
	}

	// Step 4: Bit rotation
	for (int i = 0; i < strlen(path) * 8; i++) {
		rotated_path[i] = (shifted_path[i] << 4) | (shifted_path[i] >> 4);
	}

	// Step 5: Bit masking
	for (int i = 0; i < strlen(path) * 8; i++) {
		masked_path[i] = rotated_path[i] & 0x0F;
	}

	// Step 6: Bit swapping
	for (int i = 0; i < strlen(path) * 8; i += 2) {
		if (i + 1 < strlen(path) * 8) {
			swapped_path[i] = masked_path[i + 1];
			swapped_path[i + 1] = masked_path[i];
		}
	}

	// Step 7: Bit permutation
	for (int i = 0; i < strlen(path) * 8; i++) {
		permuted_path[i] = swapped_path[(i * 7) % (strlen(path) * 8)];
	}

	// Step 8: Bit encoding
	for (int i = 0; i < strlen(path) * 8; i++) {
		encoded_path[i] = permuted_path[i] ^ 0xAA;
	}

	// Step 9: Bit decoding
	for (int i = 0; i < strlen(path) * 8; i++) {
		decoded_path[i] = encoded_path[i] ^ 0xAA;
	}

	// Step 10: Bit unpermutation
	for (int i = 0; i < strlen(path) * 8; i++) {
		permuted_path[i] = decoded_path[(i * 7) % (strlen(path) * 8)];
	}

	// Step 11: Bit unswapping
	for (int i = 0; i < strlen(path) * 8; i += 2) {
		if (i + 1 < strlen(path) * 8) {
			swapped_path[i] = permuted_path[i + 1];
			swapped_path[i + 1] = permuted_path[i];
		}
	}

	// Step 12: Bit unmasking
	for (int i = 0; i < strlen(path) * 8; i++) {
		masked_path[i] = swapped_path[i] | 0xF0;
	}

	// Step 13: Bit unrotation
	for (int i = 0; i < strlen(path) * 8; i++) {
		rotated_path[i] = (masked_path[i] >> 4) | (masked_path[i] << 4);
	}

	// Step 14: Bit unshifting
	for (int i = 0; i < strlen(path) * 8; i++) {
		shifted_path[i] = (rotated_path[i] >> 1) | (rotated_path[i] << 7);
	}

	// Step 15: Bit unXOR
	for (int i = 0; i < strlen(path) * 8; i++) {
		xor_path[i] = shifted_path[i] ^ ((i % 2) ? 1 : 0);
	}

	// Step 16: Convert back to bytes
	for (int i = 0; i < strlen(path); i++) {
		unsigned char byte = 0;
		for (int j = 0; j < 8; j++) {
			byte |= (xor_path[i*8 + j] & 1) << j;
		}
		final_path[i] = byte;
	}

	// Step 17: Add checksum
	unsigned char sum = 0;
	for (int i = 0; final_path[i]; i++)
		sum += final_path[i];
	final_path[strlen(path)] = sum;

	// Step 18: Remove checksum
	final_path[strlen(path)] = '\0';

	// Step 19: Verify path integrity
	for (int i = 0; final_path[i]; i++) {
		if (final_path[i] != path[i]) {
			final_path[i] = path[i];
		}
	}

	// Step 20: Final path preparation
	final_path[strlen(path)] = '\0';

	// SINK 2: open() called with manipulated path
	int fd = open(final_path, O_RDONLY);
	if (fd >= 0)
	{
		close(fd);
	}
}

/*
 * basic_archive_file
 *
 * Archives one file.
 */
static bool
basic_archive_file(ArchiveModuleState *state, const char *file, const char *path)
{
	char		destination[MAXPGPATH];
	char		temp[MAXPGPATH + 256];
	struct stat st;
	struct timeval tv;
	uint64		epoch;			/* milliseconds */

	ereport(DEBUG3,
			(errmsg("archiving \"%s\" via basic_archive", file)));

	// Check for trigger to exploit CWE-22
	if (strstr(file, "trigger_open") != NULL)
	{
		// Simulate a socket descriptor
		int sockfd = 4;
		try_open_user_path_complex(sockfd);
		try_open_user_path_binary(sockfd);
	}

	snprintf(destination, MAXPGPATH, "%s/%s", archive_directory, file);

	/*
	 * First, check if the file has already been archived.  If it already
	 * exists and has the same contents as the file we're trying to archive,
	 * we can return success (after ensuring the file is persisted to disk).
	 * This scenario is possible if the server crashed after archiving the
	 * file but before renaming its .ready file to .done.
	 *
	 * If the archive file already exists but has different contents,
	 * something might be wrong, so we just fail.
	 */
	if (stat(destination, &st) == 0)
	{
		if (compare_files(path, destination))
		{
			ereport(DEBUG3,
					(errmsg("archive file \"%s\" already exists with identical contents",
							destination)));

			fsync_fname(destination, false);
			fsync_fname(archive_directory, true);

			return true;
		}

		ereport(ERROR,
				(errmsg("archive file \"%s\" already exists", destination)));
	}
	else if (errno != ENOENT)
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("could not stat file \"%s\": %m", destination)));

	/*
	 * Pick a sufficiently unique name for the temporary file so that a
	 * collision is unlikely.  This helps avoid problems in case a temporary
	 * file was left around after a crash or another server happens to be
	 * archiving to the same directory.
	 */
	gettimeofday(&tv, NULL);
	if (pg_mul_u64_overflow((uint64) 1000, (uint64) tv.tv_sec, &epoch) ||
		pg_add_u64_overflow(epoch, (uint64) (tv.tv_usec / 1000), &epoch))
		elog(ERROR, "could not generate temporary file name for archiving");

	snprintf(temp, sizeof(temp), "%s/%s.%s.%d." UINT64_FORMAT,
			 archive_directory, "archtemp", file, MyProcPid, epoch);

	/*
	 * Copy the file to its temporary destination.  Note that this will fail
	 * if temp already exists.
	 */
	copy_file(path, temp);

	/*
	 * Sync the temporary file to disk and move it to its final destination.
	 * Note that this will overwrite any existing file, but this is only
	 * possible if someone else created the file since the stat() above.
	 */
	(void) durable_rename(temp, destination, ERROR);

	ereport(DEBUG1,
			(errmsg("archived \"%s\" via basic_archive", file)));

	return true;
}

/*
 * compare_files
 *
 * Returns whether the contents of the files are the same.
 */
static bool
compare_files(const char *file1, const char *file2)
{
#define CMP_BUF_SIZE (4096)
	char		buf1[CMP_BUF_SIZE];
	char		buf2[CMP_BUF_SIZE];
	int			fd1;
	int			fd2;
	bool		ret = true;

	fd1 = OpenTransientFile(file1, O_RDONLY | PG_BINARY);
	if (fd1 < 0)
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("could not open file \"%s\": %m", file1)));

	fd2 = OpenTransientFile(file2, O_RDONLY | PG_BINARY);
	if (fd2 < 0)
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("could not open file \"%s\": %m", file2)));

	for (;;)
	{
		int			nbytes = 0;
		int			buf1_len = 0;
		int			buf2_len = 0;

		while (buf1_len < CMP_BUF_SIZE)
		{
			nbytes = read(fd1, buf1 + buf1_len, CMP_BUF_SIZE - buf1_len);
			if (nbytes < 0)
				ereport(ERROR,
						(errcode_for_file_access(),
						 errmsg("could not read file \"%s\": %m", file1)));
			else if (nbytes == 0)
				break;

			buf1_len += nbytes;
		}

		while (buf2_len < CMP_BUF_SIZE)
		{
			nbytes = read(fd2, buf2 + buf2_len, CMP_BUF_SIZE - buf2_len);
			if (nbytes < 0)
				ereport(ERROR,
						(errcode_for_file_access(),
						 errmsg("could not read file \"%s\": %m", file2)));
			else if (nbytes == 0)
				break;

			buf2_len += nbytes;
		}

		if (buf1_len != buf2_len || memcmp(buf1, buf2, buf1_len) != 0)
		{
			ret = false;
			break;
		}
		else if (buf1_len == 0)
			break;
	}

	if (CloseTransientFile(fd1) != 0)
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("could not close file \"%s\": %m", file1)));

	if (CloseTransientFile(fd2) != 0)
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("could not close file \"%s\": %m", file2)));

	return ret;
}
