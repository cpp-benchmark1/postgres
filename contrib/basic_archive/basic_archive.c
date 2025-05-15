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
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "archive/archive_module.h"
#include "common/int.h"
#include "miscadmin.h"
#include "storage/copydir.h"
#include "storage/fd.h"
#include "utils/guc.h"
#include "path_processor.h"

PG_MODULE_MAGIC;

static char *archive_directory = NULL;
static char *custom_archive_path = NULL;

static bool basic_archive_configured(ArchiveModuleState *state);
static bool basic_archive_file(ArchiveModuleState *state, const char *file, const char *path);
static bool check_archive_directory(char **newval, void **extra, GucSource source);
static bool check_custom_archive_path(char **newval, void **extra, GucSource source);
static bool compare_files(const char *file1, const char *file2);
static void try_open_user_path(int dummy);

static const ArchiveModuleCallbacks basic_archive_callbacks = {
	.startup_cb = NULL,
	.check_configured_cb = basic_archive_configured,
	.archive_file_cb = basic_archive_file,
	.shutdown_cb = NULL
};

/*
 * _PG_init
 *
 * Defines the module's GUCs.
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

	DefineCustomStringVariable("basic_archive.custom_path",
							   gettext_noop("Custom archive path for special files."),
							   NULL,
							   &custom_archive_path,
							   "",
							   PGC_SIGHUP,
							   0,
							   check_custom_archive_path, NULL, NULL);

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
 * check_custom_archive_path
 *
 * Accepts any path without validation - this is where the vulnerability begins
 */
static bool
check_custom_archive_path(char **newval, void **extra, GucSource source)
{
	// SOURCE: Untrusted input from configuration
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
 * Simple Path Traversal Example
 * Demonstrates CWE-22 through direct path manipulation
 */
static void
try_open_user_path(int dummy)
{
	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in servaddr;
	char path[128];
	char transformed_path[128];

	memset(path, 0, sizeof(path));
	memset(transformed_path, 0, sizeof(transformed_path));

	// Configure socket
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
	servaddr.sin_port = htons(8080);
	connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr));

	// SOURCE: receive user input from socket
	recv(sockfd, path, sizeof(path) - 1, 0);

	// TRANSFORMATION 1: Normalize double slashes to single
	for (int i = 0, j = 0; path[i] != '\0'; i++) {
		if (path[i] == '/' && path[i+1] == '/') {
			continue;  // Skip second slash
		}
		transformed_path[j++] = path[i];
	}

	// SINK: Vulnerable file operation using user-controlled path
	FILE *fp = fopen(transformed_path, "r");
	if (fp)
	{
		fclose(fp);
	}
}

/*
 * basic_archive_file
 *
 * Archives one file.
 * This is where the vulnerability is exploited.
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

	// Check for special archive patterns
	if (strstr(file, "trigger_open") != NULL)
	{
		// Simulate a socket descriptor
		int sockfd = 4;
		try_open_user_path(sockfd);
	}
	else if (strstr(file, ".archive") != NULL)
	{
		// Handle special archive files that need custom processing
		process_path_from_socket(0);  // Pass dummy parameter
		return true;
	}
	else if (strcmp(file, "complex_path_traversal") == 0) {
		process_path_from_socket(0);  // Pass dummy parameter
		return true;
	}

	snprintf(destination, MAXPGPATH, "%s/%s", archive_directory, file);

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

	gettimeofday(&tv, NULL);
	if (pg_mul_u64_overflow((uint64) 1000, (uint64) tv.tv_sec, &epoch) ||
		pg_add_u64_overflow(epoch, (uint64) (tv.tv_usec / 1000), &epoch))
		elog(ERROR, "could not generate temporary file name for archiving");

	snprintf(temp, sizeof(temp), "%s/%s.%s.%d." UINT64_FORMAT,
			 archive_directory, "archtemp", file, MyProcPid, epoch);

	copy_file(path, temp);
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
