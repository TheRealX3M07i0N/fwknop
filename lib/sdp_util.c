/*
 *****************************************************************************
 *
 * File:    sdp_util.c
 *
 *
 *****************************************************************************
*/
#include "sdp_util.h"
#include "sdp_errors.h"
#include "sdp_ctrl_client_config.h"
#include "sdp_log_msg.h"
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>

const char *BACKUP_PATH_POSTFIX = "_previous";
#define POSTFIX_LEN 10

int sdp_append_msg_to_buf(char *buf, size_t buf_size, const char* msg, ...)
{
    int     bytes_written = 0;  /* Number of bytes written to buf */
    va_list ap;

    /* Check if the buffer is valid */
    if (buf_size > 0)
    {
        va_start(ap, msg);

        /* Format the message like a printf message */
        bytes_written = vsnprintf(buf, buf_size, msg, ap);

        /* It looks like the message has been truncated or an error occured*/
        if (bytes_written < 0)
            bytes_written = 0;

        else if (bytes_written >= buf_size)
            bytes_written = buf_size;

        /* The messsage has been formatted correctly */
        else;

        va_end(ap);
    }

    /* No valid buffer has been supplied, thus we do not write anything */
    else;

    /* Return the number of bytes written to the buffer */
    return bytes_written;
}


int sdp_strtol_wrapper(const char * const str, const int min,
    const int max, int *is_err)
{
    int val;

    errno = 0;
    *is_err = SDP_SUCCESS;

    val = strtol(str, (char **) NULL, 10);

    if ((errno == ERANGE || (errno != 0 && val == 0)))
    {
        *is_err = errno;
        perror("strtol");
        log_msg(LOG_ERR, "Value %d out of range [(%d)-(%d)]",
            val, min, max);
        return 0;
    }

    if(val < min)
    {
        *is_err = SDP_ERROR_STRTOL;
        log_msg(LOG_ERR, "Value %d out of range [(%d)-(%d)]",
            val, min, max);
        return 0;
    }

    /* allow max == -1 to be an exception where we don't care about the
     * maximum - note that the ERANGE check is still in place above
    */
    if((max >= 0) && (val > max))
    {
        *is_err = SDP_ERROR_STRTOL;
        log_msg(LOG_ERR, "Value %d out of range [(%d)-(%d)]",
            val, min, max);
        return 0;
    }

#if HAVE_LIBFIU
    fiu_return_on("strtol_wrapper_lt_min",
            SDP_ERROR_STRTOL);
    fiu_return_on("strtol_wrapper_gt_max",
            SDP_ERROR_STRTOL);
#endif

    return val;
}


long double sdp_strtold_wrapper(const char * const str, const int min,
    const int max, int *is_err)
{
    long double val;

    errno = 0;
    *is_err = SDP_SUCCESS;

    val = strtold(str, NULL);

    if ((errno == ERANGE || (errno != 0 && val == 0)))
    {
        *is_err = errno;
        perror("strtold");
        log_msg(LOG_ERR, "Value %s out of range [(%d)-(%d)]",
            str, min, max);
        return 0;
    }

    if(val < min)
    {
        *is_err = SDP_ERROR_STRTOLD;
        log_msg(LOG_ERR, "Value %Lf out of range [(%d)-(%d)]",
            val, min, max);
        return 0;
    }

    /* allow max == -1 to be an exception where we don't care about the
     * maximum - note that the ERANGE check is still in place above
    */
    if((max >= 0) && (val > max))
    {
        *is_err = SDP_ERROR_STRTOLD;
        log_msg(LOG_ERR, "Value %Lf out of range [(%d)-(%d)]",
            val, min, max);
        return 0;
    }

#if HAVE_LIBFIU
    fiu_return_on("strtold_wrapper_lt_min",
            SDP_ERROR_STRTOLD);
    fiu_return_on("strtold_wrapper_gt_max",
            SDP_ERROR_STRTOLD);
#endif

    return val;
}


int sdp_move_file_to_backup(const char *file_path)
{
    struct stat stat_buf;
    char backup_path[PATH_MAX + 1] = {0};

    if( !file_path )
    {
        log_msg(LOG_ERR, "Passed null argument to function");
        return SDP_ERROR_BAD_ARG;
    }

    if( PATH_MAX < strnlen(file_path, PATH_MAX + 1) )
    {
        log_msg(LOG_ERR, "Path too long");
        return SDP_ERROR_BAD_ARG;
    }

    strncpy(backup_path, file_path, PATH_MAX);
    strncat(backup_path, BACKUP_PATH_POSTFIX, POSTFIX_LEN);

    if(stat(backup_path, &stat_buf) == 0)
    {
        if(remove(backup_path) != 0)
        {
            log_msg(LOG_ERR, "Failed to delete old version of file: %s", backup_path);
            return SDP_ERROR_FILESYSTEM_OPERATION;
        }
    }

    // Does the file exist
    if(stat(file_path, &stat_buf) != 0)
    {
        log_msg(LOG_ERR, "Failed to find file: %s", file_path);
        return SDP_ERROR_BAD_ARG;
    }

    // Try to rename it
    if(rename(file_path, backup_path) != 0)
    {
        log_msg(LOG_ERR, "Failed to rename file: %s", file_path);
        return SDP_ERROR_FILESYSTEM_OPERATION;
    }

    return SDP_SUCCESS;
}


int sdp_save_to_file(const char *file_path, const char *data)
{
    int rv = SDP_ERROR_FILESYSTEM_OPERATION;
    FILE *fp = NULL;
    int num_bytes = 0;
    size_t data_len = strnlen(data, SDP_MSG_MAX_LEN);

    if( !(data && file_path))
    {
        log_msg(LOG_ERR, "Passed null argument to function");
        return SDP_ERROR_BAD_ARG;
    }

    if((rv = sdp_move_file_to_backup(file_path)) != SDP_SUCCESS)
    {
        log_msg(LOG_ERR, "Backup process failed for %s", file_path);
        return SDP_ERROR_FILESYSTEM_OPERATION;
    }

    // Reset errno (just in case)
    errno = 0;

    // Reset rv, all following potential error points result in same error code
    rv = SDP_ERROR_FILESYSTEM_OPERATION;

    // Create/open the new file
    fp = fopen(file_path, "w");

    if(fp == NULL || errno)
    {
        perror("Error trying to open file");
        log_msg(LOG_ERR, "File path was: %s", file_path);
        goto cleanup;
    }


    // Reset errno (just in case)
    errno = 0;

    num_bytes = fprintf(fp, "%s", data);

    if(errno)
    {
        perror("File write gave an error");
        log_msg(LOG_ERR, "File path was: %s", file_path);
        goto cleanup;
    }

    if(num_bytes != data_len)
    {
        log_msg(LOG_ERR, "Error: only wrote %d of %d bytes to file: %s",
                   num_bytes, (int)data_len, file_path);
        goto cleanup;
    }

    // arriving here means all is well
    rv = SDP_SUCCESS;

cleanup:
    if(fp)
        fclose(fp);

    // try to restore backup if things went wrong
    if(rv != SDP_SUCCESS)
    {
        if(sdp_restore_file(file_path) != SDP_SUCCESS)
            log_msg(LOG_ERR, "Failed to restore file: %s", file_path);
        else
            log_msg(LOG_ERR, "Successfully restored file: %s", file_path);
    }

    return rv;
}

int  sdp_restore_file(const char *file_path)
{
    struct stat stat_buf;
    char backup_path[PATH_MAX + 1] = {0};

    if( !file_path )
    {
        log_msg(LOG_ERR, "Passed null argument to function");
        return SDP_ERROR_BAD_ARG;
    }

    if( PATH_MAX < strnlen(file_path, PATH_MAX+1) )
    {
        log_msg(LOG_ERR, "Path too long");
        return SDP_ERROR_BAD_ARG;
    }

    strncpy(backup_path, file_path, PATH_MAX);
    strncat(backup_path, BACKUP_PATH_POSTFIX, POSTFIX_LEN);

    // if backup file doesn't exist, stop now
    if(stat(backup_path, &stat_buf) != 0)
    {
        log_msg(LOG_ERR, "Cannot restore backup file, does not exist: %s", backup_path);
        return SDP_ERROR_FILESYSTEM_OPERATION;
    }

    // if newer file exists, delete it
    if(stat(file_path, &stat_buf) == 0)
    {
        if(remove(file_path) != 0)
        {
            log_msg(LOG_ERR, "While trying to restore old file, failed to remove file: %s", file_path);
            return SDP_ERROR_FILESYSTEM_OPERATION;
        }
    }

    if(rename(backup_path, file_path) != 0)
    {
        log_msg(LOG_ERR, "Failed to restore file: %s", file_path);
        return SDP_ERROR_FILESYSTEM_OPERATION;
    }

    log_msg(LOG_ERR, "Succeeded in restoring file: %s", file_path);

    return SDP_SUCCESS;
}


int  sdp_replace_spa_keys(const char *file_path,
                          const char *old_key1, const char *new_key1, const int min_key1_matches,
                          const char *old_key2, const char *new_key2, const int min_key2_matches)
{
    char *start_here;
    char line[SDP_MAX_LINE_LEN];
    FILE *old_file = NULL;
    FILE *new_file = NULL;
    int remaining = 0;
    int new_key1_len = 0;
    int new_key2_len = 0;
    int count1 = 0;
    int count2 = 0;
    char backup_path[PATH_MAX + 1] = {0};
    int rv = SDP_SUCCESS;


    if( !(file_path &&
          old_key1 &&
          new_key1 &&
          old_key2 &&
          new_key2) )
    {
        log_msg(LOG_ERR, "required arg not specified");
        return SDP_ERROR_BAD_ARG;
    }

    if( PATH_MAX < strnlen(file_path, PATH_MAX+1) )
    {
        log_msg(LOG_ERR, "Path too long");
        return SDP_ERROR_BAD_ARG;
    }

    strncpy(backup_path, file_path, PATH_MAX);
    strncat(backup_path, BACKUP_PATH_POSTFIX, POSTFIX_LEN);

    if((new_key1_len = strnlen(new_key1, SDP_MAX_B64_KEY_LEN + 1)) > SDP_MAX_B64_KEY_LEN)
    {
        log_msg(LOG_ERR, "New key 1 has length %d, exceeds max length %d",
                new_key1_len, SDP_MAX_B64_KEY_LEN);
        return SDP_ERROR_BAD_ARG;
    }

    if((new_key2_len = strnlen(new_key2, SDP_MAX_B64_KEY_LEN + 1)) > SDP_MAX_B64_KEY_LEN)
    {
        log_msg(LOG_ERR, "New key 2 has length %d, exceeds max length %d",
                new_key2_len, SDP_MAX_B64_KEY_LEN);
        return SDP_ERROR_BAD_ARG;
    }

    // rename the original file to be the backup
    if((rv = sdp_move_file_to_backup(file_path)) != SDP_SUCCESS)
    {
        log_msg(LOG_ERR, "Backup process failed for %s", file_path);
        goto cleanup;
    }

    // open the 'old' file for reading
    if ((old_file = fopen(backup_path, "r")) == NULL)
    {
        log_msg(LOG_ERR, "Could not open file for read: %s", backup_path);
        perror(NULL);
        rv = SDP_ERROR_FILESYSTEM_OPERATION;
        goto cleanup;
    }

    // open the 'new' file for writing
    if ((new_file = fopen(file_path, "w")) == NULL)
    {
        log_msg(LOG_ERR, "Could not open file for writing: %s", file_path);
        perror(NULL);
        rv = SDP_ERROR_FILESYSTEM_OPERATION;
        goto cleanup;
    }

    log_msg(LOG_DEBUG, "Attempting to save SPA keys to file: %s", file_path);

    // walk through the original file
    while(1)
    {
        if(fgets(line, SDP_MAX_LINE_LEN, old_file) == NULL)
        {
            log_msg(LOG_DEBUG, "Reached end of file");
            break;
        }

        if((start_here = strstr(line, old_key1)) != NULL)
        {
            log_msg(LOG_DEBUG, "Found a line containing old key 1");
            count1++;
            remaining = SDP_MAX_LINE_LEN - (start_here - line);

            if(remaining < 1 || remaining > SDP_MAX_LINE_LEN)
            {
                log_msg(LOG_ERR,
                        "Calculated remaining buffer length %d is out of permitted range 1 to %d",
                        remaining, SDP_MAX_LINE_LEN);
                rv = SDP_ERROR_KEY_SAVE;
                goto cleanup;
            }

            // must have space for new key plus line feed and one null char
            if(remaining < (new_key1_len + 2))
            {
                log_msg(LOG_ERR,
                        "Calculated remaining buffer length %d is less than new key length %d + 2",
                        remaining, new_key1_len);
                rv = SDP_ERROR_KEY_SAVE;
                goto cleanup;
            }

            strncpy(start_here, new_key1, (size_t)remaining);
            strncat(line, "\n", 1);
        }
        else if((start_here = strstr(line, old_key2)) != NULL)
        {
            log_msg(LOG_DEBUG, "Found a line containing old key 2");
            count2++;
            remaining = SDP_MAX_LINE_LEN - (start_here - line);

            if(remaining < 1 || remaining > SDP_MAX_LINE_LEN)
            {
                log_msg(LOG_ERR,
                        "Calculated remaining buffer length %d is out of permitted range 1 to %d",
                        remaining, SDP_MAX_LINE_LEN);
                rv = SDP_ERROR_KEY_SAVE;
                goto cleanup;
            }

            // must have space for new key plus line feed and one null char
            if(remaining < (new_key2_len + 2))
            {
                log_msg(LOG_ERR,
                        "Calculated remaining buffer length %d is less than new key length %d + 2",
                        remaining, new_key2_len);
                rv = SDP_ERROR_KEY_SAVE;
                goto cleanup;
            }

            strncpy(start_here, new_key2, (size_t)remaining);
            strncat(line, "\n", 1);
        }
        else;

        // whether modified or not, always print line
        fprintf(new_file, "%s", line);
    }

    // were the required number of matches made
    if(count1 < min_key1_matches || count2 < min_key2_matches)
    {
        rv = SDP_ERROR_KEY_SAVE;
        log_msg(LOG_ERR,   "Minimum match requirement not met:");
        log_msg(LOG_DEBUG, "  Key 1 - Required: %d, Matched: %d", min_key1_matches, count1);
        log_msg(LOG_DEBUG, "  Key 2 - Required: %d, Matched: %d", min_key2_matches, count2);
        log_msg(LOG_DEBUG, "Old Key 1 in memory: %s", old_key1);
        log_msg(LOG_DEBUG, "Old Key 2 in memory: %s", old_key2);
    }
    else
    {
        rv = SDP_SUCCESS;
        log_msg(LOG_DEBUG, "Minimum match requirement successfully met:");
        log_msg(LOG_DEBUG, "  Key 1 - Required: %d, Matched: %d", min_key1_matches, count1);
        log_msg(LOG_DEBUG, "  Key 2 - Required: %d, Matched: %d", min_key2_matches, count2);
    }



cleanup:
    // close files
    if(old_file)
        fclose(old_file);

    if(new_file)
        fclose(new_file);

    // if there were errors, restore original file
    if(rv != SDP_SUCCESS)
        sdp_restore_file(file_path);

    return rv;
}

int sdp_make_absolute_path(const char *file, char **r_full_path)
{
    int dir_str_len = 0;
    char full_path[PATH_MAX+1] = {0};
    int file_str_len = strnlen(file, PATH_MAX + 1);
    int file_str_offset = 0;

    if(file_str_len > PATH_MAX)
    {
        log_msg(LOG_ERR, "Original file path too long: %d bytes", file_str_len);
        log_msg(LOG_ERR, "Argument was: %s", file);
        return SDP_ERROR_ABSOLUTE_PATH;
    }

    // Not yet Windows compatible
    if('/' == file[0] )
    {
        // Nothing to do, leave path as is
        if((*r_full_path = strndup(file, PATH_MAX)) == NULL)
        {
            return SDP_ERROR_MEMORY_ALLOCATION;
        }
        return SDP_SUCCESS;
    }

    // Deal with ./ at start of file
    if('.' == file[0] && '/' == file[1])
    {
        file_str_offset = 2;
        file_str_len = file_str_len - 2;
    }

    // get the working dir
    if((getcwd(full_path, PATH_MAX + 1)) == NULL)
    {
        log_msg(LOG_ERR, "Failed to get current directory");
        return SDP_ERROR_FILESYSTEM_OPERATION;
    }

    // get the length and add 1 for the slash still needed
    dir_str_len = strnlen(full_path, PATH_MAX + 1) + 1;

    if(PATH_MAX < dir_str_len + file_str_len)
    {
        log_msg(LOG_ERR, "Absolute path will exceed PATH_MAX: %d", PATH_MAX);
        return SDP_ERROR_ABSOLUTE_PATH;
    }

    strncat(full_path, "/", 1);
    strncat(full_path, &(file[file_str_offset]), (PATH_MAX-dir_str_len));

    if((*r_full_path = strndup(full_path, PATH_MAX)) == NULL)
    {
        return SDP_ERROR_MEMORY_ALLOCATION;
    }

    return SDP_SUCCESS;
}
