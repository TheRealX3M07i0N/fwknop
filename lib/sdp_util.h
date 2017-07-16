/*
 *****************************************************************************
 *
 * File:    sdp_util.h
 *
 *
 *****************************************************************************
*/
#ifndef SDP_UTIL_H
#define SDP_UTIL_H 1

#include <stddef.h>

#define EXIT_UPON_ERR 1
#define NO_EXIT_UPON_ERR 0

int  sdp_append_msg_to_buf(char *buf, size_t buf_size, const char* msg, ...);
int  sdp_strtol_wrapper(const char * const str, const int min,
            const int max, int *is_err);
long double sdp_strtold_wrapper(const char * const str, const int min,
            const int max, int *is_err);
int  sdp_move_file_to_backup(const char *file_path);
int  sdp_save_to_file(const char *file_path, const char *data);
int  sdp_restore_file(const char *file_path);
int  sdp_replace_spa_keys(const char *file_path,
					      const char *old_key1, const char *new_key1, const int min_key1_matches,
						  const char *old_key2, const char *new_key2, const int min_key2_matches);
int  sdp_make_absolute_path(const char *file, char **r_full_path);
#endif /* SDP_UTIL_H */

/***EOF***/
