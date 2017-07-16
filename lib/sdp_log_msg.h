/*
 *****************************************************************************
 *
 * File:    sdp_log_msg.h
 *
 *****************************************************************************
*/
#ifndef SDP_LOG_MSG_H
#define SDP_LOG_MSG_H

#include <syslog.h>
#include <stdarg.h>

/* The LOG_STDERR value can be or'ed with the msg_log() level value
 * to cause message going to syslog to be printed to stderr as well.
 * LOG_STDERR_ONLY can be set to send a message stderr with a copy to
 * syslog as well.
*/
#define LOG_SYSLOG_ONLY         0x0000
#define LOG_STDERR              0x1000
#define LOG_WITHOUT_SYSLOG      0x2000
#define LOG_STDERR_ONLY         (LOG_STDERR | LOG_WITHOUT_SYSLOG)
#define LOG_VERBOSITY_MASK      0x0FFF

#define LOG_DEFAULT_VERBOSITY   LOG_NOTICE     /*!< Default verbosity to use */

enum {
	LOGGING_NOT_INITIALIZED = 0,
	LOGGING_INITIALIZED     = 1
};

#define log_msg(I, M, ...) log_msg_final(I, "(%s:%d) " M, __FILE__, __LINE__, ##__VA_ARGS__)


int  init_logging(int foreground, int use_syslog, char *log_facility, int verbosity);
void log_msg_final(int, char*, ...);
void log_set_verbosity(int level);

#endif /* SDP_LOG_MSG_H */

/***EOF***/
