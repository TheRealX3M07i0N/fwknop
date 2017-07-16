/*
 *****************************************************************************
 *
 * File:    log_msg.c
 *
 *
 *****************************************************************************
*/
#include "sdp_ctrl_client.h"
#include "sdp_log_msg.h"
#include "sdp_errors.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int  logging_state = LOGGING_NOT_INITIALIZED;

/* The default log facility (can be overridden via config file directive).
*/
static int  syslog_fac      = LOG_DAEMON;

/* This value is or'ed with the log level on all logging calls. This allows
 * for force log to stderr instead of syslog simply be setting this to the
 * appropriate value (which is done at init_logging().
*/
static int  static_log_flag = LOG_STDERR_ONLY;

/* The name to use for ID in log messages.  This defaults to fwknopd.
*/
static char *log_name = "sdp_ctrl_client";

/* The value of the default verbosity used by the log module */
static int log_verbosity = LOG_DEFAULT_VERBOSITY;


int init_logging(int foreground, int use_syslog, char *log_facility, int new_verbosity) {

    static_log_flag = LOG_SYSLOG_ONLY;

    // If we are running in the foreground all logging will go to stderr.
    if(foreground != 0)
        static_log_flag = LOG_STDERR_ONLY;

    // If the caller forces syslog, remove the LOG_WITHOUT_SYSLOG flag
    if(use_syslog != 0)
        static_log_flag &= ~LOG_WITHOUT_SYSLOG;

    /* Parse the log facility as specified in the config struct. If, for some
     * reason, it is not, fac will already be set to LOG_DAEMON.
    */
    if(log_facility != NULL && log_facility != '\0')
    {
        if(!strcasecmp(log_facility, "LOG_DAEMON"))
            syslog_fac = LOG_DAEMON;
        else if(!strcasecmp(log_facility, "LOG_LOCAL0"))
            syslog_fac = LOG_LOCAL0;
        else if(!strcasecmp(log_facility, "LOG_LOCAL1"))
            syslog_fac = LOG_LOCAL1;
        else if(!strcasecmp(log_facility, "LOG_LOCAL2"))
            syslog_fac = LOG_LOCAL2;
        else if(!strcasecmp(log_facility, "LOG_LOCAL3"))
            syslog_fac = LOG_LOCAL3;
        else if(!strcasecmp(log_facility, "LOG_LOCAL4"))
            syslog_fac = LOG_LOCAL4;
        else if(!strcasecmp(log_facility, "LOG_LOCAL5"))
            syslog_fac = LOG_LOCAL5;
        else if(!strcasecmp(log_facility, "LOG_LOCAL6"))
            syslog_fac = LOG_LOCAL6;
        else if(!strcasecmp(log_facility, "LOG_LOCAL7"))
            syslog_fac = LOG_LOCAL7;
        else
        {
            fprintf(stderr, "Invalid SYSLOG_FACILITY setting '%s'\n",
                    log_facility);
            return SDP_ERROR_SYSLOG;
        }
    }

    log_verbosity = new_verbosity;

    logging_state = LOGGING_INITIALIZED;

    return SDP_SUCCESS;
}


void log_msg_final(int level, char* msg, ...)
{
    va_list ap, apse;

    // Make sure the level is in the right range
    if ((level & LOG_VERBOSITY_MASK) > log_verbosity)
        return;

    va_start(ap, msg);

    level |= static_log_flag;

    // Print msg to stderr if the level was or'ed with LOG_STDERR
    if(LOG_STDERR & level)
    {
        // Need to make a copy of our va_list so we don't screw
        // up the message going to syslog after we print it to stderr.
        va_copy(apse, ap);

        vfprintf(stderr, msg, apse);
        fprintf(stderr, "\n");
        fflush(stderr);

        va_end(apse);
    }

    // If logging was not yet initialized, OR
    // the message should not be printed to the syslog, return
    if ( (logging_state == LOGGING_NOT_INITIALIZED) || (LOG_WITHOUT_SYSLOG & level) )
    {
        va_end(ap);
        return;
    }


    // Remove the static log flags from the level
    level &= LOG_VERBOSITY_MASK;

    // Send the message to syslog.
    openlog(log_name, LOG_PID, syslog_fac);

    vsyslog(level, msg, ap);

    va_end(ap);
}

void log_set_verbosity(int level)
{
    log_verbosity = level;
}

// ***EOF***
