/*
 * sdp_ctrl_client_config_init.c
 *
 *  Created on: Apr 11, 2016
 *      Author: hydrolucid3
 */

#include "sdp_ctrl_client_config.h"

#include <stdint.h>
#include <unistd.h>
#include "sdp_util.h"
#include "sdp_errors.h"
#include "sdp_log_msg.h"

const char *sdp_ctrl_client_default_pid_file = "/var/run/sdp_ctrl_client.pid";
const char *sdp_ctrl_client_default_fwknop_path = "fwknop";


// this must always be updated in conjunction with the
// config enumeration in sdp_ctrl_client_config.h
const char *sdp_ctrl_client_config_map[SDP_CTRL_CLIENT_CONFIG_ENTRIES] = {
    "CTRL_PORT",
    "CTRL_ADDR",
    "USE_SPA",
    "FWKNOP_PATH",
    "CTRL_STANZA",
    "REMAIN_CONNECTED",
    "FOREGROUND",
    "USE_SYSLOG",
    "VERBOSITY",
    "KEY_FILE",
    "CERT_FILE",
    "SPA_ENCRYPTION_KEY",
    "SPA_HMAC_KEY",
    "MSG_Q_LEN",
    "POST_SPA_DELAY",
    "READ_TIMEOUT",
    "WRITE_TIMEOUT",
    "CREDENTIAL_UPDATE_INTERVAL",
    "ACCESS_REFRESH_INTERVAL",
    "SERVICE_REFRESH_INTERVAL",
    "MAX_CONN_ATTEMPTS",
    "INITIAL_CONN_RETRY_INTERVAL",
    "KEEP_ALIVE_INTERVAL",
    "MAX_REQUEST_ATTEMPTS",
    "INITIAL_REQUEST_RETRY_INTERVAL",
    "PID_FILE"
};


static int is_conf_var(const char *map_var, const char *var)
{
    return (strncmp(map_var, var, SDP_MAX_LINE_LEN) == 0);
}

static void set_defaults(sdp_ctrl_client_t client)
{
    client->com->use_spa = DEFAULT_USE_SPA;
    client->com->max_conn_attempts = DEFAULT_MAX_CONN_ATTEMPTS;
    client->use_syslog = DEFAULT_USE_SYSLOG;
    client->remain_connected = DEFAULT_REMAIN_CONNECTED;
    client->foreground = DEFAULT_FOREGROUND;
    client->verbosity = LOG_DEFAULT_VERBOSITY;
}


static int finalize_config(sdp_ctrl_client_t client)
{
    int rv = SDP_SUCCESS;

    client->client_state = SDP_CTRL_CLIENT_STATE_READY;

    if(!(client->com->ctrl_port))
    {
        log_msg(LOG_ERR, "Controller port not specified");
        return SDP_ERROR_CONFIG;
    }

    if(!(client->com->ctrl_addr))
    {
        log_msg(LOG_ERR, "Controller address not specified");
        return SDP_ERROR_CONFIG;
    }

    if(!(client->com->key_file))
    {
        log_msg(LOG_ERR, "Key file not specified");
        return SDP_ERROR_CONFIG;
    }

    if(!(client->com->fwknop_path))
    {
        client->com->fwknop_path = strndup(sdp_ctrl_client_default_fwknop_path, PATH_MAX);
        if(client->com->fwknop_path == NULL)
        {
            sdp_ctrl_client_destroy(client);
            return(SDP_ERROR_MEMORY_ALLOCATION);
        }
    }

    if(client->com->use_spa && client->com->fwknoprc_file == NULL)
    {
        log_msg(LOG_ERR, "SDP CTRL Client config error: USE_SPA set to 'Y' but fwknoprc file not specified.");
        return SDP_ERROR_CONFIG;
    }

    if(!(client->com->cert_file))
    {
        log_msg(LOG_ERR, "Cert file not specified");
        return SDP_ERROR_CONFIG;
    }

    if( !(client->message_queue_len))
        client->message_queue_len = DEFAULT_MSG_Q_LEN;

    if( !(client->com->post_spa_delay.tv_nsec) &&
        !(client->com->post_spa_delay.tv_sec))
    {
        client->com->post_spa_delay.tv_nsec = DEFAULT_POST_SPA_DELAY_NANOSECONDS;
        client->com->post_spa_delay.tv_sec  = DEFAULT_POST_SPA_DELAY_SECONDS;
    }

    if( !(client->com->read_timeout.tv_sec))
        client->com->read_timeout.tv_sec = DEFAULT_READ_TIMOUT_SECONDS;
    client->com->read_timeout.tv_usec = 0;

    if( !(client->com->write_timeout.tv_sec))
        client->com->write_timeout.tv_sec = DEFAULT_WRITE_TIMOUT_SECONDS;
    client->com->write_timeout.tv_usec = 0;

    if( !(client->com->initial_conn_attempt_interval))
        client->com->initial_conn_attempt_interval = DEFAULT_INTERVAL_INITIAL_RETRY_SECONDS;

    if((rv = sdp_com_init(client->com)) != SDP_SUCCESS)
        return rv;

    if( !(client->cred_update_interval))
        client->cred_update_interval = DEFAULT_INTERVAL_CRED_UPDATE_SECONDS;

    if( !(client->service_refresh_interval))
        client->service_refresh_interval = DEFAULT_INTERVAL_SERVICE_REFRESH_SECONDS;

    if( !(client->access_refresh_interval))
        client->access_refresh_interval = DEFAULT_INTERVAL_ACCESS_REFRESH_SECONDS;

    if( !(client->max_req_attempts))
        client->max_req_attempts = DEFAULT_MAX_REQ_ATTEMPTS;

    if( !(client->initial_req_retry_interval))
        client->initial_req_retry_interval = DEFAULT_INTERVAL_REQ_RETRY_SECONDS;

    if( !(client->req_retry_interval))
        client->req_retry_interval = DEFAULT_INTERVAL_REQ_RETRY_SECONDS;

    if( !(client->keep_alive_interval))
        client->keep_alive_interval = DEFAULT_INTERVAL_KEEP_ALIVE_SECONDS;

    if( !(client->pid_file))
    {
        client->pid_file = strndup(sdp_ctrl_client_default_pid_file, PATH_MAX);
        if(client->pid_file == NULL)
        {
            sdp_ctrl_client_destroy(client);
            return(SDP_ERROR_MEMORY_ALLOCATION);
        }
    }

    if((rv = init_logging(client->foreground, client->use_syslog, NULL, client->verbosity)) != SDP_SUCCESS)
    {
        log_msg(LOG_ERR, "Failed to initialize logging");
        return rv;
    }

    client->initialized = 1;

    return SDP_SUCCESS;

}


int sdp_ctrl_client_config_init(sdp_ctrl_client_t client, const char *config_file,
                                const char *fwknoprc_file, const int foreground)
{
    int             rv = SDP_SUCCESS;
    FILE           *cfile_ptr;
    unsigned int    numLines = 0;
    unsigned int    i, good_ent;

    char            conf_line_buf[SDP_MAX_LINE_LEN] = {0};
    char            var[SDP_MAX_LINE_LEN]  = {0};
    char            val[SDP_MAX_LINE_LEN]  = {0};
    char            current_dir[PATH_MAX+1] = {0};

    struct stat     st;

    // Make sure the client object exists
    if(client == NULL)
    {
        log_msg(LOG_ERR, "sdp_ctrl_client_t client object is NULL.");
        return SDP_ERROR_CONFIG;
    }

    // Make sure the config file exists.
    if(config_file == NULL)
    {
        log_msg(LOG_ERR, "Config file not specified.");
        return SDP_ERROR_CONFIG;
    }

    if(stat(config_file, &st) != 0)
    {
        log_msg(LOG_ERR, "Config file: '%s' was not found.",
            config_file);

        // get the working dir
        if((getcwd(current_dir, PATH_MAX+1)) == NULL)
        {
            log_msg(LOG_ERR, "Failed to get current directory");
        }
        else
        {
            log_msg(LOG_ERR, "Running from: %s", current_dir);
        }

        return SDP_ERROR_CONFIG;
    }

    if(fwknoprc_file != NULL && stat(fwknoprc_file, &st) != 0)
    {
        log_msg(LOG_ERR, ".fwknoprc file: '%s' was not found.",
            config_file);

        // get the working dir
        if((getcwd(current_dir, PATH_MAX+1)) == NULL)
        {
            log_msg(LOG_ERR, "Failed to get current directory");
        }
        else
        {
            log_msg(LOG_ERR, "Running from: %s", current_dir);
        }

        return SDP_ERROR_CONFIG;
    }

    // store config file location for later use
    if((rv = sdp_make_absolute_path(config_file, &(client->config_file))) != SDP_SUCCESS)
    {
        log_msg(LOG_ERR, "Error storing sdp ctrl client config file path");
        return rv;
    }

    log_msg(LOG_DEBUG, "SDP ctrl client config file absolute path: %s", client->config_file);


    // store fwknoprc file location for later use if given
    if(fwknoprc_file == NULL)
    {
        client->com->fwknoprc_file = NULL;
    }
    else if((rv = sdp_make_absolute_path(fwknoprc_file, &(client->com->fwknoprc_file))) != SDP_SUCCESS)
    {
        log_msg(LOG_ERR, "Error storing fwknop config file path");
        return rv;
    }

    log_msg(LOG_DEBUG, "fwknop config file absolute path: %s", client->com->fwknoprc_file);

    // set a few default values, not ALL though, before proceeding
    set_defaults(client);

    if ((cfile_ptr = fopen(config_file, "r")) == NULL)
    {
        log_msg(LOG_ERR, "Could not open config file: %s",
            config_file);
        perror(NULL);

        return SDP_ERROR_CONFIG;
    }

    //log_msg(LOG_DEBUG, "Opened config file: %s", config_file);

    while ((fgets(conf_line_buf, SDP_MAX_LINE_LEN, cfile_ptr)) != NULL)
    {
        numLines++;
        conf_line_buf[SDP_MAX_LINE_LEN-1] = '\0';

        /* Get past comments and empty lines (note: we only look at the
         * first character.
        */
        //log_msg(LOG_DEBUG, "Looking at line: %s", conf_line_buf);
        if(IS_EMPTY_LINE(conf_line_buf[0]))
            continue;

        //log_msg(LOG_DEBUG, "Scanning line: %s", conf_line_buf);
        if(sscanf(conf_line_buf, "%s %[^;\n\r]", var, val) != 2)
        {
            log_msg(LOG_ERR,
                "Invalid config file entry in %s at line %i. - '%s'",
                config_file, numLines, conf_line_buf
            );
            continue;
        }

        good_ent = 0;
        //log_msg(LOG_DEBUG, "Starting for loop on line: %s", conf_line_buf);
        for(i=0; i<SDP_CTRL_CLIENT_CONFIG_ENTRIES; i++)
        {
            if(is_conf_var(sdp_ctrl_client_config_map[i], var))
            {
                log_msg(LOG_DEBUG, "Found matching var: %s", var);
                if((rv = sdp_ctrl_client_set_config_entry(client, i, val)) != SDP_SUCCESS)
                {
                    log_msg(LOG_ERR, "Error setting config entry: %s", var);
                    goto cleanup;
                }
                //log_msg(LOG_DEBUG, "Set var: %s", var);
                good_ent++;
                break;
            }
        }

        if(good_ent == 0)
            log_msg(LOG_WARNING,
                "Ignoring unknown configuration parameter: '%s' in %s",
                var, config_file
            );
    }

    // only override the config file if this variable is set to zero
    if(!foreground)
        client->foreground = 0;

    rv = finalize_config(client);

cleanup:
    fclose(cfile_ptr);

    return rv;
}

static int yes_or_no(const char *val)
{
    return ((strncasecmp(val, "Y", 1) == 0) ? 1 : 0);
}

int sdp_ctrl_client_set_config_entry(sdp_ctrl_client_t client, int var, const char *val)
{
    int rv = SDP_SUCCESS;
    long double time_flt = 0;

    /* Sanity check the index value.
    */
    if(var < 0 || var >= SDP_CTRL_CLIENT_CONFIG_ENTRIES)
    {
        log_msg(LOG_ERR, "Index value of %i is not valid", var);
        return SDP_ERROR_CONFIG;
    }

    switch(var) {
        case SDP_CTRL_CLIENT_CONFIG_CTRL_PORT:
            client->com->ctrl_port = sdp_strtol_wrapper(val, 0,
                    UINT16_MAX, &rv);
            break;

        case SDP_CTRL_CLIENT_CONFIG_CTRL_ADDR:
            client->com->ctrl_addr = strndup(val, PATH_MAX);
            if(client->com->ctrl_addr == NULL)
            {
                rv = SDP_ERROR_MEMORY_ALLOCATION;
            }
            break;

        case SDP_CTRL_CLIENT_CONFIG_USE_SPA:
            client->com->use_spa = yes_or_no(val);
            break;

        case SDP_CTRL_CLIENT_CONFIG_FWKNOP_PATH:
            if((rv = sdp_make_absolute_path(val, &(client->com->fwknop_path))) != SDP_SUCCESS)
            {
                log_msg(LOG_ERR, "Error storing fwknop executable path");
            }
            break;

        case SDP_CTRL_CLIENT_CONFIG_CTRL_STANZA:
            client->com->ctrl_stanza = strndup(val, SDP_MAX_LINE_LEN);
            if(client->com->ctrl_stanza == NULL)
            {
                rv = SDP_ERROR_MEMORY_ALLOCATION;
            }
            break;

        case SDP_CTRL_CLIENT_CONFIG_REMAIN_CONNECTED:
            client->remain_connected = yes_or_no(val);
            break;

        case SDP_CTRL_CLIENT_CONFIG_FOREGROUND:
            client->foreground = yes_or_no(val);
            break;

        case SDP_CTRL_CLIENT_CONFIG_USE_SYSLOG:
            client->use_syslog = yes_or_no(val);
            break;

        case SDP_CTRL_CLIENT_CONFIG_VERBOSITY:
            client->verbosity = sdp_strtol_wrapper(val, 0, 7, &rv);
            break;

        case SDP_CTRL_CLIENT_CONFIG_KEY_FILE:
            if((rv = sdp_make_absolute_path(val, &(client->com->key_file))) != SDP_SUCCESS)
            {
                log_msg(LOG_ERR, "Error storing TLS key file path");
            }
            break;

        case SDP_CTRL_CLIENT_CONFIG_CERT_FILE:
            if((rv = sdp_make_absolute_path(val, &(client->com->cert_file))) != SDP_SUCCESS)
            {
                log_msg(LOG_ERR, "Error storing TLS cert file path");
            }
            break;

        case SDP_CTRL_CLIENT_CONFIG_SPA_ENCRYPTION_KEY:
            client->com->spa_encryption_key = strndup(val, SDP_MAX_B64_KEY_LEN);
            if(client->com->spa_encryption_key == NULL)
            {
                rv = SDP_ERROR_MEMORY_ALLOCATION;
            }
            break;

        case SDP_CTRL_CLIENT_CONFIG_SPA_HMAC_KEY:
            client->com->spa_hmac_key = strndup(val, SDP_MAX_B64_KEY_LEN);
            if(client->com->spa_hmac_key == NULL)
            {
                rv = SDP_ERROR_MEMORY_ALLOCATION;
            }
            break;

        case SDP_CTRL_CLIENT_CONFIG_MSG_Q_LEN:
            client->message_queue_len = sdp_strtol_wrapper(val, 1,
                    SDP_MAX_MSG_Q_LEN, &rv);
            break;

        case SDP_CTRL_CLIENT_CONFIG_POST_SPA_DELAY:
            time_flt = sdp_strtold_wrapper(val, 0, SDP_MAX_POST_SPA_DELAY, &rv);
            if(rv == SDP_SUCCESS)
            {
                // this assignment drops everything after the decimal
                client->com->post_spa_delay.tv_sec = time_flt;
                client->com->post_spa_delay.tv_nsec = NANOS_PER_SECOND *
                        (time_flt - client->com->post_spa_delay.tv_sec);
            }
            break;

        case SDP_CTRL_CLIENT_CONFIG_READ_TIMEOUT:
            client->com->read_timeout.tv_sec = sdp_strtol_wrapper(val, 0,
                    INT32_MAX, &rv);
            break;

        case SDP_CTRL_CLIENT_CONFIG_WRITE_TIMEOUT:
            client->com->write_timeout.tv_sec = sdp_strtol_wrapper(val, 0,
                    INT32_MAX, &rv);
            break;

        case SDP_CTRL_CLIENT_CONFIG_CRED_UPDATE_INTERVAL:
            client->cred_update_interval = sdp_strtol_wrapper(val, 0,
                    INT32_MAX, &rv);
            break;

        case SDP_CTRL_CLIENT_CONFIG_SERVICE_REFRESH_INTERVAL:
            client->service_refresh_interval = sdp_strtol_wrapper(val, 0,
                    INT32_MAX, &rv);
            break;

        case SDP_CTRL_CLIENT_CONFIG_ACCESS_REFRESH_INTERVAL:
            client->access_refresh_interval = sdp_strtol_wrapper(val, 0,
                    INT32_MAX, &rv);
            break;

        case SDP_CTRL_CLIENT_CONFIG_MAX_CONN_ATTEMPTS:
            client->com->max_conn_attempts = sdp_strtol_wrapper(val, 0,
                    INT32_MAX, &rv);
            break;

        case SDP_CTRL_CLIENT_CONFIG_INIT_CONN_RETRY_INTERVAL:
            client->com->initial_conn_attempt_interval = sdp_strtol_wrapper(val, 0,
                    SDP_COM_MAX_RETRY_INTERVAL_SECONDS, &rv);
            break;

        case SDP_CTRL_CLIENT_CONFIG_KEEP_ALIVE_INTERVAL:
            client->keep_alive_interval = sdp_strtol_wrapper(val, 0,
                    INT32_MAX, &rv);
            break;

        case SDP_CTRL_CLIENT_CONFIG_MAX_REQUEST_ATTEMPTS:
            client->max_req_attempts = sdp_strtol_wrapper(val, 0,
                    INT32_MAX, &rv);
            break;

        case SDP_CTRL_CLIENT_CONFIG_INIT_REQUEST_RETRY_INTERVAL:
            client->initial_req_retry_interval = sdp_strtol_wrapper(val, 0,
                    SDP_COM_MAX_RETRY_INTERVAL_SECONDS, &rv);
            break;

        case SDP_CTRL_CLIENT_CONFIG_PID_FILE:
            if((rv = sdp_make_absolute_path(val, &(client->pid_file))) != SDP_SUCCESS)
            {
                log_msg(LOG_ERR, "Error storing PID file path");
            }
            break;

        default:
            // do nothing
            break;
    }

    return rv;
}

