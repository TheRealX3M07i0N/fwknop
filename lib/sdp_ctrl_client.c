/*
 * sdp_ctrl_client.c
 *
 *  Created on: Mar 28, 2016
 *      Author: Daniel Bailey
 */

#include "sdp_ctrl_client.h"
#include "sdp_ctrl_client_config.h"
#include "sdp_log_msg.h"
#include "sdp_util.h"
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <resolv.h>
#include <netdb.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <json-c/json.h>
#include <pthread.h>

#ifndef HAVE_STAT
#define HAVE_STAT 1
#endif

// Some hoops for accommodating Windows

#ifdef WIN32
  #include <io.h>
  #define strcasecmp    _stricmp
  #define strncasecmp    _strnicmp
  #define snprintf        _snprintf
  #define unlink        _unlink
  #define open            _open
  #define fdopen        _fdopen
  #define close            _close
  #define write            _write
  #define popen            _popen
  #define pclose        _pclose
  #define O_WRONLY        _O_WRONLY
  #define O_RDONLY        _O_RDONLY
  #define O_RDWR        _O_RDWR
  #define O_CREAT        _O_CREAT
  #define O_EXCL        _O_EXCL
  #define S_IRUSR        _S_IREAD
  #define S_IWUSR        _S_IWRITE
  #define PATH_SEP      '\\'
  // --DSS needed for VS versions before 2010
  typedef __int8 int8_t;
  typedef unsigned __int8 uint8_t;
  typedef __int16 int16_t;
  typedef unsigned __int16 uint16_t;
  typedef __int32 int32_t;
  typedef unsigned __int32 uint32_t;
  typedef __int64 int64_t;
  typedef unsigned __int64 uint64_t;

#else
  #include <signal.h>
  #define PATH_SEP      '/'
#endif


#define CTRL_CLIENT_CTX_DUMP_BUFSIZE            4096
#define PID_BUFLEN 7


sig_atomic_t sdp_ctrl_client_got_signal     = 0;    // General signal flag (break capture)

sig_atomic_t sdp_ctrl_client_got_sighup     = 0;    // SIGHUP flag
sig_atomic_t sdp_ctrl_client_got_sigint     = 0;    // SIGINT flag
sig_atomic_t sdp_ctrl_client_got_sigterm    = 0;    // SIGTERM flag
sig_atomic_t sdp_ctrl_client_got_sigusr1    = 0;    // SIGUSR1 flag
sig_atomic_t sdp_ctrl_client_got_sigusr2    = 0;    // SIGUSR2 flag
sig_atomic_t sdp_ctrl_client_got_sigchld    = 0;    // SIGCHLD flag

sigset_t    *ctrl_client_csmask;





// PRIVATE FUNCTION PROTOTYPES
static int  sdp_ctrl_client_clean_exit(sdp_ctrl_client_t client, int status);
static int  sdp_ctrl_client_setup_pid(sdp_ctrl_client_t client, pid_t *r_pid);
static int  sdp_ctrl_client_daemonize(sdp_ctrl_client_t client, pid_t *r_pid);
static int  sdp_ctrl_client_handle_signals(sdp_ctrl_client_t client);
static void sdp_ctrl_client_sig_handler(int sig);
static int  sdp_ctrl_client_set_sig_handlers(void);
static int  sdp_ctrl_client_write_pid_file(sdp_ctrl_client_t client, pid_t *r_old_pid);
static int  sdp_ctrl_client_get_running_pid(sdp_ctrl_client_t client, pid_t *r_pid);
static int  sdp_ctrl_client_verify_file_perms(const char *file);
static int  sdp_ctrl_client_loop(sdp_ctrl_client_t client);
static void sdp_ctrl_client_clear_state_vars(sdp_ctrl_client_t client);
static void sdp_ctrl_client_set_request_vars(sdp_ctrl_client_t client, sdp_ctrl_client_state_t new_state);
//static void sdp_ctrl_client_set_failed_request_vars(sdp_ctrl_client_t client, sdp_ctrl_client_state_t new_state);
static int  sdp_ctrl_client_save_credentials(sdp_ctrl_client_t client, sdp_creds_t creds);
static void sdp_ctrl_client_destroy_internals(sdp_ctrl_client_t client);
static int  sdp_ctrl_client_restart_myself(sdp_ctrl_client_t client);


// PUBLIC FUNCTION DEFINITIONS
// ======================================================================================
// ======================================================================================
// ======================================================================================
// ======================================================================================
// ======================================================================================
// ======================================================================================
// ======================================================================================


/**
 * @brief Create and initialize a new sdp_ctrl_client_t object
 *
 * This function performs a calloc for the object and uses a configuration file to
 * initialize the object.
 *
 * @param config_file - Path to SDP CTRL CLIENT config file.
 * @param fwknoprc_file - Path to fwknop config file.
 * @param r_client - This pointer is used to return the new object.
 *
 * @return SDP_SUCCESS if the object is successfully created, an error code otherwise.
 */
int sdp_ctrl_client_new(const char *config_file, const char *fwknoprc_file,
                        const int foreground, sdp_ctrl_client_t *r_client)
{
    sdp_ctrl_client_t client = NULL;
    int rv = SDP_SUCCESS;

    //
    // allocate memory
    if((client = calloc(1, sizeof *client)) == NULL)
        return (SDP_ERROR_MEMORY_ALLOCATION);

    // create the com object
    if((rv = sdp_com_new(&(client->com))) != SDP_SUCCESS)
        return sdp_ctrl_client_clean_exit(client, rv);


    if((rv = sdp_ctrl_client_config_init(client, config_file, fwknoprc_file, foreground)) != SDP_SUCCESS)
        return sdp_ctrl_client_clean_exit(client, rv);

    *r_client = client;
    return rv;
}


/**
 * @brief Deallocate all memory associated with a sdp_ctrl_client_t object
 *
 * @param client - The pointer to the object being destroyed.
 *
 * @return void.
 */
void sdp_ctrl_client_destroy(sdp_ctrl_client_t client)
{
    if(client == NULL)
        return;

    sdp_ctrl_client_destroy_internals(client);

    free(client);
}


/**
 * @brief Start the sdp ctrl client loop
 *
 * This function starts the sdp ctrl client run loop. If the client is configured to
 * both remain connected to the controller and to run in the background, this function
 * will fork a child process to daemonize the ctrl client. The parent process will
 * return immediately to allow any cleanup or continued execution outside of this
 * module. The child process or main thread if not forking will then enter the sdp ctrl
 * client run loop. The child or main thread will also return whenever it exits
 * the run loop, returning an error code if applicable.
 *
 * If not configured to remain connected, the client will connect, request a credential
 * update, and then exit. Otherwise it will continue running until interrupted by a signal
 * or error.
 *
 * @param client - sdp_ctrl_client_t object.
 * @param r_child_pid - This pointer is used to return the child PID.
 *
 * @return SDP_SUCCESS or an error code.
 */
int sdp_ctrl_client_start(sdp_ctrl_client_t client, pid_t *r_child_pid)
{
    int rv = SDP_SUCCESS;
    pid_t child_pid = -1;
    *r_child_pid = -1;

    if(client == NULL || !client->initialized)
        return SDP_ERROR_UNINITIALIZED;

    if(!client->foreground)
    {
        if((rv = sdp_ctrl_client_setup_pid(client, &child_pid)) != SDP_SUCCESS)
        {
            return rv;
        }

        *r_child_pid = child_pid;

        if(child_pid > 0)
        {
            // I'm the parent, just return
            return SDP_SUCCESS;
        }
    }

    // I'm the client process, time to run free
    rv = sdp_ctrl_client_loop(client);

    return rv;
}


/**
 * @brief Listen for data from the controller
 *
 * This function starts an sdp ctrl client run loop. This function can be configured to
 * listen indefinitely or for a max number of seconds. Whenever the controller sends
 * access data, this function passes that data up to the caller as a json array object.
 * The function also watches for credential updates meant for the calling process and
 * handles these internally, i.e. storing the new credentials. The function also watches
 * the clock to send keep-alive messages to the controller.
 *
 * @param client - sdp_ctrl_client_t object.
 * @param max_time - return after max_time even if no access data was received. Zero
 *                      indicates to listen indefinitely.
 * @param r_data - json data object containing access data
 *
 * @return SDP_SUCCESS or an error code.
 */
int sdp_ctrl_client_listen(sdp_ctrl_client_t client, int max_time, int *r_action, void **r_data)
{
    int rv = SDP_SUCCESS;
    void *data = NULL;
    time_t stop_time = time(NULL) + max_time;
    int action = INVALID_CTRL_ACTION;

    if(client == NULL || !client->initialized)
        return SDP_ERROR_UNINITIALIZED;

    while(1)
    {
        // connect if necessary
        if(client->com->conn_state == SDP_COM_DISCONNECTED)
        {
            if((rv = sdp_com_connect(client->com)) != SDP_SUCCESS)
            {
                break;
            }
            client->initial_conn_time = client->last_contact = time(NULL);
        }

        // check for incoming messages
        if((rv = sdp_ctrl_client_check_inbox(client, &action, &data)) != SDP_SUCCESS)
            break;

        // if data was returned, it must be passed up to the caller
        if(data != NULL)
        {
            log_msg(LOG_DEBUG, "sdp_ctrl_client_check_inbox returned data, passing up to caller");
            *r_action = action;
            *r_data = data;
            break;
        }

        // do not begin sending requests until controller is ready
        if( !(client->controller_ready) )
            continue;

        // if new connection or just time, update credentials
        if((rv = sdp_ctrl_client_consider_cred_update(client)) != SDP_SUCCESS)
            break;

        // if built for remote gateway, handle access updates
        if((rv = sdp_ctrl_client_consider_access_refresh(client)) != SDP_SUCCESS)
            break;

        // is a keep alive due
        if((rv = sdp_ctrl_client_consider_keep_alive(client)) != SDP_SUCCESS)
            break;

        // watch the time
        if( max_time && (time(NULL) > stop_time) )
            break;

        sleep(1);
    }

    return rv;
}


/**
 * @brief Stop the sdp ctrl client loop
 *
 * This function stops the sdp ctrl client run loop.
 *
 * @param client - sdp_ctrl_client_t object.
 *
 * @return SDP_SUCCESS or an error code.
 */
int sdp_ctrl_client_stop(sdp_ctrl_client_t client)
{
    int      res = 0, is_err = 0;
    pid_t    old_pid = 0;

    if(client == NULL || !client->initialized)
        return SDP_ERROR_UNINITIALIZED;

    sdp_ctrl_client_get_running_pid(client, &old_pid);

    if(old_pid > 0)
    {
        res    = kill(old_pid, SIGTERM);
        is_err = kill(old_pid, 0);

        if(res == 0 && is_err != 0)
        {
            log_msg(LOG_WARNING, "Killed SDP Control Client (pid=%i)", old_pid);
            return SDP_SUCCESS;
        }
        else
        {
            // give a bit of time for process shutdown and check again
            sleep(1);
            is_err = kill(old_pid, 0);
            if(is_err != 0)
            {
                log_msg(LOG_WARNING, "Killed SDP Control Client (pid=%i) via SIGTERM",
                        old_pid);
                return SDP_SUCCESS;
            }
            else
            {
                res    = kill(old_pid, SIGKILL);
                is_err = kill(old_pid, 0);
                if(res == 0 && is_err != 0)
                {
                    log_msg(LOG_WARNING,
                            "Killed SDP Control Client (pid=%i) via SIGKILL",
                            old_pid);
                    return SDP_SUCCESS;
                }
                else
                {
                    sleep(1);
                    is_err = kill(old_pid, 0);
                    if(is_err != 0)
                    {
                        log_msg(LOG_WARNING,
                                "Killed SDP Control Client (pid=%i) via SIGKILL",
                                old_pid);
                        return SDP_SUCCESS;
                    }
                    else
                    {
                        perror("Unable to kill SDP Control Client: ");
                        return SDP_ERROR;
                    }
                }
            }
        }
    }

    log_msg(LOG_WARNING, "No running SDP Control Client detected.");
    return SDP_ERROR;
}

/**
 * @brief Restart the sdp ctrl client
 *
 * This function restarts an sdp ctrl client running in the background by sending
 * SIGHUP. The background process disconnects if necessary, destroys all internal
 * data structures and zeros all memory. It then rereads the config file to
 * initialize all internal data. Once initialized, the run loop continues.
 *
 * @param client - sdp_ctrl_client_t object.
 *
 * @return SDP_SUCCESS or an error code.
 */
int sdp_ctrl_client_restart(sdp_ctrl_client_t client)
{
    int      res = 0;
    pid_t    old_pid = 0;

    if(client == NULL || !client->initialized)
        return SDP_ERROR_UNINITIALIZED;

    sdp_ctrl_client_get_running_pid(client, &old_pid);

    if(old_pid > 0)
    {
        res = kill(old_pid, SIGHUP);
        if(res == 0)
        {
            log_msg(LOG_WARNING, "Sent restart signal to SDP Control Client (pid=%i)", old_pid);
            return SDP_SUCCESS;
        }
        else
        {
            perror("Unable to send signal to SDP Control Client: ");
            return SDP_ERROR;
        }
    }

    log_msg(LOG_WARNING, "No running SDP Control Client detected.");
    return SDP_ERROR;
}



/**
 * @brief Connect the sdp ctrl client to the configured controller
 *
 * @param client - sdp_ctrl_client_t object.
 *
 * @return SDP_SUCCESS or an error code.
 */
int sdp_ctrl_client_connect(sdp_ctrl_client_t client)
{
    int res = SDP_SUCCESS;

    if(client == NULL || !client->initialized)
        return SDP_ERROR_UNINITIALIZED;

    res = sdp_com_connect(client->com);

    if(res == SDP_SUCCESS)
    {
        client->initial_conn_time = client->last_contact = time(NULL);
    }

    return res;
}


/**
 * @brief Disconnect the sdp ctrl client from the configured controller
 *
 * @param client - sdp_ctrl_client_t object.
 *
 * @return SDP_SUCCESS or an error code.
 */
int sdp_ctrl_client_disconnect(sdp_ctrl_client_t client)
{
    if(client == NULL || !client->initialized)
        return SDP_ERROR_UNINITIALIZED;

    return sdp_com_disconnect(client->com);
}


/**
 * @brief Check whether an sdp ctrl client is currently connected
 *
 * @param client - sdp_ctrl_client_t object.
 *
 * @return SDP_COM_CONNECTED or SDP_COM_DISCONNECTED.
 */
int sdp_ctrl_client_connection_status(sdp_ctrl_client_t client)
{
    return client->com->conn_state;
}


/**
 * @brief Check whether controller is ready for requests
 *
 * @param client - sdp_ctrl_client_t object.
 *
 * @return 1 for yes, 0 for no.
 */
int sdp_ctrl_client_controller_status(sdp_ctrl_client_t client)
{
    return client->controller_ready;
}


/**
 * @brief Check whether an sdp ctrl client instance is currently running
 *
 * @param client - sdp_ctrl_client_t object.
 *
 * @return SDP_SUCCESS or an error code.
 */
int sdp_ctrl_client_status(sdp_ctrl_client_t client)
{
    pid_t    old_pid = 0;
    int rv = SDP_ERROR;

    if(client == NULL || !client->initialized)
        return SDP_ERROR_UNINITIALIZED;

    // call this function because it ensures that a running
    // process actually has a lock on the file
    if((rv = sdp_ctrl_client_write_pid_file(client, &old_pid)) != SDP_SUCCESS)
        return rv;

    if(old_pid > 0)
    {
        log_msg(LOG_WARNING, "Detected SDP Ctrl Client is running (pid=%i).", old_pid);
        return SDP_SUCCESS;
    }

    log_msg(LOG_WARNING, "No running SDP Ctrl Client detected.");
    return SDP_ERROR;
}

/**
 * @brief Print all sdp ctrl client settings in a human-readable format
 *
 * @param client - sdp_ctrl_client_t object.
 *
 * @return void.
 */
void sdp_ctrl_client_describe(sdp_ctrl_client_t client)
{
    int buf_len = CTRL_CLIENT_CTX_DUMP_BUFSIZE;
    char dump_buf[buf_len];
    int cp = 0;

    if(client == NULL || !client->initialized)
    {
        log_msg(LOG_ERR, "SDP Control Client not initialized. Cannot print details.");
        return;
    }

    memset(dump_buf, 0, buf_len);

    // dump context values
    cp  = sdp_append_msg_to_buf(dump_buf,    buf_len,    "Control Client Context Values:\n");
    cp += sdp_append_msg_to_buf(dump_buf+cp, buf_len-cp, "========================================================================\n");
    cp += sdp_append_msg_to_buf(dump_buf+cp, buf_len-cp, "                      Configuration File: %s\n", client->config_file);
    cp += sdp_append_msg_to_buf(dump_buf+cp, buf_len-cp, "                             Initialized: %s\n", YES_OR_NO(client->initialized) );
    cp += sdp_append_msg_to_buf(dump_buf+cp, buf_len-cp, "                         Controller port: %d\n", client->com->ctrl_port);
    cp += sdp_append_msg_to_buf(dump_buf+cp, buf_len-cp, "                      Controller address: %s\n", client->com->ctrl_addr);
    cp += sdp_append_msg_to_buf(dump_buf+cp, buf_len-cp, "                                 Use SPA: %s\n", YES_OR_NO(client->com->use_spa) );
    cp += sdp_append_msg_to_buf(dump_buf+cp, buf_len-cp, "           Remain connected after update: %s\n", YES_OR_NO(client->remain_connected) );
    cp += sdp_append_msg_to_buf(dump_buf+cp, buf_len-cp, "                       Run in foreground: %s\n", YES_OR_NO(client->foreground) );
    cp += sdp_append_msg_to_buf(dump_buf+cp, buf_len-cp, "                               Connected: %s\n", YES_OR_NO((int)client->com->conn_state) );
    cp += sdp_append_msg_to_buf(dump_buf+cp, buf_len-cp, "                  Last credential update: %s",   ctime( &(client->last_cred_update) ) );
    cp += sdp_append_msg_to_buf(dump_buf+cp, buf_len-cp, "                 Last full access update: %s",   ctime( &(client->last_access_refresh) ) );
    cp += sdp_append_msg_to_buf(dump_buf+cp, buf_len-cp, "              Credential update interval: %d seconds\n", client->cred_update_interval);
    cp += sdp_append_msg_to_buf(dump_buf+cp, buf_len-cp, "                 Service update interval: %d seconds\n", client->service_refresh_interval);
    cp += sdp_append_msg_to_buf(dump_buf+cp, buf_len-cp, "                  Access update interval: %d seconds\n", client->access_refresh_interval);
    cp += sdp_append_msg_to_buf(dump_buf+cp, buf_len-cp, "                     Keep alive interval: %d seconds\n", client->keep_alive_interval);
    cp += sdp_append_msg_to_buf(dump_buf+cp, buf_len-cp, "                 Max connection attempts: %d\n", client->com->max_conn_attempts);
    cp += sdp_append_msg_to_buf(dump_buf+cp, buf_len-cp, "   Connection attempts during last cycle: %d\n", client->com->conn_attempts);
    cp += sdp_append_msg_to_buf(dump_buf+cp, buf_len-cp, "       Initial connection retry interval: %d seconds\n", client->com->initial_conn_attempt_interval);
    cp += sdp_append_msg_to_buf(dump_buf+cp, buf_len-cp, "                                PID file: %s\n", client->pid_file);
    cp += sdp_append_msg_to_buf(dump_buf+cp, buf_len-cp, "                           fwknoprc file: %s\n", client->com->fwknoprc_file);
    cp += sdp_append_msg_to_buf(dump_buf+cp, buf_len-cp, "                            TLS key file: %s\n", client->com->key_file);
    cp += sdp_append_msg_to_buf(dump_buf+cp, buf_len-cp, "                           TLS cert file: %s\n", client->com->cert_file);
          sdp_append_msg_to_buf(dump_buf+cp, buf_len-cp, "                PID lock file descriptor: %d\n", client->pid_lock_fd);

    log_msg(LOG_DEBUG, "\n%s\n", dump_buf);
}

int sdp_ctrl_client_get_port(sdp_ctrl_client_t client, int *r_port)
{
    if(client == NULL || !client->initialized)
        return SDP_ERROR_UNINITIALIZED;

    *r_port = client->com->ctrl_port;
    return SDP_SUCCESS;
}

int sdp_ctrl_client_get_addr(sdp_ctrl_client_t client, char **r_addr)
{
    char *addr = NULL;

    if(client == NULL || !client->initialized)
        return SDP_ERROR_UNINITIALIZED;

    addr = strndup(client->com->ctrl_addr, SDP_MAX_SERVER_STR_LEN);
    if(addr == NULL)
        return(SDP_ERROR_MEMORY_ALLOCATION);

    *r_addr = addr;
    return SDP_SUCCESS;
}


int sdp_ctrl_client_check_inbox(sdp_ctrl_client_t client, int *r_action, void **r_data)
{
    int rv = SDP_SUCCESS;
    int bytes, msg_cnt = 0;
    char *msg = NULL;
    void *data = NULL;
    ctrl_action_t action = INVALID_CTRL_ACTION;

    while(msg_cnt < client->message_queue_len)
    {
        free(msg);
        msg = NULL;

        if((rv = sdp_com_get_msg(client->com, &msg, &bytes)) != SDP_SUCCESS)
        {
            log_msg(LOG_ERR, "Error when trying to retrieve message from com.");
            goto cleanup;
        }

        if(!bytes)
        {
            log_msg(LOG_DEBUG, "No more incoming data to retrieve from com");
            break;
        }

        msg_cnt++;

        if((rv = sdp_message_process(msg, &action, &data)) != SDP_SUCCESS)
        {
            log_msg(LOG_ERR, "Message processing failed");
            goto cleanup;
        }

        switch(action)
        {
            case CTRL_ACTION_CREDENTIALS_GOOD:
                log_msg(LOG_NOTICE, "Credentials-good message received");
                client->controller_ready = 1;
                break;

            case CTRL_ACTION_KEEP_ALIVE:
                log_msg(LOG_INFO, "Keep-alive response received");
                sdp_ctrl_client_process_keep_alive(client);
                break;

            case CTRL_ACTION_CREDENTIAL_UPDATE:
                log_msg(LOG_NOTICE, "Credential update received");
                client->controller_ready = 1;

                // Process new credentials
                if((rv = sdp_ctrl_client_process_cred_update(client, data)) != SDP_SUCCESS)
                {
                    log_msg(LOG_ERR, "Failed to process credential update.");
                    goto cleanup;
                }
                break;

            case CTRL_ACTION_SERVICE_REFRESH:
                log_msg(LOG_NOTICE, "Service data refresh received");
                client->last_service_refresh = time(NULL);
                *r_action = action;
                *r_data = data;
                goto cleanup;

            case CTRL_ACTION_SERVICE_UPDATE:
                log_msg(LOG_NOTICE, "Service data update received");
                *r_action = action;
                *r_data = data;
                goto cleanup;

            case CTRL_ACTION_SERVICE_REMOVE:
                log_msg(LOG_NOTICE, "Service data remove received");
                *r_action = action;
                *r_data = data;
                goto cleanup;

            case CTRL_ACTION_ACCESS_REFRESH:
                log_msg(LOG_NOTICE, "Access data refresh received");
                client->last_access_refresh = time(NULL);
                *r_action = action;
                *r_data = data;
                goto cleanup;

            case CTRL_ACTION_ACCESS_UPDATE:
                log_msg(LOG_NOTICE, "Access data update received");
                *r_action = action;
                *r_data = data;
                goto cleanup;

            case CTRL_ACTION_ACCESS_REMOVE:
                log_msg(LOG_NOTICE, "Access data remove received");
                *r_action = action;
                *r_data = data;
                goto cleanup;

            default:
                log_msg(LOG_ERR, "Unknown message processing result");

        }  // END switch(result)

    }  // END while(msg_cnt < q_len)

cleanup:
    free(msg);
    return rv;
}


int sdp_ctrl_client_request_keep_alive(sdp_ctrl_client_t client)
{
    //int bytes = 0;
    int rv = SDP_ERROR_KEEP_ALIVE;
    //ctrl_response_result_t result = BAD_RESULT;
    char *msg = NULL;

    if(client == NULL || !client->initialized)
        return SDP_ERROR_UNINITIALIZED;

    if(client->com->conn_state == SDP_COM_DISCONNECTED)
        return SDP_ERROR_CONN_DOWN;

    if(client->client_state != SDP_CTRL_CLIENT_STATE_READY &&
       client->client_state != SDP_CTRL_CLIENT_STATE_KEEP_ALIVE_UNFULFILLED &&
       client->client_state != SDP_CTRL_CLIENT_STATE_KEEP_ALIVE_REQUESTING)
    {
        log_msg(LOG_DEBUG, "Control Client not in proper state to request keep alive.");
        return SDP_ERROR_STATE;
    }

    // Make the proper message
    if((rv = sdp_message_make(sdp_action_keep_alive, NULL, &msg)) != SDP_SUCCESS)
    {
        log_msg(LOG_ERR, "Failed to make keep alive message.");
        goto cleanup;
    }

    // Send it off
    if((rv = sdp_com_send_msg(client->com, msg)) != SDP_SUCCESS)
    {
        log_msg(LOG_ERR, "Failed to send keep alive message.");
        goto cleanup;
    }

    // Set state accordingly
    sdp_ctrl_client_set_request_vars(client, SDP_CTRL_CLIENT_STATE_KEEP_ALIVE_REQUESTING);


cleanup:
    free(msg);
    return rv;
}

void sdp_ctrl_client_process_keep_alive(sdp_ctrl_client_t client)
{
    client->last_contact = time(NULL);

    if(client->client_state == SDP_CTRL_CLIENT_STATE_KEEP_ALIVE_REQUESTING ||
       client->client_state == SDP_CTRL_CLIENT_STATE_KEEP_ALIVE_UNFULFILLED)
        sdp_ctrl_client_clear_state_vars(client);

}


int sdp_ctrl_client_request_cred_update(sdp_ctrl_client_t client)
{
    int rv = SDP_ERROR_CRED_REQ;
    char *msg = NULL;

    // Is the client context properly initialized
    if(client == NULL || !client->initialized)
        return SDP_ERROR_UNINITIALIZED;

    // Is the client currently connected
    if(client->com->conn_state == SDP_COM_DISCONNECTED)
        return SDP_ERROR_CONN_DOWN;

    // Is the client in the right state
    if(client->client_state != SDP_CTRL_CLIENT_STATE_READY &&
       client->client_state != SDP_CTRL_CLIENT_STATE_CRED_UNFULFILLED &&
       client->client_state != SDP_CTRL_CLIENT_STATE_CRED_REQUESTING)
    {
        log_msg(LOG_DEBUG, "Control Client not in proper state to request credential update.");
        return SDP_ERROR_STATE;
    }

    // Make the proper message
    if((rv = sdp_message_make(sdp_action_cred_update_request, NULL, &msg)) != SDP_SUCCESS)
    {
        log_msg(LOG_ERR, "Failed to make credential request message.");
        goto cleanup;
    }

    // Send it off
    if((rv = sdp_com_send_msg(client->com, msg)) != SDP_SUCCESS)
    {
        log_msg(LOG_ERR, "Failed to send credential request message.");
        goto cleanup;
    }

    // Set state accordingly
    sdp_ctrl_client_set_request_vars(client, SDP_CTRL_CLIENT_STATE_CRED_REQUESTING);


cleanup:
    log_msg(LOG_DEBUG, "Freeing memory before exiting function");

    free(msg);
    return rv;
}

int sdp_ctrl_client_request_service_refresh(sdp_ctrl_client_t client)
{
    int rv = SDP_ERROR_CRED_REQ;
    char *msg = NULL;

    // Is the client context properly initialized
    if(client == NULL || !client->initialized)
        return SDP_ERROR_UNINITIALIZED;

    // Is the client currently connected
    if(client->com->conn_state == SDP_COM_DISCONNECTED)
        return SDP_ERROR_CONN_DOWN;

    // Is the client in the right state
    if(client->client_state != SDP_CTRL_CLIENT_STATE_READY &&
       client->client_state != SDP_CTRL_CLIENT_STATE_SERVICE_REFRESH_REQUESTING &&
       client->client_state != SDP_CTRL_CLIENT_STATE_SERVICE_REFRESH_UNFULFILLED)
    {
        log_msg(LOG_DEBUG, "Control Client not in proper state to request service data refresh.");
        return SDP_ERROR_STATE;
    }

    // Make the proper message
    if((rv = sdp_message_make(sdp_action_service_refresh_request, NULL, &msg)) != SDP_SUCCESS)
    {
        log_msg(LOG_ERR, "Failed to make service refresh request message.");
        goto cleanup;
    }

    // Send it off
    if((rv = sdp_com_send_msg(client->com, msg)) != SDP_SUCCESS)
    {
        log_msg(LOG_ERR, "Failed to send service refresh request message.");
        goto cleanup;
    }

    // Set state accordingly
    sdp_ctrl_client_set_request_vars(client, SDP_CTRL_CLIENT_STATE_SERVICE_REFRESH_REQUESTING);


cleanup:
    log_msg(LOG_DEBUG, "Freeing memory before exiting function");

    free(msg);
    return rv;
}



int sdp_ctrl_client_request_access_refresh(sdp_ctrl_client_t client)
{
    int rv = SDP_ERROR_CRED_REQ;
    char *msg = NULL;

    // Is the client context properly initialized
    if(client == NULL || !client->initialized)
        return SDP_ERROR_UNINITIALIZED;

    // Is the client currently connected
    if(client->com->conn_state == SDP_COM_DISCONNECTED)
        return SDP_ERROR_CONN_DOWN;

    // Is the client in the right state
    if(client->client_state != SDP_CTRL_CLIENT_STATE_READY &&
       client->client_state != SDP_CTRL_CLIENT_STATE_ACCESS_REFRESH_REQUESTING &&
       client->client_state != SDP_CTRL_CLIENT_STATE_ACCESS_REFRESH_UNFULFILLED)
    {
        log_msg(LOG_DEBUG, "Control Client not in proper state to request access data refresh.");
        return SDP_ERROR_STATE;
    }

    // Make the proper message
    if((rv = sdp_message_make(sdp_action_access_refresh_request, NULL, &msg)) != SDP_SUCCESS)
    {
        log_msg(LOG_ERR, "Failed to make access refresh request message.");
        goto cleanup;
    }

    // Send it off
    if((rv = sdp_com_send_msg(client->com, msg)) != SDP_SUCCESS)
    {
        log_msg(LOG_ERR, "Failed to send access refresh request message.");
        goto cleanup;
    }

    // Set state accordingly
    sdp_ctrl_client_set_request_vars(client, SDP_CTRL_CLIENT_STATE_ACCESS_REFRESH_REQUESTING);


cleanup:
    log_msg(LOG_DEBUG, "Freeing memory before exiting function");

    free(msg);
    return rv;
}



int sdp_ctrl_client_process_cred_update(sdp_ctrl_client_t client, void *credentials)
{
    int rv = SDP_ERROR_CRED_REQ;
    char *msg = NULL;

    // critical section, disable thread cancellation
    // apparently many, many C functions are considered cancellation points
    // and could cause the thread to exit at a very inopportune time, so
    // disable cancellation while in this function
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);

    // Store new credentials
    if((rv = sdp_ctrl_client_save_credentials(client, (sdp_creds_t)credentials)) != SDP_SUCCESS)
    {
        log_msg(LOG_ERR, "Failed to store new credentials. May need to restore previous credentials.");
        goto cleanup;
    }

    client->last_contact = time(NULL);
    client->last_cred_update = client->last_contact;

    if(client->client_state == SDP_CTRL_CLIENT_STATE_CRED_REQUESTING ||
       client->client_state == SDP_CTRL_CLIENT_STATE_CRED_UNFULFILLED)
        sdp_ctrl_client_clear_state_vars(client);

    // Make the 'Fulfilled' response message
    if((rv = sdp_message_make(sdp_action_cred_ack, NULL, &msg)) != SDP_SUCCESS)
    {
        log_msg(LOG_ERR, "Failed to make credential request 'ACK' message.");
        goto cleanup;
    }

    if((rv = sdp_com_send_msg(client->com, msg)) != SDP_SUCCESS)
    {
        log_msg(LOG_ERR, "Failed to send credential request 'ACK' message.");
        goto cleanup;
    }

cleanup:
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    pthread_testcancel();

    sdp_message_destroy_creds(credentials);
    free(msg);
    return rv;
}


int  sdp_ctrl_client_send_data_ack(sdp_ctrl_client_t client, int action)
{
    int rv = SDP_SUCCESS;
    char *msg = NULL;
    const char *action_str = NULL;

    if(action == CTRL_ACTION_ACCESS_ACK)
    {
        action_str = sdp_action_access_ack;

        if(client->client_state == SDP_CTRL_CLIENT_STATE_ACCESS_REFRESH_REQUESTING ||
           client->client_state == SDP_CTRL_CLIENT_STATE_ACCESS_REFRESH_UNFULFILLED ||
           client->client_state == SDP_CTRL_CLIENT_STATE_ACCESS_UPDATE_REQUESTING ||
           client->client_state == SDP_CTRL_CLIENT_STATE_ACCESS_UPDATE_UNFULFILLED)
            sdp_ctrl_client_clear_state_vars(client);

    }
    else if(action == CTRL_ACTION_SERVICE_ACK)
    {
        action_str = sdp_action_service_ack;

        if(client->client_state == SDP_CTRL_CLIENT_STATE_SERVICE_REFRESH_REQUESTING ||
           client->client_state == SDP_CTRL_CLIENT_STATE_SERVICE_REFRESH_UNFULFILLED ||
           client->client_state == SDP_CTRL_CLIENT_STATE_SERVICE_UPDATE_REQUESTING ||
           client->client_state == SDP_CTRL_CLIENT_STATE_SERVICE_UPDATE_UNFULFILLED)
            sdp_ctrl_client_clear_state_vars(client);

    }
    else
    {
        log_msg(LOG_ERR, "sdp_ctrl_client_send_data_ack() unrecognized ack type requested, not sending ACK");
        return SDP_ERROR_BAD_ARG;
    }

    // Make the ACK response message
    if((rv = sdp_message_make(action_str, NULL, &msg)) != SDP_SUCCESS)
    {
        log_msg(LOG_ERR, "Failed to make access data 'ACK' message.");
        goto cleanup;
    }

    if((rv = sdp_com_send_msg(client->com, msg)) != SDP_SUCCESS)
    {
        log_msg(LOG_ERR, "Failed to send access data 'ACK' message.");
        goto cleanup;
    }

cleanup:
    log_msg(LOG_DEBUG, "Freeing memory before exiting function");

    free(msg);
    return rv;
}


int  sdp_ctrl_client_send_data_error(sdp_ctrl_client_t client)
{
    int rv = SDP_SUCCESS;
    char *msg = NULL;

    // Make the Error response message
    // THIS NEEDS TO CHANGE DEPENDING ON HOW WE WANT TO MANAGE STATE ON BOTH SIDES
    if((rv = sdp_message_make(sdp_action_bad_message, NULL, &msg)) != SDP_SUCCESS)
    {
        log_msg(LOG_ERR, "Failed to make data 'ERROR' message.");
        goto cleanup;
    }

    if((rv = sdp_com_send_msg(client->com, msg)) != SDP_SUCCESS)
    {
        log_msg(LOG_ERR, "Failed to send data 'ERROR' message.");
        goto cleanup;
    }

cleanup:
    log_msg(LOG_DEBUG, "Freeing memory before exiting function");

    free(msg);
    return rv;
}


int  sdp_ctrl_client_send_message(sdp_ctrl_client_t client, char *action, json_object *data)
{
    int rv = SDP_SUCCESS;
    char *msg = NULL;

    // Make the message
    if((rv = sdp_message_make(action, data, &msg)) != SDP_SUCCESS)
    {
        log_msg(LOG_ERR, "Failed to make ctrl message.");
        goto cleanup;
    }

    if((rv = sdp_com_send_msg(client->com, msg)) != SDP_SUCCESS)
    {
        log_msg(LOG_ERR, "Failed to send ctrl message.");
        goto cleanup;
    }

cleanup:
    log_msg(LOG_DEBUG, "Freeing memory before exiting function");

    free(msg);
    return rv;
}

// PRIVATE FUNCTION DEFINITIONS
// ======================================================================================
// ======================================================================================
// ======================================================================================
// ======================================================================================
// ======================================================================================
// ======================================================================================
// ======================================================================================


int sdp_ctrl_client_clean_exit(sdp_ctrl_client_t client, int status)
{
    sdp_ctrl_client_destroy(client);
    return status;
}

int sdp_ctrl_client_setup_pid(sdp_ctrl_client_t client, pid_t *r_pid)
{
    pid_t    pid = 0, old_pid = 0;
    int rv;

    if(client == NULL || !client->initialized)
        return SDP_ERROR_UNINITIALIZED;

    // If we are a new process (just being started), proceed with normal
    // start-up. Otherwise, we are here as a result of a signal sent to an
    // existing process and we want to restart.
    //
    rv = sdp_ctrl_client_get_running_pid(client, &old_pid);
    if(old_pid != getpid())
    {
        // If foreground mode is not set, then fork off and become a daemon.
        // Otherwise, attempt to get the pid file lock and go on.
        //
        if(client->foreground == 0)
        {
            rv = sdp_ctrl_client_daemonize(client, &pid);
            *r_pid = pid;
        }
        else
        {
            rv = sdp_ctrl_client_write_pid_file(client, &old_pid);
            if(old_pid > 0)
            {
                log_msg(LOG_ERR,
                    "An instance of fwknopd is already running: (PID=%i).", old_pid
                );

                return SDP_ERROR_PROC_EXISTS;
            }
            else if(rv != SDP_SUCCESS)
            {
                log_msg(LOG_ERR, "PID file error. The lock may not be effective.");
            }
        }
        log_msg(LOG_WARNING, "Starting SDP Control Client");
    }
    else
    {
        log_msg(LOG_WARNING, "Re-starting SDP Control Client");
    }

    return rv;
}

// Become a daemon: fork(), start a new session, chdir "/",
// and close unneeded standard filehandles.
//
int sdp_ctrl_client_daemonize(sdp_ctrl_client_t client, pid_t *r_pid)
{
    pid_t pid, old_pid = 0;
    int rv = SDP_SUCCESS;

    if(client == NULL || !client->initialized)
        return SDP_ERROR_UNINITIALIZED;

    // Reset the our umask
    umask(0);

    if ((pid = fork()) < 0)
    {
        perror("Unable to fork: ");
        return SDP_ERROR_FORK;
    }

    *r_pid = pid;

    if (pid != 0) // parent
    {
        return SDP_SUCCESS;
    }

    // Child process from here on out

    // Start a new session
    setsid();

    // Create the PID file (or be blocked by an existing one).
    if((rv = sdp_ctrl_client_write_pid_file(client, &old_pid)) != SDP_SUCCESS)
        return rv;

    if(old_pid > 0)
    {
        log_msg(LOG_ERR,
            "An instance of sdp_ctrl_client is already running: (PID=%i).", old_pid
        );
        return SDP_ERROR_FORK;
    }
    else if(old_pid < 0)
    {
        log_msg(LOG_ERR,
                "PID file error. The lock may not be effective.");
    }

    // Chdir to the root of the filesystem
    if ((chdir("/")) < 0) {
        perror("Could not chdir() to /: ");
        return SDP_ERROR_FILESYSTEM_OPERATION;
    }

    // Change signal handling
    if(sdp_ctrl_client_set_sig_handlers() > 0)
    {
        perror("Could not set up signal handlers");
        return SDP_ERROR_FORK;
    }

    // Close unneeded file handles
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    client->pid = getpid();
    return SDP_SUCCESS;
}


int sdp_ctrl_client_handle_signals(sdp_ctrl_client_t client)
{
    int      last_sig = 0, rv = SDP_ERROR_GOT_EXIT_SIG;

    if(sdp_ctrl_client_got_signal) {
        last_sig   = sdp_ctrl_client_got_signal;
        sdp_ctrl_client_got_signal = 0;

        if(sdp_ctrl_client_got_sighup)
        {
            log_msg(LOG_WARNING, "Got SIGHUP. Restarting.");
            sdp_ctrl_client_got_sighup = 0;

            // if restart func succeeds, loop will carry on
            // any error will cause the loop to break out
            rv = sdp_ctrl_client_restart_myself(client);
        }
        else if(sdp_ctrl_client_got_sigint)
        {
            log_msg(LOG_WARNING, "Got SIGINT. Exiting...");
            sdp_ctrl_client_got_sigint = 0;
        }
        else if(sdp_ctrl_client_got_sigterm)
        {
            log_msg(LOG_WARNING, "Got SIGTERM. Exiting...");
            sdp_ctrl_client_got_sigterm = 0;
        }
        else
        {
            log_msg(LOG_ERR,
                "Got signal %i. No defined action to be taken.", last_sig);
            rv = SDP_SUCCESS;
        }
    }
    else    // ctrl_client_got_signal was not set
    {
        // log_msg(LOG_DEBUG, "No signals. Carry on...");
        rv = SDP_SUCCESS;
    }
    return rv;
}


void sdp_ctrl_client_sig_handler(int sig)
{
    int o_errno;
    sdp_ctrl_client_got_signal = sig;

    switch(sig) {
        case SIGHUP:
            sdp_ctrl_client_got_sighup = 1;
            return;
        case SIGINT:
            sdp_ctrl_client_got_sigint = 1;
            return;
        case SIGTERM:
            sdp_ctrl_client_got_sigterm = 1;
            return;
        case SIGUSR1:
            sdp_ctrl_client_got_sigusr1 = 1;
            return;
        case SIGUSR2:
            sdp_ctrl_client_got_sigusr2 = 1;
            return;
        case SIGCHLD:
            o_errno = errno; // Save errno
            sdp_ctrl_client_got_sigchld = 1;
            waitpid(-1, NULL, WNOHANG);
            errno = o_errno; // restore errno (in case reset by waitpid)
            return;
    }
}

// Setup signal handlers
int sdp_ctrl_client_set_sig_handlers(void)
{
    int                 err = 0;
    struct sigaction    act;

    // Clear the signal flags.
    sdp_ctrl_client_got_signal     = 0;
    sdp_ctrl_client_got_sighup     = 0;
    sdp_ctrl_client_got_sigint     = 0;
    sdp_ctrl_client_got_sigterm    = 0;
    sdp_ctrl_client_got_sigusr1    = 0;
    sdp_ctrl_client_got_sigusr2    = 0;

    // Setup the handlers
    act.sa_handler = sdp_ctrl_client_sig_handler;
    sigemptyset(&act.sa_mask);
    act.sa_flags = SA_RESTART;

    if(sigaction(SIGHUP, &act, NULL) < 0)
    {
        log_msg(LOG_ERR, "* Error setting SIGHUP handler: %s",
            strerror(errno));
        err++;
    }

    if(sigaction(SIGINT, &act, NULL) < 0)
    {
        log_msg(LOG_ERR, "* Error setting SIGINT handler: %s",
            strerror(errno));
        err++;
    }

    if(sigaction(SIGTERM, &act, NULL) < 0)
    {
        log_msg(LOG_ERR, "* Error setting SIGTERM handler: %s",
            strerror(errno));
        err++;
    }

    if(sigaction(SIGUSR1, &act, NULL) < 0)
    {
        log_msg(LOG_ERR, "* Error setting SIGUSR1 handler: %s",
            strerror(errno));
        err++;
    }

    if(sigaction(SIGUSR2, &act, NULL) < 0)
    {
        log_msg(LOG_ERR, "* Error setting SIGUSR2 handler: %s",
            strerror(errno));
        err++;
    }

    if(sigaction(SIGCHLD, &act, NULL) < 0)
    {
        log_msg(LOG_ERR, "* Error setting SIGCHLD handler: %s",
            strerror(errno));
        err++;
    }

    return(err);
}

int sdp_ctrl_client_write_pid_file(sdp_ctrl_client_t client, pid_t *r_old_pid)
{
    pid_t   old_pid, my_pid;
    int     op_fd, lck_res, num_bytes;
    char    buf[PID_BUFLEN] = {0};
    int     rv;

    // Reset errno (just in case)
    errno = 0;

    if(client == NULL || !client->initialized)
        return SDP_ERROR_UNINITIALIZED;

    // Open the PID file
    op_fd = open(client->pid_file, O_WRONLY|O_CREAT, S_IRUSR|S_IWUSR);

    if(op_fd == -1)
    {
        perror("Error trying to open PID file: ");
        return SDP_ERROR_FILESYSTEM_OPERATION;
    }

    if(fcntl(op_fd, F_SETFD, FD_CLOEXEC) == -1)
    {
        close(op_fd);
        perror("Unexpected error from fcntl: ");
        return SDP_ERROR_FILESYSTEM_OPERATION;
    }

    // Attempt to lock the PID file. If we get an EWOULDBLOCK
    // error, another instance already has the lock. So we grab
    // the pid from the existing lock file, complain and bail.
    lck_res = lockf(op_fd, F_TLOCK, 0);
    if(lck_res == -1)
    {
        close(op_fd);

        if(errno != EAGAIN)
        {
            perror("Unexpected error from lockf: ");
            return SDP_ERROR_FILESYSTEM_OPERATION;
        }

        // Look for an existing lock holder. If we get a pid return it.
        rv = sdp_ctrl_client_get_running_pid(client, &old_pid);
        if(rv == SDP_SUCCESS)
        {
            *r_old_pid = old_pid;
            return SDP_SUCCESS;
        }

        // Otherwise, consider it an error.
        perror("Unable read existing PID file: ");
        return SDP_ERROR_FILESYSTEM_OPERATION;
    }

    // Write PID to the file
    my_pid = getpid();
    snprintf(buf, PID_BUFLEN, "%i\n", my_pid);

    log_msg(LOG_DEBUG, "Writing my PID (%i) to the lock file: %s",
        my_pid, client->pid_file);

    num_bytes = write(op_fd, buf, strnlen(buf, PID_BUFLEN));

    if(errno || num_bytes != strnlen(buf, PID_BUFLEN))
        perror("Lock may not be valid. PID file write error: ");

    // Sync/flush regardless...
    fsync(op_fd);

    // Put the lock file discriptor in context struct so any
    // child processes we my spawn can close and release it.
    client->pid_lock_fd = op_fd;

    *r_old_pid = 0;
    return SDP_SUCCESS;
}

int sdp_ctrl_client_get_running_pid(sdp_ctrl_client_t client, pid_t *r_pid)
{
    int     op_fd, bytes_read = 0;
    char    buf[PID_BUFLEN] = {0};
    pid_t   pid            = 0;
    int     rv = SDP_ERROR_FILESYSTEM_OPERATION;
    *r_pid = 0;

    if(client == NULL || !client->initialized)
        return SDP_ERROR_UNINITIALIZED;

    if((rv = sdp_ctrl_client_verify_file_perms(client->pid_file)) != SDP_SUCCESS)
    {
        log_msg(LOG_ERR, "ctrl_client_get_running_pid() error");
        return(rv);
    }

    op_fd = open(client->pid_file, O_RDONLY);

    if(op_fd == -1)
    {
        if(client->foreground != 0)
            perror("Error trying to open PID file: ");
        return(SDP_ERROR_FILESYSTEM_OPERATION);
    }

    bytes_read = read(op_fd, buf, PID_BUFLEN);
    if (bytes_read > 0)
    {
        buf[PID_BUFLEN-1] = '\0';
        // max pid value is configurable on Linux
        pid = (pid_t) sdp_strtol_wrapper(buf, 0, (2 << 30),
                &rv);

        if(rv != SDP_SUCCESS)
            pid = 0;
    }
    else
    {
        rv = SDP_ERROR_FILESYSTEM_OPERATION;
        perror("Error trying to read() PID file: ");
    }

    close(op_fd);

    *r_pid = pid;
    return(rv);
}

int sdp_ctrl_client_verify_file_perms(const char *file)
{
#if HAVE_STAT
    struct stat st;
    uid_t caller_uid = 0;

    // Every file that ctrl_client deals with should be owned
    // by the user and permissions set to 600 (user read/write)
    if((stat(file, &st)) == 0)
    {
        // Make sure it is a regular file
        if(S_ISREG(st.st_mode) != 1 && S_ISLNK(st.st_mode) != 1)
        {
            log_msg(LOG_ERR,
                "file: %s is not a regular file or symbolic link.",
                file
            );
            return SDP_ERROR_FILESYSTEM_OPERATION;
        }

        if((st.st_mode & (S_IRWXU|S_IRWXG|S_IRWXO)) != (S_IRUSR|S_IWUSR))
        {
            log_msg(LOG_ERR,
                "file: %s permissions should only be user read/write (0600, -rw-------)",
                file
            );
        }

        caller_uid = getuid();
        if(st.st_uid != caller_uid)
        {
            log_msg(LOG_ERR, "file: %s (owner: %llu) not owned by current effective user id: %llu",
                file, (unsigned long long)st.st_uid, (unsigned long long)caller_uid);
        }
    }
    else
    {
        // if the path doesn't exist, just return, but otherwise something
        // went wrong
        if(errno != ENOENT)
        {
            log_msg(LOG_ERR, "stat() against file: %s returned: %s",
                file, strerror(errno));
            return SDP_ERROR_FILESYSTEM_OPERATION;
        }
    }

#endif

    return SDP_SUCCESS;
}


int sdp_ctrl_client_loop(sdp_ctrl_client_t client)
{
    int rv = SDP_ERROR;
    int action = INVALID_CTRL_ACTION;
    void *data = NULL;

    if(client == NULL || !client->initialized)
        return SDP_ERROR_UNINITIALIZED;

    while(1)
    {
        // connect if necessary
        if(client->com->conn_state == SDP_COM_DISCONNECTED)
        {
            if((rv = sdp_com_connect(client->com)) != SDP_SUCCESS)
            {
                break;
            }
            client->initial_conn_time = client->last_contact = time(NULL);

            // reset to wait for first message from controller
            client->controller_ready = 0;
        }

        // check for incoming messages
        if((rv = sdp_ctrl_client_check_inbox(client, &action, &data)) != SDP_SUCCESS)
            break;

        // do not begin sending requests until controller is ready
        if( !(client->controller_ready) )
            continue;

        // if new connection or just time, update credentials
        if((rv = sdp_ctrl_client_consider_cred_update(client)) != SDP_SUCCESS)
            break;

        // if configured to disconnect after update, do so
        if(!client->remain_connected && client->last_cred_update > 0)
            break;

        // handle any signals that may have come in
        if((rv = sdp_ctrl_client_handle_signals(client)) != SDP_SUCCESS)
            break;

        // is a keep alive due
        if((rv = sdp_ctrl_client_consider_keep_alive(client)) != SDP_SUCCESS)
            break;

        sleep(1);
    }

    sdp_com_disconnect(client->com);

    log_msg(LOG_WARNING, "SDP Control Client Exiting");
    return rv;
}


int sdp_ctrl_client_consider_keep_alive(sdp_ctrl_client_t client)
{
    time_t ts;
    int rv = SDP_SUCCESS;

    // This should never happen, but just to be safe
    if(client == NULL || !client->initialized)
        return SDP_ERROR_UNINITIALIZED;

    // This is not a failure, but we do halt consideration
    if(client->com->conn_state == SDP_COM_DISCONNECTED)
        return SDP_SUCCESS;

    if(client->client_state == SDP_CTRL_CLIENT_STATE_READY)
    {
        if( (ts = time(NULL)) >= (client->last_contact + client->keep_alive_interval) )
        {
            rv = sdp_ctrl_client_request_keep_alive(client);
        }
        else
        {
            //log_msg(LOG_DEBUG, "Not time for keep alive request.");
            return SDP_SUCCESS;
        }
    }
    else if(client->client_state == SDP_CTRL_CLIENT_STATE_KEEP_ALIVE_REQUESTING ||
            client->client_state == SDP_CTRL_CLIENT_STATE_KEEP_ALIVE_UNFULFILLED)
    {
        if( (ts = time(NULL)) >= (client->last_req_time + client->req_retry_interval) )
        {
            if(client->req_attempts >= client->max_req_attempts)
            {
                log_msg(LOG_ERR, "Too many failed keep alive requests. Attempting reconnect.");
                sdp_com_disconnect(client->com);
                client->req_attempts = 0;
                return SDP_SUCCESS;
            }
            else
            {
                client->client_state = SDP_CTRL_CLIENT_STATE_KEEP_ALIVE_UNFULFILLED;
                client->req_retry_interval *= 2;
                if(client->req_retry_interval > SDP_COM_MAX_RETRY_INTERVAL_SECONDS)
                    client->req_retry_interval = SDP_COM_MAX_RETRY_INTERVAL_SECONDS;
                log_msg(LOG_DEBUG, "It is time to retry an unfulfilled keep alive request.");
                rv = sdp_ctrl_client_request_keep_alive(client);
            }
        }
        else
        {
            //log_msg(LOG_DEBUG, "Not time to retry keep alive request.");
            return SDP_SUCCESS;
        }
    }
    else
    {
        //log_msg(LOG_DEBUG, "Control Client not in proper state to make keep alive request.");
        return SDP_SUCCESS;
    }


    if(rv == SDP_ERROR_SOCKET_WRITE)
    {
        sdp_com_disconnect(client->com);
    }

    if(rv != SDP_ERROR_MEMORY_ALLOCATION)
    {
        return SDP_SUCCESS;
    }

    // Should only get here if there was a memory allocation error
    return rv;
}

int sdp_ctrl_client_consider_cred_update(sdp_ctrl_client_t client)
{
    time_t ts;
    int rv = SDP_SUCCESS;

    // This should never happen, but just to be safe
    if(client == NULL || !client->initialized)
        return SDP_ERROR_UNINITIALIZED;

    // This is not a failure, but we do halt consideration
    if(client->com->conn_state == SDP_COM_DISCONNECTED)
        return SDP_SUCCESS;

    if(client->client_state == SDP_CTRL_CLIENT_STATE_READY)
    {
        if( (ts = time(NULL)) >= (client->last_cred_update + client->cred_update_interval) )
        {
            log_msg(LOG_DEBUG, "It is time for a credential update request.");
            rv = sdp_ctrl_client_request_cred_update(client);
        }
        else
        {
            //log_msg(LOG_DEBUG, "Not time for credential update request.");
            return SDP_SUCCESS;
        }
    }
    else if(client->client_state == SDP_CTRL_CLIENT_STATE_CRED_REQUESTING ||
            client->client_state == SDP_CTRL_CLIENT_STATE_CRED_UNFULFILLED)
    {
        if( (ts = time(NULL)) >= (client->last_req_time + client->req_retry_interval) )
        {
            if(client->req_attempts >= client->max_req_attempts)
            {
                log_msg(LOG_ERR, "Too many failed credential requests. Attempting reconnect.");
                sdp_com_disconnect(client->com);
                client->req_attempts = 0;
                return SDP_SUCCESS;
            }
            else
            {
                client->client_state = SDP_CTRL_CLIENT_STATE_CRED_UNFULFILLED;
                client->req_retry_interval *= 2;
                if(client->req_retry_interval > SDP_COM_MAX_RETRY_INTERVAL_SECONDS)
                    client->req_retry_interval = SDP_COM_MAX_RETRY_INTERVAL_SECONDS;
                log_msg(LOG_DEBUG, "It is time to retry an unfulfilled credential update request.");
                rv = sdp_ctrl_client_request_cred_update(client);
            }
        }
        else
        {
            //log_msg(LOG_DEBUG, "Not time to retry credential update request.");
            return SDP_SUCCESS;
        }
    }
    else
    {
        //log_msg(LOG_DEBUG, "Control Client not in proper state to request credential update.");
        return SDP_SUCCESS;
    }

    if(rv == SDP_ERROR_SOCKET_WRITE)
    {
        sdp_com_disconnect(client->com);
    }

    if(rv != SDP_ERROR_MEMORY_ALLOCATION)
    {
        return SDP_SUCCESS;
    }

    // Should only get here if there was a memory allocation error
    return rv;
}


int sdp_ctrl_client_consider_service_refresh(sdp_ctrl_client_t client)
{
    time_t ts;
    int rv = SDP_SUCCESS;

    // This should never happen, but just to be safe
    if(client == NULL || !client->initialized)
        return SDP_ERROR_UNINITIALIZED;

    // This is not a failure, but we do halt consideration
    if(client->com->conn_state == SDP_COM_DISCONNECTED)
        return SDP_SUCCESS;

    if(client->client_state == SDP_CTRL_CLIENT_STATE_READY)
    {
        if( (ts = time(NULL)) >= (client->last_service_refresh + client->service_refresh_interval) )
        {
            log_msg(LOG_DEBUG, "It is time for service data refresh request.");
            rv = sdp_ctrl_client_request_service_refresh(client);
        }
        else
        {
            //log_msg(LOG_DEBUG, "Not time for access data refresh request.");
            return SDP_SUCCESS;
        }
    }
    else if(client->client_state == SDP_CTRL_CLIENT_STATE_SERVICE_REFRESH_REQUESTING ||
            client->client_state == SDP_CTRL_CLIENT_STATE_SERVICE_REFRESH_UNFULFILLED)
    {
        if( (ts = time(NULL)) >= (client->last_req_time + client->req_retry_interval) )
        {
            if(client->req_attempts >= client->max_req_attempts)
            {
                log_msg(LOG_ERR, "Too many failed service refresh requests. Attempting reconnect.");
                sdp_com_disconnect(client->com);
                client->req_attempts = 0;
                return SDP_SUCCESS;
            }
            else
            {
                client->client_state = SDP_CTRL_CLIENT_STATE_SERVICE_REFRESH_UNFULFILLED;
                client->req_retry_interval *= 2;
                if(client->req_retry_interval > SDP_COM_MAX_RETRY_INTERVAL_SECONDS)
                    client->req_retry_interval = SDP_COM_MAX_RETRY_INTERVAL_SECONDS;
                log_msg(LOG_DEBUG, "It is time to retry an unfulfilled service data refresh request.");
                rv = sdp_ctrl_client_request_service_refresh(client);
            }
        }
        else
        {
            //log_msg(LOG_DEBUG, "Not time to retry access data refresh request.");
            return SDP_SUCCESS;
        }
    }
    else
    {
        //log_msg(LOG_DEBUG, "Control Client not in proper state to request service data refresh.");
        return SDP_SUCCESS;
    }

    if(rv == SDP_ERROR_SOCKET_WRITE)
    {
        sdp_com_disconnect(client->com);
    }

    if(rv != SDP_ERROR_MEMORY_ALLOCATION)
    {
        return SDP_SUCCESS;
    }

    // Should only get here if there was a memory allocation error
    return rv;
}


int sdp_ctrl_client_consider_access_refresh(sdp_ctrl_client_t client)
{
    time_t ts;
    int rv = SDP_SUCCESS;

    // This should never happen, but just to be safe
    if(client == NULL || !client->initialized)
        return SDP_ERROR_UNINITIALIZED;

    // This is not a failure, but we do halt consideration
    if(client->com->conn_state == SDP_COM_DISCONNECTED)
        return SDP_SUCCESS;

    if(client->client_state == SDP_CTRL_CLIENT_STATE_READY)
    {
        if( (ts = time(NULL)) >= (client->last_access_refresh + client->access_refresh_interval) )
        {
            log_msg(LOG_DEBUG, "It is time for an access data refresh request.");
            rv = sdp_ctrl_client_request_access_refresh(client);
        }
        else
        {
            //log_msg(LOG_DEBUG, "Not time for access data refresh request.");
            return SDP_SUCCESS;
        }
    }
    else if(client->client_state == SDP_CTRL_CLIENT_STATE_ACCESS_REFRESH_REQUESTING ||
            client->client_state == SDP_CTRL_CLIENT_STATE_ACCESS_REFRESH_UNFULFILLED)
    {
        if( (ts = time(NULL)) >= (client->last_req_time + client->req_retry_interval) )
        {
            if(client->req_attempts >= client->max_req_attempts)
            {
                log_msg(LOG_ERR, "Too many failed access refresh requests. Attempting reconnect.");
                sdp_com_disconnect(client->com);
                client->req_attempts = 0;
                return SDP_SUCCESS;
            }
            else
            {
                client->client_state = SDP_CTRL_CLIENT_STATE_ACCESS_REFRESH_UNFULFILLED;
                client->req_retry_interval *= 2;
                if(client->req_retry_interval > SDP_COM_MAX_RETRY_INTERVAL_SECONDS)
                    client->req_retry_interval = SDP_COM_MAX_RETRY_INTERVAL_SECONDS;
                log_msg(LOG_DEBUG, "It is time to retry an unfulfilled access data refresh request.");
                rv = sdp_ctrl_client_request_access_refresh(client);
            }
        }
        else
        {
            //log_msg(LOG_DEBUG, "Not time to retry access data refresh request.");
            return SDP_SUCCESS;
        }
    }
    else
    {
        //log_msg(LOG_DEBUG, "Control Client not in proper state to request access data refresh.");
        return SDP_SUCCESS;
    }

    if(rv == SDP_ERROR_SOCKET_WRITE)
    {
        sdp_com_disconnect(client->com);
    }

    if(rv != SDP_ERROR_MEMORY_ALLOCATION)
    {
        return SDP_SUCCESS;
    }

    // Should only get here if there was a memory allocation error
    return rv;
}




void sdp_ctrl_client_clear_state_vars(sdp_ctrl_client_t client)
{
    client->last_req_time = 0;
    client->req_retry_interval = client->initial_req_retry_interval;
    client->req_attempts = 0;
    client->client_state = SDP_CTRL_CLIENT_STATE_READY;
}


void sdp_ctrl_client_set_request_vars(sdp_ctrl_client_t client, sdp_ctrl_client_state_t new_state)
{
    client->client_state = new_state;
    client->last_req_time = time(NULL);
    client->req_attempts++;
}


int  sdp_ctrl_client_save_credentials(sdp_ctrl_client_t client, sdp_creds_t creds)
{
    int rv = SDP_ERROR_FILESYSTEM_OPERATION;

    // store certificate file
    log_msg(LOG_DEBUG, "Storing certificate file");
    if((rv = sdp_save_to_file(client->com->cert_file, creds->tls_cert)) != SDP_SUCCESS)
    {
        log_msg(LOG_ERR, "Failed to store client certificate to: %s", client->com->cert_file);
        return rv;
    }

    // store key file
    log_msg(LOG_DEBUG, "Storing key file");
    if((rv = sdp_save_to_file(client->com->key_file, creds->tls_key)) != SDP_SUCCESS)
    {
        log_msg(LOG_ERR, "Failed to store client key to: %s", client->com->key_file);
        sdp_restore_file(client->com->cert_file);
        return rv;
    }

    // can only replace SPA keys if old ones were defined to search for
    // and if new ones were provided
    if( client->com->fwknoprc_file != NULL &&
        client->com->spa_encryption_key != NULL &&
        client->com->spa_hmac_key != NULL &&
        creds->encryption_key != NULL &&
        creds->hmac_key != NULL )
    {
        // store SPA keys in ctrl client config file
        log_msg(LOG_DEBUG, "Storing SPA keys in sdp ctrl client config file");
        if((rv = sdp_replace_spa_keys(
                client->config_file,
                client->com->spa_encryption_key, creds->encryption_key, 1,
                client->com->spa_hmac_key, creds->hmac_key, 1
                )) != SDP_SUCCESS)
        {
            log_msg(LOG_ERR, "Failed to store SPA keys in ctrl client config file");
            sdp_restore_file(client->com->cert_file);
            sdp_restore_file(client->com->key_file);
            return rv;
        }

        // store SPA keys in fwknop config file
        log_msg(LOG_DEBUG, "Storing SPA keys in fwknop config file");
        if((rv = sdp_replace_spa_keys(
                client->com->fwknoprc_file,
                client->com->spa_encryption_key, creds->encryption_key, 1,
                client->com->spa_hmac_key, creds->hmac_key, 1
                )) != SDP_SUCCESS)
        {
            log_msg(LOG_ERR, "Failed to store SPA keys in fwknop config file");
            sdp_restore_file(client->com->cert_file);
            sdp_restore_file(client->com->key_file);
            sdp_restore_file(client->config_file);
            return rv;
        }

        // Now that the keys are stored, save them in com
        free(client->com->spa_encryption_key);
        if((client->com->spa_encryption_key = strndup(creds->encryption_key, SDP_MAX_B64_KEY_LEN)) == NULL)
        {
            log_msg(LOG_ERR, "Memory error while swapping keys in com module. Still saved in relevant files.");
            return SDP_ERROR_MEMORY_ALLOCATION;
        }

        free(client->com->spa_hmac_key);
        if((client->com->spa_hmac_key = strndup(creds->hmac_key, SDP_MAX_B64_KEY_LEN)) == NULL)
        {
            log_msg(LOG_ERR, "Memory error while swapping keys in com module. Still saved in relevant files.");
            return SDP_ERROR_MEMORY_ALLOCATION;
        }

    }

    log_msg(LOG_WARNING, "All new credentials stored successfully");

    return rv;
}

/**
 * @brief Free all allocated memory within the client object
 *
 * Does not delete the client object itself
 *
 * @param client - object to clean out
 *
 * @return void
 */
void sdp_ctrl_client_destroy_internals(sdp_ctrl_client_t client)
{
    if(client == NULL)
        return;

    if(client->config_file != NULL)
    {
        free(client->config_file);
        client->config_file = NULL;
    }

    if(client->pid_file != NULL)
    {
        free(client->pid_file);
        client->pid_file = NULL;
    }

    if(client->com != NULL)
    {
        sdp_com_destroy(client->com);
        client->com = NULL;
    }
}


/**
 * @brief Restart the sdp ctrl client internals
 *
 * This function restarts the sdp ctrl client. It disconnects if necessary, destroys
 * all internal data structures and zeros all memory. It then rereads the config file
 * to initialize all internal data. Once initialized, the run loop continues.
 *
 * @param client - sdp_ctrl_client_t object.
 *
 * @return SDP_SUCCESS or an error code.
 */
int sdp_ctrl_client_restart_myself(sdp_ctrl_client_t client)
{
    int rv = SDP_SUCCESS;
    char *config_file = NULL;
    char *fwknoprc_file = NULL;
    int foreground = client->foreground;

    // disconnect
    sdp_com_disconnect(client->com);

    // grab key items required from old object
    if((config_file = strndup(client->config_file, PATH_MAX)) == NULL)
    {
        log_msg(LOG_ERR, "Error copying config file path");
        rv = SDP_ERROR_MEMORY_ALLOCATION;
        goto cleanup;
    }

    if(client->com->fwknoprc_file != NULL)
    {
        if((fwknoprc_file = strndup(client->com->fwknoprc_file, PATH_MAX)) == NULL)
        {
            log_msg(LOG_ERR, "Error copying fwknoprc file path");
            rv = SDP_ERROR_MEMORY_ALLOCATION;
            goto cleanup;
        }
    }


    // destroy old internals including com object
    sdp_ctrl_client_destroy_internals(client);
    memset(client, 0x00, sizeof *client);

    // create new com object
    if((rv = sdp_com_new(&(client->com))) != SDP_SUCCESS)
        goto cleanup;

    if((rv = sdp_ctrl_client_config_init(client, config_file, fwknoprc_file, foreground)) != SDP_SUCCESS)
        goto cleanup;

    sdp_ctrl_client_describe(client);

cleanup:
    free(config_file);
    free(fwknoprc_file);

    // if no errors, client loop will now carry on
    return rv;
}



// EOF
