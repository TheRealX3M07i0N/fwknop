/*
 * sdp_ctrl_client.h
 *
 *  Created on: Mar 28, 2016
 *      Author: hydrolucid3
 */

#ifndef SDP_CTRL_CLIENT_H_
#define SDP_CTRL_CLIENT_H_

#include <signal.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include "sdp_com.h"
#include "sdp_errors.h"
#include "sdp_message.h"


extern sig_atomic_t sdp_ctrl_client_got_signal;

extern sig_atomic_t sdp_ctrl_client_got_sighup;
extern sig_atomic_t sdp_ctrl_client_got_sigint;
extern sig_atomic_t sdp_ctrl_client_got_sigterm;
extern sig_atomic_t sdp_ctrl_client_got_sigusr1;
extern sig_atomic_t sdp_ctrl_client_got_sigusr2;
extern sig_atomic_t sdp_ctrl_client_got_sigchld;


enum {
    SDP_MAX_SERVER_STR_LEN  = 50,
    SDP_MAX_LINE_LEN        = 1024,
    SDP_MAX_KEY_LEN         = 128,
    SDP_MAX_B64_KEY_LEN     = 180,
    SDP_MAX_MSG_Q_LEN       = 100,
    SDP_MAX_POST_SPA_DELAY  = 10,
    SDP_MAX_CLIENT_ID_STR_LEN = 11,
	SDP_MAX_SERVICE_ID_STR_LEN = 11
};


enum {
    SDP_SUCCESS = 0,
    SDP_ERROR_MEMORY_ALLOCATION = 0x8000,
    SDP_ERROR_FILESYSTEM_OPERATION,
    SDP_ERROR_ABSOLUTE_PATH,
    SDP_ERROR_PROC_EXISTS,
    SDP_ERROR_UNINITIALIZED,
    SDP_ERROR_CONFIG,
    SDP_ERROR_FORK,
    SDP_ERROR_SYSLOG,
    SDP_ERROR_BAD_ARG,
    SDP_ERROR_SPA,
    SDP_ERROR_CONN_FAIL,
    SDP_ERROR_CONN_DOWN,
    SDP_ERROR_GET_HOST,
    SDP_ERROR_GETADDRINFO,
    SDP_ERROR_SSL,
    SDP_ERROR_SSL_HANDSHAKE,
    SDP_ERROR_SSL_NO_CERT_RECEIVED,
    SDP_ERROR_KEY,
    SDP_ERROR_CERT,
    SDP_ERROR_FIELD_NOT_PRESENT,
    SDP_ERROR_INVALID_MSG,
    SDP_ERROR_INVALID_MSG_SHORT,
    SDP_ERROR_INVALID_MSG_LONG,
    SDP_ERROR_KEEP_ALIVE,
    SDP_ERROR_CRED_REQ,
    SDP_ERROR_ACC_REQ,
    SDP_ERROR_MANY_FAILED_REQS,
    SDP_ERROR_STATE,
    SDP_ERROR_SOCKET,
    SDP_ERROR_SOCKET_OPTION,
    SDP_ERROR_SOCKET_READ,
    SDP_ERROR_SOCKET_WRITE,
    SDP_ERROR_STRTOL,
    SDP_ERROR_STRTOLD,
    SDP_ERROR_KEY_SAVE,
    SDP_ERROR_EXIT_FAILURE,
    SDP_ERROR_GOT_EXIT_SIG,
    SDP_ERROR
};

#define IS_SDP_ERROR(x) (x & 0x8000)


#define YES_OR_NO(I) (I == 0 ? "NO" : "YES")

typedef enum {
    SDP_CTRL_CLIENT_STATE_READY,
    SDP_CTRL_CLIENT_STATE_KEEP_ALIVE_REQUESTING,
    SDP_CTRL_CLIENT_STATE_KEEP_ALIVE_UNFULFILLED,
    SDP_CTRL_CLIENT_STATE_CRED_REQUESTING,
    SDP_CTRL_CLIENT_STATE_CRED_FULFILLED,
    SDP_CTRL_CLIENT_STATE_CRED_UNFULFILLED,
    SDP_CTRL_CLIENT_STATE_ACCESS_REFRESH_REQUESTING,
    SDP_CTRL_CLIENT_STATE_ACCESS_REFRESH_FULFILLED,
    SDP_CTRL_CLIENT_STATE_ACCESS_REFRESH_UNFULFILLED,
    SDP_CTRL_CLIENT_STATE_ACCESS_UPDATE_REQUESTING,
    SDP_CTRL_CLIENT_STATE_ACCESS_UPDATE_FULFILLED,
    SDP_CTRL_CLIENT_STATE_ACCESS_UPDATE_UNFULFILLED,
    SDP_CTRL_CLIENT_STATE_SERVICE_REFRESH_REQUESTING,
    SDP_CTRL_CLIENT_STATE_SERVICE_REFRESH_FULFILLED,
    SDP_CTRL_CLIENT_STATE_SERVICE_REFRESH_UNFULFILLED,
    SDP_CTRL_CLIENT_STATE_SERVICE_UPDATE_REQUESTING,
    SDP_CTRL_CLIENT_STATE_SERVICE_UPDATE_FULFILLED,
    SDP_CTRL_CLIENT_STATE_SERVICE_UPDATE_UNFULFILLED,
    SDP_CTRL_CLIENT_STATE_NEED_RECONNECT,
    SDP_CTRL_CLIENT_STATE_TIME_TO_QUIT,
} sdp_ctrl_client_state_t;


struct sdp_ctrl_client{
    char *config_file;
    int   initialized;
    int   controller_ready;
    sdp_com_t com;
    int   remain_connected;
    int   foreground;
    int   use_syslog;
    int   verbosity;

    sdp_ctrl_client_state_t client_state;

    int keep_alive_interval;

    time_t initial_conn_time;
    time_t last_contact;
    time_t last_cred_update;
    time_t last_service_refresh;
    time_t last_access_refresh;
    time_t last_req_time;
    time_t last_failed_req_time;
    int cred_update_interval;
    int service_refresh_interval;
    int access_refresh_interval;
    int max_req_attempts;
    int req_attempts;
    int initial_req_retry_interval;
    int req_retry_interval;
    int pid;
    char *pid_file;
    int pid_lock_fd;
    unsigned int message_queue_len;
};

typedef struct sdp_ctrl_client *sdp_ctrl_client_t;

int  sdp_ctrl_client_new(const char *config_file, const char *fwknoprc_file, const int foreground, sdp_ctrl_client_t *r_client);
void sdp_ctrl_client_destroy(sdp_ctrl_client_t client);
int  sdp_ctrl_client_listen(sdp_ctrl_client_t client, int max_time, int *r_action, void **r_data);
int  sdp_ctrl_client_start(sdp_ctrl_client_t client, pid_t *r_child_pid);
int  sdp_ctrl_client_stop(sdp_ctrl_client_t client);
int  sdp_ctrl_client_restart(sdp_ctrl_client_t client);
int  sdp_ctrl_client_connect(sdp_ctrl_client_t client);
int  sdp_ctrl_client_disconnect(sdp_ctrl_client_t client);
int  sdp_ctrl_client_connection_status(sdp_ctrl_client_t client);
int  sdp_ctrl_client_controller_status(sdp_ctrl_client_t client);
int  sdp_ctrl_client_status(sdp_ctrl_client_t client);
void sdp_ctrl_client_describe(sdp_ctrl_client_t client);
int  sdp_ctrl_client_get_port(sdp_ctrl_client_t client, int *r_port);
int  sdp_ctrl_client_get_addr(sdp_ctrl_client_t client, char **r_addr);
int  sdp_ctrl_client_check_inbox(sdp_ctrl_client_t client, int *r_action, void **r_data);
int  sdp_ctrl_client_request_keep_alive(sdp_ctrl_client_t client);
void sdp_ctrl_client_process_keep_alive(sdp_ctrl_client_t client);
int  sdp_ctrl_client_request_cred_update(sdp_ctrl_client_t client);
int  sdp_ctrl_client_request_service_refresh(sdp_ctrl_client_t client);
int  sdp_ctrl_client_request_access_refresh(sdp_ctrl_client_t client);
int  sdp_ctrl_client_process_cred_update(sdp_ctrl_client_t client, void *credentials);
int  sdp_ctrl_client_consider_keep_alive(sdp_ctrl_client_t client);
int  sdp_ctrl_client_consider_cred_update(sdp_ctrl_client_t client);
int  sdp_ctrl_client_consider_service_refresh(sdp_ctrl_client_t client);
int  sdp_ctrl_client_consider_access_refresh(sdp_ctrl_client_t client);
int  sdp_ctrl_client_send_data_ack(sdp_ctrl_client_t client, int action);
int  sdp_ctrl_client_send_data_error(sdp_ctrl_client_t client);
int  sdp_ctrl_client_send_message(sdp_ctrl_client_t client, char *action, json_object *data);

#endif /* SDP_CTRL_CLIENT_H_ */
