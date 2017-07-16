/*
 * sdp_message.h
 *
 *  Created on: Apr 5, 2016
 *      Author: Daniel Bailey
 */

#ifndef SDP_MESSAGE_H_
#define SDP_MESSAGE_H_

#include <json-c/json.h>

typedef enum {
    INVALID_CTRL_ACTION,
    CTRL_ACTION_CREDENTIALS_GOOD,
    CTRL_ACTION_KEEP_ALIVE,
    CTRL_ACTION_CREDENTIAL_UPDATE,
    CTRL_ACTION_ACCESS_REFRESH,
    CTRL_ACTION_ACCESS_UPDATE,
    CTRL_ACTION_ACCESS_REMOVE,
	CTRL_ACTION_ACCESS_ACK,
	CTRL_ACTION_SERVICE_REFRESH,
	CTRL_ACTION_SERVICE_UPDATE,
	CTRL_ACTION_SERVICE_REMOVE,
	CTRL_ACTION_SERVICE_ACK,
    CTRL_ACTION_BAD_MESSAGE
} ctrl_action_t;

typedef enum {
    CTRL_STAGE_NONE,
    CTRL_STAGE_FULFILLING,
    CTRL_STAGE_ERROR
} ctrl_stage_t;

enum {
    SDP_MSG_MIN_LEN = 22,
    SDP_MSG_FIELD_MAX_LEN = 65536,
    SDP_MSG_MAX_LEN = 65536
};


struct sdp_creds{
    char *encryption_key;
    char *hmac_key;
    char *tls_key;
    char *tls_cert;
};

typedef struct sdp_creds *sdp_creds_t;

// JSON message strings
extern const char *sdp_key_action;
extern const char *sdp_key_stage;
extern const char *sdp_key_data;

extern const char *sdp_action_credentials_good;
extern const char *sdp_action_keep_alive;
extern const char *sdp_action_cred_update;
extern const char *sdp_action_cred_update_request;
extern const char *sdp_action_cred_ack;
extern const char *sdp_action_access_refresh;
extern const char *sdp_action_access_refresh_request;
extern const char *sdp_action_access_update;
extern const char *sdp_action_access_remove;
extern const char *sdp_action_access_ack;
extern const char *sdp_action_service_refresh;
extern const char *sdp_action_service_refresh_request;
extern const char *sdp_action_service_update;
extern const char *sdp_action_service_remove;
extern const char *sdp_action_service_ack;
extern const char *sdp_action_bad_message;
extern const char *sdp_action_connection_update;

extern const char *sdp_stage_error;
extern const char *sdp_stage_fulfilling;
extern const char *sdp_stage_requesting;
extern const char *sdp_stage_fulfilled;
extern const char *sdp_stage_unfulfilled;

extern const char *sdp_msg_keep_alive;
extern const char *sdp_msg_cred_req;
extern const char *sdp_msg_cred_fulfilled;
extern const char *sdp_msg_cred_unfulfilled;

int  sdp_get_json_string_field(const char *key, json_object *jdata, char **r_field);
int  sdp_get_json_int_field(const char *key, json_object *jdata, int *r_field);
int  sdp_message_make(const char *subject, const json_object *data, char **r_out_msg);
int  sdp_message_process(const char *msg, ctrl_action_t *r_action, void **r_data); //json_object **r_jdata);
int  sdp_message_parse_cred_fields(json_object *jdata, void **r_creds);
void sdp_message_destroy_creds(sdp_creds_t creds);


#endif /* SDP_MESSAGE_H_ */
