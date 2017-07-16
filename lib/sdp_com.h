/*
 * sdp_com.h
 *
 *  Created on: Apr 12, 2016
 *      Author: Daniel Bailey
 */

#ifndef SDP_COM_H_
#define SDP_COM_H_

#include <stdint.h>
#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/err.h>



typedef struct sdp_header {
    uint32_t length;
} sdp_header;

#define SDP_COM_HEADER_LEN sizeof(sdp_header)

enum {
	SDP_COM_SSL_CONNECT_SUCCESS = 1,
	SDP_COM_MAX_PORT_STRING_BUFFER_LEN = 6,
	SDP_COM_MAX_IPV4_LEN = 16,
	SDP_COM_MAX_RETRY_INTERVAL_SECONDS = 7200,
	SDP_COM_MAX_ADDR_LEN = 1024,
	SDP_COM_MAX_PATH_LEN = 1024,
	SDP_COM_MAX_LINE_LEN = 1024,
	SDP_COM_MAX_MSG_BLOCK_LEN = 16384,
	SDP_COM_MAX_Q_LEN = 100,
	SDP_COM_MAX_FWKNOP_ARGS = 6,
	SDP_COM_MAX_FWKNOP_CMD_LEN = SDP_COM_MAX_PATH_LEN + SDP_COM_MAX_LINE_LEN + 100
};


typedef enum {
	SDP_COM_DISCONNECTED = 0,
	SDP_COM_CONNECTED,
} sdp_com_state_t;


struct sdp_com{
	int initialized;
	sdp_com_state_t conn_state;
	unsigned int ctrl_port;
	char *ctrl_addr;
	int use_spa;
	char *ctrl_stanza;
	int (*func_ptr_send_spa)(struct sdp_com *com);
	char *spa_encryption_key;
	char *spa_hmac_key;
	uint32_t sdp_id;
	char *fwknop_path;
	char *fwknoprc_file;

	char *key_file;
	char *cert_file;
	SSL_CTX *ssl_ctx;
	SSL *ssl;
	int socket_descriptor;
	struct timespec post_spa_delay;
	struct timeval read_timeout;
	struct timeval write_timeout;
	unsigned int max_conn_attempts;
	unsigned int conn_attempts;
	unsigned int initial_conn_attempt_interval;
	char recv_buffer[SDP_COM_MAX_MSG_BLOCK_LEN];
	//char **message_queue;
	//unsigned int message_queue_len;
};

typedef struct sdp_com *sdp_com_t;

int sdp_com_init(sdp_com_t com);
int sdp_com_new(sdp_com_t *r_com);
void sdp_com_destroy(sdp_com_t com);
int  sdp_com_state_get(sdp_com_t com, int *state);
int  sdp_com_connect(sdp_com_t com);
int  sdp_com_disconnect(sdp_com_t com);
int  sdp_com_show_certs(sdp_com_t com);
int  sdp_com_send_msg(sdp_com_t com, const char *msg);
int  sdp_com_get_msg(sdp_com_t com, char **r_msg, int *r_bytes);

#endif /* SDP_COM_H_ */
