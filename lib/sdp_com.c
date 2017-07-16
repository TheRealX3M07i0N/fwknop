/*
 * sdp_com.c
 *
 *  Created on: Apr 12, 2016
 *      Author: Daniel Bailey
 */
#include "sdp_ctrl_client.h"
#include "sdp_com.h"
#include "sdp_errors.h"
#include "sdp_message.h"
#include "sdp_log_msg.h"
#include <netdb.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <ctype.h>


static void sdp_com_free_argv(char **argv_new, int *argc_new)
{
    int i;

    if(argv_new == NULL || *argv_new == NULL)
        return;

    for (i=0; i < *argc_new; i++)
    {
        if(argv_new[i] == NULL)
            break;
        else
            free(argv_new[i]);
    }
    return;
}

static int sdp_com_add_argv(char **argv_new, int *argc_new, const char *new_arg)
{
    int buf_size = 0;

    buf_size = strlen(new_arg) + 1;
    argv_new[*argc_new] = calloc(1, buf_size);

    log_msg(LOG_DEBUG, "adding arg %d, %s", *argc_new, new_arg);

    if(argv_new[*argc_new] == NULL)
    {
        log_msg(LOG_ERR, "Memory allocation error.");
        return SDP_ERROR_MEMORY_ALLOCATION;
    }
    strncpy(argv_new[*argc_new], new_arg, buf_size);

    *argc_new += 1;

    if(*argc_new > SDP_COM_MAX_FWKNOP_ARGS)
    {
        log_msg(LOG_ERR, "Max command line args exceeded.");
        return SDP_ERROR;
    }

    argv_new[*argc_new] = NULL;

    return SDP_SUCCESS;
}


static int sdp_com_strtoargv(char *args_str, char **argv_new, int *argc_new)
{
    int       current_arg_ctr = 0, i;
    char      arg_tmp[SDP_COM_MAX_LINE_LEN] = {0};

    for (i=0; i < (int)strlen(args_str); i++)
    {
        if (!isspace(args_str[i]))
        {
            arg_tmp[current_arg_ctr] = args_str[i];
            current_arg_ctr++;
        }
        else
        {
            if(current_arg_ctr > 0)
            {
                arg_tmp[current_arg_ctr] = '\0';
                if (sdp_com_add_argv(argv_new, argc_new, arg_tmp) != SDP_SUCCESS)
                {
                    log_msg(LOG_DEBUG, "Error when adding arg: %s", arg_tmp);
                    sdp_com_free_argv(argv_new, argc_new);
                    return SDP_ERROR;
                }
                current_arg_ctr = 0;
            }
        }
    }

    /* pick up the last argument in the string
    */
    if(current_arg_ctr > 0)
    {
        arg_tmp[current_arg_ctr] = '\0';
        if (sdp_com_add_argv(argv_new, argc_new, arg_tmp) != SDP_SUCCESS)
        {
            log_msg(LOG_DEBUG, "Error when adding last arg: %s", arg_tmp);
            sdp_com_free_argv(argv_new, argc_new);
            return SDP_ERROR;
        }
    }
    return SDP_SUCCESS;
}

static int sdp_com_default_send_spa(sdp_com_t com)
{
    char    fwknop_cmd[SDP_COM_MAX_FWKNOP_CMD_LEN] = {0};
    char   *fwknop_argv[SDP_COM_MAX_FWKNOP_ARGS];
    int     fwknop_argc=0;
    pid_t   pid=0;
    int     status;

    log_msg(LOG_DEBUG, "Entered sdp_com_default_send_spa function");

    if(com == NULL || !com->initialized)
        return SDP_ERROR_UNINITIALIZED;

    if(com->fwknoprc_file == NULL)
    {
        log_msg(LOG_ERR, "Attempting to send SPA, but fwknoprc file not set.");
        return SDP_ERROR_SPA;
    }

    memset(fwknop_argv, 0x0, sizeof(fwknop_argv));

    // set up fwknop options
    snprintf(fwknop_cmd, SDP_COM_MAX_FWKNOP_CMD_LEN, "%s --disable-ctrl-client --rc-file %s -n %s",
             com->fwknop_path, com->fwknoprc_file, com->ctrl_stanza);

    log_msg(LOG_DEBUG, "fwknop command string: %s", fwknop_cmd);

    if(sdp_com_strtoargv(fwknop_cmd, fwknop_argv, &fwknop_argc) != SDP_SUCCESS)
    {
        log_msg(LOG_ERR, "Error converting fwknop cmd str to argv");
        return SDP_ERROR_SPA;
    }

    pid = fork();
    if (pid == 0)
    {
        if(execvp(fwknop_argv[0], fwknop_argv) < 0)
        {
            log_msg(LOG_ERR, "Could not execute fwknop");
            sdp_com_free_argv(fwknop_argv, &fwknop_argc);
            exit(SDP_ERROR_SPA);
        }
    }
    else if(pid == -1)
    {
        log_msg(LOG_ERR, "Could not fork() for fwknop");
        sdp_com_free_argv(fwknop_argv, &fwknop_argc);
        return SDP_ERROR_SPA;
    }

    /* Only the parent process makes it here
    */
    waitpid(pid, &status, 0);

    sdp_com_free_argv(fwknop_argv, &fwknop_argc);

    // if child did not exit normally and with a zero return value
    if( !(WIFEXITED(status) && WEXITSTATUS(status) == 0) )
    {
        log_msg(LOG_ERR, "fwknop failed with exit code %d", WEXITSTATUS(status));
        return SDP_ERROR_SPA;
    }

    // delay X nanoseconds so gateway has chance to open the door
    nanosleep(&(com->post_spa_delay), NULL);

    return SDP_SUCCESS;
}

static int sdp_com_get_ssl_error(SSL *ssl, int rv, char *r_ssl_error)
{
    char *ssl_error = NULL;
    int value = SSL_get_error(ssl, rv);

    switch(value){
        case SSL_ERROR_ZERO_RETURN:
            ssl_error = "SSL_ERROR_ZERO_RETURN";
            break;
        case SSL_ERROR_WANT_READ:
            ssl_error = "SSL_ERROR_WANT_READ";
            break;
        case SSL_ERROR_WANT_WRITE:
            ssl_error = "SSL_ERROR_WANT_WRITE";
            break;
        case SSL_ERROR_WANT_CONNECT:
            ssl_error = "SSL_ERROR_WANT_CONNECT";
            break;
        case SSL_ERROR_WANT_ACCEPT:
            ssl_error = "SSL_ERROR_WANT_ACCEPT";
            break;
        case SSL_ERROR_WANT_X509_LOOKUP:
            ssl_error = "SSL_ERROR_WANT_X509_LOOKUP";
            break;
        case SSL_ERROR_SYSCALL:
            ssl_error = "SSL_ERROR_SYSCALL";
            break;
        case SSL_ERROR_SSL:
            ssl_error = "SSL_ERROR_SSL";
            break;
        default:
            ssl_error = "Unknown SSL error value";
    }

    strncpy(r_ssl_error, ssl_error, SDP_MAX_LINE_LEN);
    return value;
}


static int sdp_com_socket_connect(sdp_com_t com)
{
    int rv = SDP_SUCCESS;
    char ssl_error_string[SDP_MAX_LINE_LEN];
    int ssl_error = 0;
    int sd, true, conn_success = 0;
    struct sockaddr_in addr;
    struct addrinfo *server_info=NULL, *rp, hints;
    char   port[SDP_COM_MAX_PORT_STRING_BUFFER_LEN] = {0};

#ifdef WIN32
    WSADATA wsa_data;

    /* Winsock needs to be initialized...
    */
    rv = WSAStartup( MAKEWORD(1,1), &wsa_data );
    if( rv != 0 )
    {
        log_msg(LOG_ERR, "Winsock initialization error %d", rv );
        return SDP_ERROR;
    }
#endif

    log_msg(LOG_DEBUG, "Entered socket connect function");

    if(com == NULL || !com->initialized)
        return SDP_ERROR_UNINITIALIZED;

    if(com->conn_state == SDP_COM_CONNECTED)
        return SDP_SUCCESS;

    // cleanup old ssl object if necessary
    if(com->ssl != NULL)
    {
        SSL_free(com->ssl);
        com->ssl = NULL;
    }

    snprintf(port, SDP_COM_MAX_PORT_STRING_BUFFER_LEN, "%u", com->ctrl_port);

    memset(&hints, 0, sizeof(struct addrinfo));

    hints.ai_family   = AF_UNSPEC; /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    log_msg(LOG_DEBUG, "Calling getaddrinfo...");

    if ( (rv = getaddrinfo( com->ctrl_addr , port , &hints , &server_info)) != 0)
    {
        log_msg(LOG_ERR, "getaddrinfo: %s", gai_strerror(rv));
        return SDP_ERROR_GETADDRINFO;
    }

    if(server_info)
        log_msg(LOG_DEBUG, "getaddrinfo call was successful, first node name: %s, port: %s", server_info->ai_canonname, port);
    else
    {
        log_msg(LOG_ERR, "getaddrinfo returned 0 (success?) but server_info pointer is NULL");
        return SDP_ERROR_GETADDRINFO;
    }


       if((sd = socket(PF_INET, SOCK_STREAM, 0)) < 1)
       {
           perror("Socket Creation");
           //log_msg(LOG_ERR, "Socket creation failed");
           return SDP_ERROR_SOCKET;
       }

       // set socket option so we'll be able to reuse the port again if necessary
       true = 1;
       if(setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &true, sizeof(int)) < 0)
       {
           perror("Socket Reuse Port Option");
           return SDP_ERROR_SOCKET_OPTION;
       }

       // set socket options for read timeout
       if(setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, (char*)&(com->read_timeout), sizeof(com->read_timeout)) < 0)
       {
           perror("Socket Read Timeout Option");
           return SDP_ERROR_SOCKET_OPTION;
       }

       // set socket options for write timeout
       if(setsockopt(sd, SOL_SOCKET, SO_SNDTIMEO, (char*)&(com->write_timeout), sizeof(com->write_timeout)) < 0)
       {
           perror("Socket Read Timeout Option");
           return SDP_ERROR_SOCKET_OPTION;
       }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(com->ctrl_port);

    for (rp = server_info; rp != NULL; rp = rp->ai_next)
    {
        if ( connect(sd, rp->ai_addr, sizeof(addr)) == 0 )
        {
            conn_success = 1;
            break;
        }
    }

    freeaddrinfo(server_info);

    if(!conn_success)
    {
        close(sd);
        log_msg(LOG_ERR, "Socket connect failed");
        return SDP_ERROR_CONN_FAIL;
    }

    log_msg(LOG_DEBUG, "Socket connected, creating new SSL object");

    if((com->ssl = SSL_new(com->ssl_ctx)) == NULL)
    {
        log_msg(LOG_ERR, "Failed to create SSL object");
        close(sd);
        return SDP_ERROR_SSL;
    }

    // from here on out, we call sdp_com_disconnect to clean up connections
    // so set the socket_descriptor field for such situations
    com->socket_descriptor = sd;

    log_msg(LOG_DEBUG, "Created new SSL object, setting socket descriptor field in the SSL object");

    // set the socket descriptor field in the ssl object
    if(!SSL_set_fd(com->ssl, sd))
    {
        log_msg(LOG_ERR, "Failed to set socket descriptor in SSL object");
        sdp_com_disconnect(com);
        return SDP_ERROR_SSL;
    }

    log_msg(LOG_DEBUG, "Starting SSL handshake");

    // perform SSL handshake
    if((rv = SSL_connect(com->ssl)) != SDP_COM_SSL_CONNECT_SUCCESS )
    {
        log_msg(LOG_ERR, "SSL handshake failed");

        ssl_error = sdp_com_get_ssl_error(com->ssl, rv, ssl_error_string);

        log_msg(LOG_ERR, "Error from SSL_connect: %d - %s", ssl_error, ssl_error_string);

        sdp_com_disconnect(com);
        return SDP_ERROR_SSL_HANDSHAKE;
    }

    log_msg(LOG_NOTICE, "Connected with %s encryption", SSL_get_cipher(com->ssl));
    if((rv = sdp_com_show_certs(com)) != SDP_SUCCESS)
    {
        sdp_com_disconnect(com);
        return rv;
    }

    return SDP_SUCCESS;
}


static int sdp_com_ssl_ctx_init(SSL_CTX **ssl_ctx)
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    SSL_library_init();

    // Load cryptos, et.al.
    OpenSSL_add_all_algorithms();

    // Bring in and register error messages
    SSL_load_error_strings();

    // Create new client-method instance
    method = TLSv1_2_client_method();

    // Create new context
    ctx = SSL_CTX_new(method);
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        return SDP_ERROR_SSL;
    }

    *ssl_ctx = ctx;
    return SDP_SUCCESS;
}

static int sdp_com_load_certs(SSL_CTX* ctx, char* cert_file, char* key_file)
{
    // set the local certificate from CertFile
    if ( SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        return SDP_ERROR_CERT;
    }
    // set the private key from KeyFile (may be the same as CertFile)
    if ( SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        return SDP_ERROR_KEY;
    }
    // verify private key
    if ( !SSL_CTX_check_private_key(ctx) )
    {
        log_msg(LOG_ERR, "Private key does not match the public certificate");
        return SDP_ERROR_KEY;
    }

    return SDP_SUCCESS;
}

int sdp_com_init(sdp_com_t com)
{
    int rv = SDP_SUCCESS;

    if( !(com->ctrl_addr &&
          com->ctrl_port &&
          com->key_file &&
          com->cert_file &&
          com->read_timeout.tv_sec &&
          com->write_timeout.tv_sec &&
          com->initial_conn_attempt_interval &&
          com->max_conn_attempts))
        return SDP_ERROR_BAD_ARG;

    if( com->use_spa )
    {
        if( !com->fwknoprc_file )
        {
            log_msg(LOG_ERR, "Configured to use SPA for controller, must set FWKNOPRC_FILE.");
            return SDP_ERROR_BAD_ARG;
        }

        if( !com->spa_encryption_key )
        {
            log_msg(LOG_ERR, "Configured to use SPA for controller, must set SPA_ENCRYPTION_KEY.");
            return SDP_ERROR_BAD_ARG;
        }

        if( !com->spa_hmac_key )
        {
            log_msg(LOG_ERR, "Configured to use SPA for controller, must set SPA_HMAC_KEY.");
            return SDP_ERROR_BAD_ARG;
        }

        if( !com->ctrl_stanza )
        {
            log_msg(LOG_ERR, "Configured to use SPA for controller, must set CTRL_STANZA.");
            return SDP_ERROR_BAD_ARG;
        }
    }

    com->conn_state = SDP_COM_DISCONNECTED;

    if(!(com->func_ptr_send_spa))
        com->func_ptr_send_spa = sdp_com_default_send_spa;

    if((rv = sdp_com_ssl_ctx_init(&(com->ssl_ctx))) != SDP_SUCCESS)
        return rv;

    if((rv = sdp_com_load_certs(com->ssl_ctx, com->cert_file, com->key_file)) != SDP_SUCCESS)
        return rv;

    // disable the SIGPIPE signal and handle dropped connections as needed
    signal(SIGPIPE, SIG_IGN);

    com->initialized = 1;

    return SDP_SUCCESS;
}

int sdp_com_new(sdp_com_t *r_com)
{
    sdp_com_t com = NULL;

    if((com = calloc(1, sizeof *com)) == NULL)
        return (SDP_ERROR_MEMORY_ALLOCATION);

    *r_com = com;
    return SDP_SUCCESS;
}


void sdp_com_destroy(sdp_com_t com)
{
    if(com == NULL)
        return;

    if(com->ctrl_addr != NULL)
        free(com->ctrl_addr);

    if(com->ctrl_stanza != NULL)
        free(com->ctrl_stanza);

    if(com->fwknop_path != NULL)
        free(com->fwknop_path);

    if(com->fwknoprc_file != NULL)
        free(com->fwknoprc_file);

    if(com->key_file != NULL)
        free(com->key_file);

    if(com->cert_file != NULL)
        free(com->cert_file);

    if(com->spa_encryption_key != NULL)
        free(com->spa_encryption_key);

    if(com->spa_hmac_key != NULL)
        free(com->spa_hmac_key);

    if(com->ssl != NULL)
        SSL_free(com->ssl);

    if(com->ssl_ctx != NULL)
        SSL_CTX_free(com->ssl_ctx);

    // free the OpenSSL digests and algorithms
    EVP_cleanup();

    // free the OpenSSL error strings
    ERR_free_strings();

    free(com);
}


/**
 * @brief Indicate whether the com module is currently connected
 *
 * This function sets the function parameter 'state' to 1 for
 * connected, 0 for disconnected
 *
 * @param com - sdp_com_tobject
 *
 * @param state    - int, will be set to SDP_COM_CONNECTED or
 *                SDP_COM_DISCONNECTED
 *
 * @return SDP_SUCCESS or error code
 */
int sdp_com_state_get(sdp_com_t com, int *state)
{
    if(com == NULL || !com->initialized)
        return SDP_ERROR_UNINITIALIZED;

    *state = com->conn_state;
    return SDP_SUCCESS;
}


int sdp_com_connect(sdp_com_t com)
{
    int rv = SDP_SUCCESS;
    uint32_t interval;
    int attempts_remaining;
    char *plural;

    if(com == NULL || !com->initialized)
        return SDP_ERROR_UNINITIALIZED;

    interval = com->initial_conn_attempt_interval;

    while(com->conn_state != SDP_COM_CONNECTED)
    {
        com->conn_attempts += 1;

        log_msg(LOG_NOTICE, "Starting connection attempt %d", com->conn_attempts);

        // if SPA required, send SPA
        if(com->use_spa)
        {
            if((rv = com->func_ptr_send_spa(com)) != SDP_SUCCESS)
            {
                // SPA failure can only be a failure on our side
                // so it's fatal
                log_msg(LOG_ERR, "Failed to send SPA, exiting");

                // Leave
                break;
            }
        }

        // connect
        if((rv = sdp_com_socket_connect(com)) != SDP_SUCCESS)
        {
            if(com->max_conn_attempts == 0)
            {
                log_msg(LOG_WARNING,
                        "Connection attempt %d failed, unlimited attempts remaining",
                        com->conn_attempts );
            }
            else
            {
                if((attempts_remaining = com->max_conn_attempts - com->conn_attempts) == 1)
                    plural = "";
                else
                    plural = "s";

                log_msg(LOG_WARNING,
                        "Connection attempt %d failed, %d attempt%s remaining",
                        com->conn_attempts, attempts_remaining, plural );

                if(com->conn_attempts >= com->max_conn_attempts)
                {
                    log_msg(LOG_ERR,
                            "Too many failed connection attempts. Exiting now");
                    break;
                }
            }

            log_msg(LOG_WARNING,
                    "Waiting %d seconds until retry",
                    interval);
            sleep(interval);

            interval *= 2;
            if(interval > SDP_COM_MAX_RETRY_INTERVAL_SECONDS)
                interval = SDP_COM_MAX_RETRY_INTERVAL_SECONDS;
        }
        else
        {
            // have successfully connected
            com->conn_attempts = 0;
            com->conn_state = SDP_COM_CONNECTED;
            break;
        }
    }

    return rv;
}


int sdp_com_disconnect(sdp_com_t com)
{
    if(com == NULL || !com->initialized)
        return SDP_ERROR_UNINITIALIZED;

    log_msg(LOG_DEBUG, "Entered sdp_com_disconnect");

    if(com->ssl != NULL)
    {
        log_msg(LOG_DEBUG, "Tearing down SSL object");
        SSL_shutdown(com->ssl);
        SSL_free(com->ssl);
        com->ssl = NULL;
    }

    if(com->socket_descriptor != 0)
    {
        log_msg(LOG_DEBUG, "Closing socket");
#ifdef WIN32
        closesocket(com->socket_descriptor);
#else
        close(com->socket_descriptor);
#endif
        com->socket_descriptor = 0;
    }

    com->conn_state = SDP_COM_DISCONNECTED;

    log_msg(LOG_DEBUG, "Exiting sdp_com_disconnect");

    return SDP_SUCCESS;
}


int sdp_com_show_certs(sdp_com_t com)
{
    X509 *cert;
    char *line;
    int rv;

    if(com == NULL || !com->initialized)
        return SDP_ERROR_UNINITIALIZED;

    cert = SSL_get_peer_certificate(com->ssl); /* get the server's certificate */
    if ( cert != NULL )
    {
        rv = SDP_SUCCESS;
        log_msg(LOG_NOTICE, "Server certificates:");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        log_msg(LOG_NOTICE, "Subject: %s", line);
        free(line);       /* free the malloc'ed string */
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        log_msg(LOG_NOTICE, "Issuer: %s", line);
        free(line);       /* free the malloc'ed string */
        X509_free(cert);     /* free the malloc'ed certificate copy */
    }
    else
    {
        log_msg(LOG_ERR, "Error: Could not retrieve controller certificate.");
        rv = SDP_ERROR_SSL_NO_CERT_RECEIVED;
    }

    return rv;
}


int sdp_com_send_msg(sdp_com_t com, const char *msg)
{
    uint32_t msg_len = 0;
    int bytes_sent = 0;
    char ssl_error_string[SDP_MAX_LINE_LEN];
    int ssl_error = 0;
    //sdp_header header;
    char header[4];

    log_msg(LOG_DEBUG, "Entered sdp_com_send_msg");

    if(com == NULL || !com->initialized)
        return SDP_ERROR_UNINITIALIZED;

    if(com->conn_state == SDP_COM_DISCONNECTED || com->ssl == NULL)
    {
        log_msg(LOG_ERR, "Failed to send message. Not connected.");
        return SDP_ERROR_CONN_DOWN;
    }

    // this should never be an issue, but safety first
    if(msg == NULL)
        return SDP_ERROR_INVALID_MSG;

    if((msg_len = strnlen(msg, SDP_MSG_MAX_LEN)) >= SDP_MSG_MAX_LEN)
    {
        log_msg(LOG_ERR, "Failed to send message, too long.");
        return SDP_ERROR_INVALID_MSG_LONG;
    }
    else if(msg_len < SDP_MSG_MIN_LEN)
    {
        log_msg(LOG_ERR, "Failed to send message, too short.");
        return SDP_ERROR_INVALID_MSG_SHORT;
    }

    log_msg(LOG_DEBUG, "Message to send: ");
    log_msg(LOG_DEBUG, "  %s", msg);

    //header.length = htonl(msg_len);
    header[0] = (char)( (msg_len >> 24) & 0xFF );
    header[1] = (char)( (msg_len >> 16) & 0xFF );
    header[2] = (char)( (msg_len >> 8) & 0xFF );
    header[3] = (char)(  msg_len & 0xFF );

    if((bytes_sent = SSL_write(com->ssl, header, SDP_COM_HEADER_LEN)) != SDP_COM_HEADER_LEN){
        ssl_error = sdp_com_get_ssl_error(com->ssl, bytes_sent, ssl_error_string);

        log_msg(LOG_ERR, "Error from SSL_write: %s", ssl_error_string);

        // All other cases, tear down and start again
        sdp_com_disconnect(com);
        return SDP_ERROR_SOCKET_WRITE;
    }
    
    // encrypt and send
    if((bytes_sent = SSL_write(com->ssl, msg, msg_len)) != msg_len)
    {
        ssl_error = sdp_com_get_ssl_error(com->ssl, bytes_sent, ssl_error_string);

        log_msg(LOG_ERR, "Error from SSL_write: %s", ssl_error_string);

        if(ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE)
        {
            // retry one time
            if((bytes_sent = SSL_write(com->ssl, msg, msg_len)) == msg_len)
            {
                log_msg(LOG_ERR, "SSL_write succeeded on second attempt");
                return SDP_SUCCESS;
            }
        }

        // All other cases, tear down and start again
        sdp_com_disconnect(com);
        return SDP_ERROR_SOCKET_WRITE;
    }
    // if we got here, all is well
    return SDP_SUCCESS;
}


int sdp_com_get_msg(sdp_com_t com, char **r_msg, int *r_bytes)
{
    int bytes = 0;
    int total_bytes = 0;
    char *msg = NULL;
    unsigned int data_length = 0;
    sdp_header header;

    if(com == NULL || !com->initialized)
        return SDP_ERROR_UNINITIALIZED;

    if(com->conn_state == SDP_COM_DISCONNECTED)
        return SDP_ERROR_CONN_DOWN;

    /* Always returns 0, even when data is available
    if((bytes = SSL_pending(com->ssl)) == 0)
    {
        log_msg(LOG_DEBUG, "No data waiting to be retrieved from socket");
        *r_bytes = 0;
        *r_msg = NULL;
        return SDP_SUCCESS;
    }
    */

    if((bytes = SSL_read(com->ssl, &header, SDP_COM_HEADER_LEN)) <= 0) {
        log_msg(LOG_DEBUG, "No data to read right now");
        *r_bytes = 0;
        return SDP_SUCCESS;
    }

    if (bytes != SDP_COM_HEADER_LEN) {
        log_msg(LOG_ERR, "Header found was shorter than minimum message size");
        return SDP_ERROR_INVALID_MSG_SHORT;
    }

    data_length = ntohl(header.length);

    if (data_length > SDP_COM_MAX_MSG_BLOCK_LEN) {
        log_msg(LOG_ERR, "Header length field indicates message sizes longer than the maximum");
        log_msg(LOG_ERR, "Length field: %u; maximum: %d", data_length, SDP_COM_MAX_MSG_BLOCK_LEN);
        return SDP_ERROR_INVALID_MSG_LONG;
    }

    if((bytes = SSL_read(com->ssl, com->recv_buffer, data_length)) <= 0)
    {
        log_msg(LOG_ERR, "Data found was shorter than minimum message size");
        return SDP_ERROR_INVALID_MSG_SHORT;
    }

    if (bytes != data_length) {
        log_msg(LOG_ERR, "Data read was short %d of %d", bytes, data_length);
        return SDP_ERROR_INVALID_MSG_SHORT;
    }

    log_msg(LOG_DEBUG, "Initial socket read returned %d bytes", bytes);

    if(bytes < SDP_MSG_MIN_LEN)
    {
        log_msg(LOG_ERR, "Data found was shorter than minimum message size");
        return SDP_ERROR_INVALID_MSG_SHORT;
    }

    if((msg = strndup(com->recv_buffer, (size_t)bytes)) == NULL)
        return SDP_ERROR_MEMORY_ALLOCATION;

    total_bytes = bytes;

    // if necessary, keep reading input from controller
    while(bytes >= SDP_COM_MAX_MSG_BLOCK_LEN)
    {
        log_msg(LOG_DEBUG, "Checking for additional data waiting in stream");
        if((bytes = SSL_read(com->ssl, com->recv_buffer, SDP_COM_MAX_MSG_BLOCK_LEN)) > 0)
        {
            if((msg = strncat(msg, com->recv_buffer, (size_t)bytes)) == NULL)
                return SDP_ERROR_MEMORY_ALLOCATION;

            if((total_bytes += bytes) > SDP_MSG_MAX_LEN)
            {
                log_msg(LOG_ERR,
                        "Socket read resulted in too much data: %d bytes. Possible attack.",
                        total_bytes);
                free(msg);
                return SDP_ERROR_INVALID_MSG_LONG;
            }
        }
    }

    *r_msg = msg;
    *r_bytes = total_bytes;
    return SDP_SUCCESS;
}




