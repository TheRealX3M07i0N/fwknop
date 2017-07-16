/*
 * connection_tracker.c
 *
 *  Created on: Sep 29, 2016
 *      Author: Daniel Bailey
 */

//#ifdef FIREWALL_IPTABLES


#include "fwknopd_common.h"
#include "fwknopd_errors.h"
#include "utils.h"
#include "log_msg.h"
#include "extcmd.h"
#include "access.h"
#include "bstrlib.h"
#include "hash_table.h"
#include "sdp_ctrl_client.h"
#include <json-c/json.h>
#include <fcntl.h>
#include "service.h"
#include "connection_tracker.h"

//const char *conn_id_key = "connection_id";
const char *sdp_id_key  = "sdp_id";

//#define DEBUG_CONNECTION_TRACKER
#ifdef DEBUG_CONNECTION_TRACKER
static int new_unknown_conn_count;
static int new_unknown_conn_count_closed;
static int new_unknown_conn_count_open;
static int new_unknown_conn_count_before_walk;
static int known_conn_cnt_before_update;
static int known_conn_cnt_before_update_closed;
static int known_conn_cnt_before_update_open;
static int known_conn_cnt_after_update;
static int known_conn_cnt_after_update_closed;
static int known_conn_cnt_after_update_open;
static int final_known_cnt;
static int known_conns_deleted_during_comp;
static int known_conns_deleted;
#endif


static int msg_conn_list_count = 0;
static hash_table_t *connection_hash_tbl = NULL;
static hash_table_t *latest_connection_hash_tbl = NULL;
//static uint64_t last_conn_id = 0;
static connection_t msg_conn_list = NULL;
static int verbosity = 0;
static time_t next_ctrl_msg_due = 0;
static char conntrack_buf[CONNTRACK_CMD_OUT_BUFSIZE] = {0};

static int close_connections(fko_srv_options_t *opts, char *criteria);


static void print_connection_item(connection_t this_conn)
{
    char start_str[100] = {0};
    char end_str[100] = {0};

    memcpy(start_str, ctime( &(this_conn->start_time) ), 100);

    memcpy(end_str,
           this_conn->end_time ? ctime( &(this_conn->end_time)) : "connection open\n",
           100);

    log_msg(LOG_WARNING,
//            "    Conn ID:  %"PRIu64"\n"
            "      SDP ID:  %"PRIu32"\n"
            "  service ID:  %"PRIu32"\n"
            "    protocol:  %s\n"
            "      src ip:  %s\n"
            "    src port:  %u\n"
            "      dst ip:  %s\n"
            "    dst port:  %u\n"
            "  nat dst ip:  %s\n"
            "nat dst port:  %u\n"
            "  start time:  %s"
            "    end time:  %s"
            "        next:  %p\n\n",
//            this_conn->connection_id,
            this_conn->sdp_id,
            this_conn->service_id,
            this_conn->protocol,
            this_conn->src_ip_str,
            this_conn->src_port,
            this_conn->dst_ip_str,
            this_conn->dst_port,
            this_conn->nat_dst_ip_str,
            this_conn->nat_dst_port,
            start_str, //ctime( &(this_conn->start_time) ),
            end_str, //this_conn->end_time ? ctime( &(this_conn->end_time)) : "connection open\n",
            this_conn->next );

}


static void print_connection_list(connection_t conn)
{
    while(conn != NULL)
    {
        print_connection_item(conn);
        conn = conn->next;
    }

    log_msg(LOG_WARNING, "\n");
}


static void destroy_connection_item(connection_t item)
{
    free(item);
}


static void destroy_connection_list(connection_t list)
{
    connection_t this_conn = list;
    connection_t next = NULL;

    while(this_conn != NULL)
    {
        next = this_conn->next;
        destroy_connection_item(this_conn);
        this_conn = next;
    }
}


static int validate_connection(acc_stanza_t *acc, connection_t conn, int *valid_r)
{
    acc_service_list_t *open_service = NULL;
    acc_port_list_t *open_port = NULL;

    *valid_r = 0;

    if( !(acc && conn) )
    {
        log_msg(LOG_ERR, "validate_connection() ERROR: NULL arg passed");
        return FWKNOPD_ERROR_CONNTRACK;
    }

    open_service = acc->service_list;

    while(open_service != NULL)
    {
        if(open_service->service_id == conn->service_id)
        {
            *valid_r = 1;
            return FWKNOPD_SUCCESS;
        }
        open_service = open_service->next;
    }

    // that didn't work, look for an open port
    open_port = acc->oport_list;

    while(open_port != NULL)
    {
        if(open_port->port == conn->dst_port)
        {
            *valid_r = 1;
            return FWKNOPD_SUCCESS;
        }
        open_port = open_port->next;
    }

    log_msg(LOG_WARNING, "validate_connection() found invalid connection:");
    print_connection_item(conn);
    return FWKNOPD_SUCCESS;
}


static int add_to_connection_list(connection_t *list, connection_t new_guy)
{
    connection_t this_conn = *list;

    if(!new_guy)
    {
        log_msg(LOG_ERR,
                "add_to_connection_list() Error: NULL argument passed");
        return FWKNOPD_ERROR_CONNTRACK;
    }

    if(*list == NULL)
    {
        *list = new_guy;
        return FWKNOPD_SUCCESS;
    }

    while(this_conn->next != NULL)
        this_conn = this_conn->next;

    this_conn->next = new_guy;

    return FWKNOPD_SUCCESS;
}


static int create_connection_item( //uint64_t connection_id,
                                   uint32_t sdp_id,
                                   uint32_t service_id,
                                   char *protocol,
                                   char *src_ip_str,
                                   unsigned int src_port,
                                   char *dst_ip_str,
                                   unsigned int dst_port,
                                   char *nat_dst_ip_str,
                                   unsigned int nat_dst_port,
                                   time_t start_time,
                                   time_t end_time,
                                   connection_t *this_conn_r
                                 )
{
    connection_t this_conn = calloc(1, sizeof *this_conn);

    if(this_conn == NULL)
    {
        log_msg(LOG_ERR, "create_connection_item() FATAL MEMORY ERROR. ABORTING.");
        *this_conn_r = NULL;
        return FWKNOPD_ERROR_MEMORY_ALLOCATION;
    }

//    this_conn->connection_id = connection_id;
    this_conn->sdp_id     = sdp_id;
    this_conn->service_id = service_id;
    strncpy(this_conn->protocol, protocol, MAX_PROTO_STR_LEN+1);
    strncpy(this_conn->src_ip_str, src_ip_str, MAX_IPV4_STR_LEN);
    this_conn->src_port   = src_port;
    strncpy(this_conn->dst_ip_str, dst_ip_str, MAX_IPV4_STR_LEN);
    this_conn->dst_port   = dst_port;
    this_conn->start_time = start_time;
    this_conn->end_time   = end_time;

    if(nat_dst_ip_str != NULL)
        strncpy(this_conn->nat_dst_ip_str, nat_dst_ip_str, MAX_IPV4_STR_LEN);

    this_conn->nat_dst_port = nat_dst_port;

    *this_conn_r = this_conn;

    return FWKNOPD_SUCCESS;
}


static int close_invalid_connection(fko_srv_options_t *opts, connection_t this_conn)
{
    int rv = FWKNOPD_SUCCESS;
    char criteria[CRITERIA_BUF_LEN];
    int reply_src_port = 0;

    // set the closing time
    this_conn->end_time = time(NULL);

    // create search criteria to close the connection
    if(this_conn->nat_dst_port != 0)
    {
        reply_src_port = this_conn->nat_dst_port;
    }
    else
    {
        reply_src_port = this_conn->dst_port;
    }

    snprintf(criteria, CRITERIA_BUF_LEN-1, CONNMARK_SEARCH_ARGS,
             this_conn->sdp_id, this_conn->protocol, this_conn->src_ip_str,
             this_conn->src_port, this_conn->dst_ip_str, this_conn->dst_port,
             reply_src_port);

    // close it
    if( (rv = close_connections(opts, criteria)) != FWKNOPD_SUCCESS)
    {
        return rv;
    }

    // print closed connection
    log_msg(LOG_WARNING, "Gateway closed the following invalid connection from SDP ID %"PRIu32":",
            this_conn->sdp_id);
    print_connection_list(this_conn);

    // add to the ctrl msg list
    if( (rv = add_to_connection_list(&msg_conn_list, this_conn)) != FWKNOPD_SUCCESS)
    {
        return rv;
    }
    msg_conn_list_count++;

    return rv;
}


static int create_connection_item_from_line(fko_srv_options_t *opts,
                                            const char *line,
                                            time_t now,
                                            connection_t *this_conn_r)
{
    int res = FWKNOPD_SUCCESS;
    connection_t this_conn = NULL;
    char *ndx = NULL;
    unsigned int id = 0;
    char return_src_ip_str[MAX_IPV4_STR_LEN] = {0};
    char return_dst_ip_str[MAX_IPV4_STR_LEN] = {0};
    unsigned int return_src_port = 0;

    // first determine if 'mark' is nonzero
    if( (ndx = strstr(line, "mark=")) == NULL)
    {
        *this_conn_r = NULL;
        return FWKNOPD_SUCCESS;
    }

    id = 0;
    if( !sscanf((ndx+strlen("mark=")), "%u", &id) )
    {
        log_msg(LOG_ERR, "create_connection_item_from_line() ERROR: failed to extract "
                "'mark' value from conntrack line:\n     %s\n", line);
        *this_conn_r = NULL;
        return FWKNOPD_SUCCESS;
    }

    if( id == 0 )
    {
        *this_conn_r = NULL;
        return FWKNOPD_SUCCESS;
    }

    // get the connection details
    if( (this_conn = calloc(1, sizeof *this_conn)) == NULL)
    {
        log_msg(LOG_ERR, "create_connection_item_from_line() FATAL MEMORY ERROR. ABORTING.");
        *this_conn_r = NULL;
        return FWKNOPD_ERROR_MEMORY_ALLOCATION;
    }


    if( !sscanf(line, "%4s", this_conn->protocol) )
    {
        log_msg(LOG_ERR, "create_connection_item_from_line() ERROR: failed to extract "
                "protocol value from conntrack line:\n     %s\n", line);
        destroy_connection_item(this_conn);
        *this_conn_r = NULL;
        return FWKNOPD_SUCCESS;
    }

    if( (strncmp(this_conn->protocol, "tcp", 3) != 0) && (strncmp(this_conn->protocol, "udp", 3) != 0) )
    {
        log_msg(LOG_ERR, "create_connection_item_from_line() ERROR: unrecognized "
                "protocol value from conntrack line:\n     %s\n", line);
        destroy_connection_item(this_conn);
        *this_conn_r = NULL;
        return FWKNOPD_SUCCESS;
    }

    if( (ndx = strstr(line, "src=")) == NULL)
    {
        log_msg(LOG_ERR, "create_connection_item_from_line() Failed to find 'src=' "
                "in line: \n     %s\n", line);
        destroy_connection_item(this_conn);
        *this_conn_r = NULL;
        return FWKNOPD_SUCCESS;
    }

    if( (res = sscanf(ndx, "src=%15s dst=%15s sport=%u dport=%u src=%15s dst=%15s sport=%u",
               this_conn->src_ip_str,
               this_conn->dst_ip_str,
               &(this_conn->src_port),
               &(this_conn->dst_port),
               return_src_ip_str,
               return_dst_ip_str,
               &return_src_port)) != 7 )
    {
        log_msg(LOG_ERR, "create_connection_item_from_line() Failed to find "
                "connection details in line: \n     %s\n", ndx);
        destroy_connection_item(this_conn);
        *this_conn_r = NULL;
        return FWKNOPD_SUCCESS;
    }

    this_conn->sdp_id = (uint32_t)id;
    this_conn->start_time = now;

    // if dest address does not match returning source address
    // then NAT is in use
    if(strncmp(this_conn->dst_ip_str, return_src_ip_str, MAX_IPV4_STR_LEN) != 0)
    {
        strncpy(this_conn->nat_dst_ip_str, return_src_ip_str, MAX_IPV4_STR_LEN);
        this_conn->nat_dst_port = return_src_port;
    }

    // if TIME_WAIT flag set, connection is closed
    if( (ndx = strstr(line, "TIME_WAIT")) != NULL)
    {
        log_msg(LOG_DEBUG, "create_connection_item_from_line() TIME_WAIT flag is set "
                "in line: \n     %s\n", line);
        this_conn->end_time = now;
    }

    if((res = get_service_id_by_details(opts, this_conn->protocol,
                                        this_conn->dst_port,
                                        this_conn->nat_dst_ip_str,
                                        this_conn->nat_dst_port,
                                        &(this_conn->service_id))) != FWKNOPD_SUCCESS)
    {
        if(res == FWKNOPD_ERROR_MEMORY_ALLOCATION)
        {
            log_msg(LOG_ERR, "Fatal memory error. Aborting.");
            destroy_connection_item(this_conn);
            *this_conn_r = NULL;
            return res;
        }

        log_msg(LOG_ERR, "Unable to identify service for connection with following details:");
        print_connection_item(this_conn);

        // function adds the connection item to the msg_conn_list so don't destroy it
        res = close_invalid_connection(opts, this_conn);
        *this_conn_r = NULL;
        return res;
    }

    *this_conn_r = this_conn;
    return FWKNOPD_SUCCESS;
}


static int handle_conntrack_print_issue(char **line, char *next_line, char *bad_start, int *line_repaired)
{
    int rv = FWKNOPD_SUCCESS;
    char *temp = NULL;

    *line_repaired = 0;

    if(*line == NULL || next_line == NULL || bad_start == NULL || line_repaired == NULL)
    {
        log_msg(LOG_ERR, "handle_conntrack_print_issue() null arg passed, doing nothing");
        return rv;
    }

    if(bad_start <= *line)
    {
        log_msg(LOG_ERR, "handle_conntrack_print_issue() index to start of bad data is invalid");
        return rv;
    }

    if((temp = calloc(1, (bad_start - *line) + strlen(next_line) + 1)) == NULL)
    {
        log_msg(LOG_ERR, "handle_conntrack_print_issue() fatal memory allocation error");
        return FWKNOPD_ERROR_MEMORY_ALLOCATION;
    }

    memcpy(temp, *line, bad_start - *line);
    strcat(temp, next_line);

    *line = temp;
    *line_repaired = 1;
    return rv;
}


static int search_conntrack(fko_srv_options_t *opts,
                            char *criteria,
                            connection_t *conn_list_r,
                            int *conn_count_r)
{
    char   cmd_buf[CMD_BUFSIZE];
    int    conn_count = 0, res = FWKNOPD_SUCCESS;
    time_t now;
    int pid_status = 0;
    char *line = NULL;
    char *next_line = NULL;
    char *ndx = NULL;
    int line_repaired = 0;
    connection_t this_conn = NULL;
    connection_t conn_list = NULL;

    time(&now);

    memset(cmd_buf, 0x0, CMD_BUFSIZE);
    memset(conntrack_buf, 0x0, CONNTRACK_CMD_OUT_BUFSIZE);

    if(criteria != NULL)
        snprintf(cmd_buf, CMD_BUFSIZE, "conntrack -L %s", criteria);
    else
        snprintf(cmd_buf, CMD_BUFSIZE, "conntrack -L");

    res = run_extcmd(cmd_buf, conntrack_buf, CONNTRACK_CMD_OUT_BUFSIZE,
            WANT_STDERR, NO_TIMEOUT, &pid_status, opts);
    conntrack_buf[CONNTRACK_CMD_OUT_BUFSIZE - 1] = 0x0;

    if(!EXTCMD_IS_SUCCESS(res))
    {
        log_msg(LOG_ERR,
                "search_conntrack() Error %i from cmd:'%s': %s",
                res, cmd_buf, conntrack_buf);
        return FWKNOPD_ERROR_CONNTRACK;
    }

    line = strtok(conntrack_buf, "\n");
    log_msg(LOG_DEBUG, "search_conntrack() first line from conntrack call: \n"
            "    %s\n", line);

    // walk through each of the lines
    while( line != NULL )
    {
        // handle issue with conntrack, prints a status message midstream,
        // inserting it in the middle of a line of data
        if( (ndx = strstr(line, "conntrack")) != NULL)
        {
            if(ndx == line)
            {
                line = strtok(NULL, "\n");
                continue;
            }

            log_msg(LOG_DEBUG, "Found corrupt conntrack line:\n    %s\n", line);

            next_line = strtok(NULL, "\n");

            if((res = handle_conntrack_print_issue(&line, next_line, ndx, &line_repaired))
                    != FWKNOPD_SUCCESS)
            {
                goto cleanup;
            }

            log_msg(LOG_DEBUG, "Corrected conntrack line:\n    %s\n", line);
        }

        // extract connection info from line and create connection item
        if( (res = create_connection_item_from_line(opts, line, now, &this_conn)) != FWKNOPD_SUCCESS)
        {
            goto cleanup;
        }

        if(this_conn != NULL)
        {
            if( (res = add_to_connection_list(&conn_list, this_conn)) != FWKNOPD_SUCCESS)
            {
                destroy_connection_item(this_conn);
                goto cleanup;
            }

            conn_count++;
        }

        if(line_repaired)
        {
            free(line);
            line_repaired = 0;
        }

        line = strtok(NULL, "\n");
    }

    *conn_list_r = conn_list;
    *conn_count_r = conn_count;

    return res;

cleanup:
    destroy_connection_list(conn_list);
    if(line_repaired)
        free(line);

    return res;
}


static int close_connections(fko_srv_options_t *opts, char *criteria)
{
    char   cmd_buf[CMD_BUFSIZE];
    char   cmd_out[STANDARD_CMD_OUT_BUFSIZE];
    int    conn_count = 0, res = FWKNOPD_SUCCESS;
    int pid_status = 0;
    connection_t conn_list = NULL;

    if(criteria == NULL)
    {
        log_msg(LOG_WARNING, "close_connections() null criteria passed, nothing to close");
        return res;
    }

    memset(cmd_buf, 0x0, CMD_BUFSIZE);
    memset(cmd_out, 0x0, STANDARD_CMD_OUT_BUFSIZE);

    snprintf(cmd_buf, CMD_BUFSIZE, "conntrack -D %s", criteria);

    res = run_extcmd(cmd_buf, cmd_out, STANDARD_CMD_OUT_BUFSIZE,
                     WANT_STDERR, NO_TIMEOUT, &pid_status, opts);
    chop_newline(cmd_out);

    if(!EXTCMD_IS_SUCCESS(res))
    {
        log_msg(LOG_ERR, "close_connections() Error %i from cmd:'%s': %s",
                res, cmd_buf, cmd_out);
        return FWKNOPD_ERROR_CONNTRACK;
    }

    if( (res = search_conntrack(opts, criteria, &conn_list, &conn_count)) != FWKNOPD_SUCCESS)
    {
        log_msg(LOG_ERR, "close_connections() Error when trying to verify connections were closed");
        return res;
    }

    if(conn_count != 0)
    {
        log_msg(LOG_ERR, "close_connections() Failed to close the following connections:");
        print_connection_list(conn_list);
        return FWKNOPD_ERROR_CONNTRACK;
    }

    log_msg(LOG_WARNING, "Gateway closed connections meeting the following criteria:\n"
                         "     %s \n", criteria);

    return res;
}


static int duplicate_connection_item(connection_t orig, connection_t *copy)
{
    if(orig == NULL)
    {
        *copy = NULL;
        return FWKNOPD_SUCCESS;
    }

    return create_connection_item( //orig->connection_id,
                                   orig->sdp_id,
                                   orig->service_id,
                                   orig->protocol,
                                   orig->src_ip_str,
                                   orig->src_port,
                                   orig->dst_ip_str,
                                   orig->dst_port,
                                   orig->nat_dst_ip_str,
                                   orig->nat_dst_port,
                                   orig->start_time,
                                   orig->end_time,
                                   copy );
}


static int duplicate_connection_list(connection_t orig, connection_t *copy)
{
    int rv = FWKNOPD_SUCCESS;
    connection_t this_conn = orig;
    connection_t last_conn = NULL;
    connection_t new_list = NULL;

    if(this_conn == NULL)
    {
        *copy = NULL;
        return rv;
    }

    if((rv = duplicate_connection_item(this_conn, &new_list)) != FWKNOPD_SUCCESS)
        return rv;

    last_conn = new_list;

    while(this_conn->next != NULL)
    {
        this_conn = this_conn->next;

        if((rv = duplicate_connection_item(this_conn, &(last_conn->next))) != FWKNOPD_SUCCESS)
            goto cleanup;

        // shouldn't be possible, but just to be safe
        if(last_conn->next == NULL)
        {
            log_msg(LOG_ERR, "duplicate_connection_list() duplicate_connection_item "
                    "failed to set last_conn->next.");
            rv = FWKNOPD_ERROR_CONNTRACK;
            goto cleanup;
        }

        last_conn = last_conn->next;
    }

    *copy = new_list;
    return rv;

cleanup:
    destroy_connection_list(new_list);
    *copy = NULL;
    return rv;
}


static int store_in_connection_hash_tbl(hash_table_t *tbl, connection_t this_conn)
{
    int res = FWKNOPD_SUCCESS;
    bstring key = NULL;
    char id_str[SDP_MAX_CLIENT_ID_STR_LEN] = {0};
    connection_t present_conns = NULL;

    // convert the sdp id integer to a bstring
    snprintf(id_str, SDP_MAX_CLIENT_ID_STR_LEN, "%"PRIu32, this_conn->sdp_id);
    key = bfromcstr(id_str);
    // key is not freed if hash_table_set is called,
    // because the hash table keeps it

    // if a node for this SDP ID doesn't yet exist in the table
    // gotta make it
    if( (present_conns = hash_table_get(tbl, key)) == NULL)
    {
        log_msg(LOG_DEBUG, "store_in_connection_hash_tbl() ID %"PRIu32
                " not yet in table. \n", this_conn->sdp_id);

        if( (res = hash_table_set(tbl, key, this_conn)) != FWKNOPD_SUCCESS)
        {
            log_msg(LOG_ERR,
                "[*] Fatal memory allocation error updating 'latest' connection tracking hash table"
            );
            bdestroy(key);
        }
    }
    else
    {
        log_msg(LOG_DEBUG, "store_in_connection_hash_tbl() ID %"PRIu32
                " already exists in table. \n", this_conn->sdp_id);

        // key is no longer needed in this case, didn't create a new hash node
        bdestroy(key);

        // this one should be impossible to fail, but we will still return the res
        res = add_to_connection_list(&present_conns, this_conn);

        log_msg(LOG_DEBUG, "store_in_connection_hash_tbl() Added conn to current "
                "list for SDP ID: %"PRIu32" \n", this_conn->sdp_id);
    }

    return res;
}


static int check_conntrack(fko_srv_options_t *opts, int *conn_count_r)
{
    int    conn_count = 0, res = FWKNOPD_SUCCESS;
    connection_t this_conn = NULL;
    connection_t next = NULL;

    log_msg(LOG_DEBUG, "check_conntrack() Getting latest connections... \n");

    if( (res = search_conntrack(opts, NULL, &this_conn, &conn_count)) != FWKNOPD_SUCCESS)
        return res;

    if(verbosity >= LOG_DEBUG)
    {
        log_msg(LOG_DEBUG, "\n\nDumping connection list from search_conntrack:");
        print_connection_list(this_conn);
    }

    while(this_conn != NULL)
    {
        next = this_conn->next;
        this_conn->next = NULL;

        if( (res = store_in_connection_hash_tbl(latest_connection_hash_tbl, this_conn)) != FWKNOPD_SUCCESS)
        {
            // destroy remainder of list,
            // not ones that were successfully stored in the hash table
            destroy_connection_item(this_conn);
            destroy_connection_list(next);
            return res;
        }

        log_msg(LOG_DEBUG, "check_conntrack() back from storing a conn in latest_connection_hash_tbl \n");

        this_conn = next;
    }

#ifdef DEBUG_CONNECTION_TRACKER
    log_msg(LOG_ALERT, "           conntrack connection count: %6d", conn_count);
#endif

    *conn_count_r = conn_count;

    return res;
}


static void destroy_hash_node_cb(hash_table_node_t *node)
{
  if(node->key != NULL) bdestroy((bstring)(node->key));
  if(node->data != NULL)
  {
      // this function takes care of all connection nodes (NOT hash table nodes)
      // for this SDP ID, including the very first one
      destroy_connection_list((connection_t)(node->data));
  }
}


static int connection_items_match(connection_t a, connection_t b)
{
    // make sure neither is NULL first
    if(!(a && b))
        return 0;

    if( a->sdp_id   == b->sdp_id     &&
        a->src_port == b->src_port   &&
        a->dst_port == b->dst_port   &&
        a->nat_dst_port == b->nat_dst_port   &&
        strncmp(a->src_ip_str, b->src_ip_str, MAX_IPV4_STR_LEN) == 0 &&
        strncmp(a->dst_ip_str, b->dst_ip_str, MAX_IPV4_STR_LEN) == 0 &&
        strncmp(a->nat_dst_ip_str, b->nat_dst_ip_str, MAX_IPV4_STR_LEN) == 0)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}


static int compare_connection_lists(connection_t *known_conns,
                                    connection_t *current_conns,
                                    connection_t *closed_conns)
{
    int rv = FWKNOPD_SUCCESS;
    int match = 0;
    int conn_closed = 0;
    connection_t this_known_conn = *known_conns;
    connection_t prev_known_conn = NULL;
    connection_t next_conn = NULL;
    connection_t this_current_conn = NULL;
    connection_t prev_current_conn = NULL;
    time_t now = time(NULL);

#ifdef DEBUG_CONNECTION_TRACKER
    int known_conns_count_pre = 0;
    int known_conns_count_post = 0;
    int known_conns_del = 0;

    while(this_known_conn != NULL)
    {
        known_conns_count_pre++;
        this_known_conn = this_known_conn->next;
    }

    this_known_conn = *known_conns;
#endif

    log_msg(LOG_DEBUG, "compare_connection_lists() entered");

    while(this_known_conn != NULL)
    {
        match = 0;
        conn_closed = 0;
        this_current_conn = *current_conns;
        prev_current_conn = NULL;

        while(this_current_conn != NULL)
        {
            if( (match = connection_items_match(this_known_conn, this_current_conn)) == 1 )
            {
                // got a match, remove from current_conns list

                 // if very first connection item was the match
                if(prev_current_conn == NULL)
                {
                    *current_conns = this_current_conn->next;
                }
                else
                {
                    prev_current_conn->next = this_current_conn->next;
                }

                // if end_time was set, means TIME_WAIT flag was set
                if(this_current_conn->end_time != 0)
                    conn_closed = 1;

                destroy_connection_item(this_current_conn);
                this_current_conn = NULL;
                break;
            }

            prev_current_conn = this_current_conn;
            this_current_conn = this_current_conn->next;

        }   // END while(this_current_conn != NULL)

        next_conn = this_known_conn->next;

        // if a match was found for this known connection
        if(match && !conn_closed)
        {
            // then it's still live, so
            // the conn stays in the known conn list
            // just move to next known conn
            prev_known_conn = this_known_conn;
#ifdef DEBUG_CONNECTION_TRACKER
            known_conn_cnt_before_update_open++;
            known_conn_cnt_after_update_open++;
#endif
        }
        else
        {
            // if end_time not set, this is first time we saw that it's closed
            // whether because it's missing from conntrack or TIME_WAIT flag set
            // so need to add to closed_conns list to report to controller
            if(this_known_conn->end_time == 0)
            {
#ifdef DEBUG_CONNECTION_TRACKER
                known_conn_cnt_before_update_open++;
#endif

                this_known_conn->end_time = now;

                log_msg(LOG_DEBUG, "compare_connection_lists() adding previously known conn to closed list");

                if( (rv = duplicate_connection_item(this_known_conn, &this_current_conn))
                        != FWKNOPD_SUCCESS)
                {
                    goto cleanup;
                }

                this_current_conn->next = NULL;

                if( (rv = add_to_connection_list(closed_conns, this_current_conn))
                        != FWKNOPD_SUCCESS)
                {
                    destroy_connection_item(this_current_conn);
                    goto cleanup;
                }
            }
#ifdef DEBUG_CONNECTION_TRACKER
            else
            {
                known_conn_cnt_before_update_closed++;
            }
#endif

            // if no match was found, connection is truly gone from conntrack so
            // can now remove from known connections
            if(!match)
            {
                // the conn no longer exists, remove from known conns
                // when removing a known conn, prev_known_conn should not be updated
                this_known_conn->next = NULL;

                // if we're removing the first conn in the known conn list
                if(prev_known_conn == NULL)
                {
                    *known_conns = next_conn;
                }
                else
                {
                    prev_known_conn->next = next_conn;
                }

#ifdef DEBUG_CONNECTION_TRACKER
                known_conns_deleted++;
                known_conns_deleted_during_comp++;
                known_conns_del++;
#endif

                destroy_connection_item(this_known_conn);
            }
            else
            {
                prev_known_conn = this_known_conn;
#ifdef DEBUG_CONNECTION_TRACKER
                if(conn_closed)
                        known_conn_cnt_after_update_closed++;
                else
                        known_conn_cnt_after_update_open++;
#endif
            }

        }  // END if(match)

        // move to next known conn
        this_known_conn = next_conn;

    }  // END while(this_known_conn != NULL)

#ifdef DEBUG_CONNECTION_TRACKER
    this_known_conn = *known_conns;
    while(this_known_conn != NULL)
    {
        known_conns_count_post++;
        this_known_conn = this_known_conn->next;
    }

    log_msg(LOG_ALERT, " Known conns before:  %6d", known_conns_count_pre);
    log_msg(LOG_ALERT, " Known conns deleted: %6d", known_conns_del);
    log_msg(LOG_ALERT, " Known conns after:   %6d", known_conns_count_post);
    if(known_conns_count_post != (known_conns_count_pre - known_conns_del))
    {
        log_msg(LOG_ALERT, "ERROR: CONN COUNT DOES NOT ADD UP!");
        rv = FWKNOPD_ERROR_MEMORY_ALLOCATION;
    }
    else
    {
        log_msg(LOG_ALERT, "SUCCESS: CONN COUNT CHECKS OUT");
    }
    log_msg(LOG_ALERT, "\n\n");
#endif

    return rv;

cleanup:
    destroy_connection_list(*closed_conns);
    *closed_conns = NULL;

    return rv;
}


static int traverse_print_conn_items_cb(hash_table_node_t *node, void *arg)
{
    print_connection_list((connection_t)(node->data));

    return FWKNOPD_SUCCESS;
}


static int traverse_compare_latest_cb(hash_table_node_t *node, void *arg)
{
    int rv = FWKNOPD_SUCCESS;
    connection_t known_conns = NULL;
    connection_t current_conns = NULL;
    connection_t copy_current_conns = NULL;
    time_t *end_time = (time_t*)arg;
    connection_t closed_conns = NULL;
    int closed_conn_count = 0;
    connection_t temp_conn = NULL;
    connection_t prev_conn = NULL;
    connection_t next_conn = NULL;
    bstring key = NULL;

    // just a safety check, shouldn't be possible
    if(node->data == NULL)
    {
        hash_table_delete(connection_hash_tbl, node->key);
        return rv;
    }

    if((key = bstrcpy((bstring)(node->key))) == NULL)
    {
        log_msg(LOG_ERR, "traverse_compare_latest_cb() Failed to duplicate key");
        return FWKNOPD_ERROR_MEMORY_ALLOCATION;
    }

    // going to manipulate this data directly and reset the data pointer
    known_conns = (connection_t)(node->data);

    // check whether this SDP ID still has any current connections
    if( (current_conns = hash_table_get(latest_connection_hash_tbl, key)) == NULL)
    {
        // only report those that haven't been reported yet
        temp_conn = known_conns;
        while(temp_conn != NULL)
        {
#ifdef DEBUG_CONNECTION_TRACKER
            known_conns_deleted++;
#endif

            next_conn = temp_conn->next;

            // don't report those already reported
            if(temp_conn->end_time != 0)
            {
#ifdef DEBUG_CONNECTION_TRACKER
                known_conn_cnt_before_update_closed++;
#endif
                prev_conn = temp_conn;
            }
            else
            {
#ifdef DEBUG_CONNECTION_TRACKER
                known_conn_cnt_before_update_open++;
#endif
                temp_conn->end_time = *end_time;

                if(prev_conn != NULL)
                    prev_conn->next = temp_conn->next;
                else
                    node->data = (void*)(temp_conn->next);

                temp_conn->next = NULL;

                // add to closed_conns
                closed_conn_count++;
                if( (rv = add_to_connection_list(&closed_conns, temp_conn))
                        != FWKNOPD_SUCCESS)
                {
                    goto cleanup;
                }
            }

            temp_conn = next_conn;
        }

        if(closed_conns != NULL)
        {
            if(verbosity >= LOG_DEBUG)
            {
                log_msg(LOG_WARNING, "All connections closed for SDP ID %"PRIu32":",
                        known_conns->sdp_id);
                print_connection_list(closed_conns);
            }


            // add these closed connections to the ctrl message list
            if( (rv = add_to_connection_list(&msg_conn_list, closed_conns))
                    != FWKNOPD_SUCCESS)
            {
                goto cleanup;
            }
            msg_conn_list_count += closed_conn_count;

            closed_conns = NULL;
        }

        // set node->data to NULL so the list is not deleted with the node
        //node->data = NULL;

        // this SDP ID no longer has connections, remove entirely from
        // known connection list, hash table traverser is fine with
        // deleting random nodes along the way
        hash_table_delete(connection_hash_tbl, key);
        goto cleanup;
    }

    // at this point, we know this ID has both known and current connections
    // have to compare each connection in-depth

    // first make a copy of current_conns to avoid data corruption
    // because we'll be deleting the node from 'latest' conn hash table
    if((rv = duplicate_connection_list(current_conns, &copy_current_conns)) != FWKNOPD_SUCCESS)
        return rv;

    // delete the entry in 'latest' conn hash table, we'll take it from here
    hash_table_delete(latest_connection_hash_tbl, key);

    // following function removes conns from known_conns if no longer in
    // conntrack - leaving only old, still-open conns and conns flagged as
    // closed but still in conntrack,
    // removes previously known conns from copy_current_conns - leaving only
    // entirely new conns,
    // puts closed conns in closed_conns
    if( (rv = compare_connection_lists(&known_conns, &copy_current_conns,
            &closed_conns)) != FWKNOPD_SUCCESS)
    {
        goto cleanup;
    }

    // any remaining conns in copy_current_conns list are totally new
    if(copy_current_conns != NULL)
    {
        // store the truly new conns back to the 'latest' conn hash table for later
        if( (rv = hash_table_set(latest_connection_hash_tbl, key, copy_current_conns))
                != FWKNOPD_SUCCESS)
        {
            log_msg(LOG_ERR, "Failed to store revised list of new conns in hash table");
            goto cleanup;
        }

        copy_current_conns = NULL;
        key = NULL;
    }

    node->data = known_conns;

    if(known_conns == NULL)
    {
        hash_table_delete(connection_hash_tbl, node->key);
    }

    // add closed conns to the ctrl message list
    if(closed_conns != NULL)
    {
        if(verbosity >= LOG_DEBUG)
        {
            log_msg(LOG_WARNING, "Following connections closed for SDP ID %"PRIu32":",
                    closed_conns->sdp_id);
            print_connection_list(closed_conns);
        }

        if( (rv = add_to_connection_list(&msg_conn_list, closed_conns))
                != FWKNOPD_SUCCESS)
        {
            goto cleanup;
        }

        // count them too
        temp_conn = closed_conns;
        while(temp_conn != NULL)
        {
            msg_conn_list_count++;
            temp_conn = temp_conn->next;
        }

    }

    // this was a duplicate of the key from known conns table
    // if it was used/stored back to latest conns table (new conns still to handle)
    // then the pointer was set to NULL so that we don't destroy it
    // if there were no new conns to store, need to destroy it
    if(key != NULL)
        bdestroy(key);

    return rv;

cleanup:
    if(key != NULL)
        bdestroy(key);
    destroy_connection_list(copy_current_conns);
    destroy_connection_list(closed_conns);
    return rv;
}


static int validate_node_connections(fko_srv_options_t *opts, hash_table_node_t *node)
{
    int rv = FWKNOPD_SUCCESS;
    acc_stanza_t *acc = NULL;
    bstring key = (bstring)node->key;
    connection_t this_conn = (connection_t)(node->data);
    connection_t prev_conn = NULL;
    connection_t next_conn = NULL;
    connection_t temp_conn = NULL;
    int closed_conn_count = 0;
    int conn_valid = 0;
    char criteria[CRITERIA_BUF_LEN];
    time_t now = time(NULL);

    // always double-check
    if(this_conn == NULL)
    {
        return rv;
    }

    memset(criteria, 0x0, CRITERIA_BUF_LEN);

    // lock the hash table mutex
    if(pthread_mutex_lock(&(opts->acc_hash_tbl_mutex)))
    {
        log_msg(LOG_ERR, "Mutex lock error.");
        return 0;
    }

    acc = hash_table_get(opts->acc_stanza_hash_tbl, key);

    pthread_mutex_unlock(&(opts->acc_hash_tbl_mutex));

    // see if sdp id still exists in access table
    if( acc == NULL )
    {
        // this sdp id is no longer authorized to access anything
        // remove all connections marked with this sdp id
        snprintf(criteria, CRITERIA_BUF_LEN, "-m %"PRIu32, this_conn->sdp_id);

        if( (rv = close_connections(opts, criteria)) != FWKNOPD_SUCCESS)
        {
            return rv;
        }

        // set the end time for all of the connections
        temp_conn = this_conn;
        while(temp_conn != NULL)
        {
            temp_conn->end_time = now;
            temp_conn = temp_conn->next;
            closed_conn_count++;
        }


        // print the closed conns
        log_msg(LOG_WARNING, "Gateway closed the following (i.e. all) connections from SDP ID %"PRIu32":",
                this_conn->sdp_id);
        print_connection_list(this_conn);

        // pin the whole list onto the ctrl message list
        if( (rv = add_to_connection_list(&msg_conn_list, node->data)) != FWKNOPD_SUCCESS)
        {
            return rv;
        }
        msg_conn_list_count += closed_conn_count;

        // make sure the hash table node no longer points to the
        // connection list
        node->data = NULL;
        this_conn = NULL;
    }

    while(this_conn != NULL)
    {
        conn_valid = 0;
        if( (rv = validate_connection(acc, this_conn, &conn_valid)) != FWKNOPD_SUCCESS)
            return rv;

        next_conn = this_conn->next;

        if(conn_valid == 1)
        {
            prev_conn = this_conn;
        }
        else
        {
            // remove from node->data list
            if(prev_conn == NULL)
                node->data = this_conn->next;
            else
                prev_conn->next = this_conn->next;

            this_conn->next = NULL;

            if( (rv = close_invalid_connection(opts, this_conn)) != FWKNOPD_SUCCESS)
            {
                return rv;
            }
        }

        this_conn = next_conn;
    }

    return FWKNOPD_SUCCESS;
}


static int traverse_validate_connections_cb(hash_table_node_t *node, void *arg)
{
    int rv = FWKNOPD_SUCCESS;
    fko_srv_options_t *opts = (fko_srv_options_t*)arg;

    if(node->data == NULL)
    {
        log_msg(LOG_ERR, "traverse_validate_connections_cb() node->data is NULL, shouldn't happen\n");
        hash_table_delete(connection_hash_tbl, node->key);
        return rv;
    }

    if( (rv = validate_node_connections(opts, node)) != FWKNOPD_SUCCESS)
    {
        return rv;
    }

    // if it happens that no connections are left open
    // delete the node from the known connections hash table
    if(node->data == NULL)
        hash_table_delete(connection_hash_tbl, node->key);

    return rv;
}


static int traverse_handle_new_conns_cb(hash_table_node_t *node, void *arg)
{
    int rv = FWKNOPD_SUCCESS;
    fko_srv_options_t *opts = (fko_srv_options_t*)arg;
    bstring key = NULL;
    connection_t temp_conn = NULL;
    connection_t known_conns = NULL;
    connection_t new_conns = NULL;

    log_msg(LOG_DEBUG, "traverse_handle_new_conns_cb() entered");

    if(node->data == NULL)
    {
        log_msg(LOG_ERR, "traverse_handle_new_conns_cb() node->data is NULL, shouldn't happen\n");
        hash_table_delete(latest_connection_hash_tbl, node->key);
        return rv;
    }

//    // assign connection ids
//    temp_conn = (connection_t)(node->data);
//    while(temp_conn != NULL)
//    {
//        last_conn_id++;
//        temp_conn->connection_id = last_conn_id;
//        temp_conn = temp_conn->next;
//    }

    temp_conn = (connection_t)(node->data);
    if(verbosity >= LOG_DEBUG)
    {
        log_msg(LOG_WARNING, "New connections from SDP ID %"PRIu32":",
                temp_conn->sdp_id);
        print_connection_list(temp_conn);
    }

    if( (rv = validate_node_connections(opts, node)) != FWKNOPD_SUCCESS)
    {
        return rv;
    }

    // if it happens that no connections are left open (all were invalid)
    // delete the node from the 'latest' connections hash table
    if(node->data == NULL)
    {
        hash_table_delete(latest_connection_hash_tbl, node->key);
        return rv;
    }


    // arriving here means there are new connections which we have validated
    // so we need to store in known conns list and ctrl message list
    if((rv = duplicate_connection_list((connection_t)(node->data), &temp_conn)) != FWKNOPD_SUCCESS)
    {
        goto cleanup;
    }

    // this sdp id may have other connections already in the known conn table
    if( (known_conns = hash_table_get(connection_hash_tbl, node->key)) != NULL)
    {
        if( (rv = add_to_connection_list(&known_conns, temp_conn)) != FWKNOPD_SUCCESS)
            goto cleanup;
    }
    else
    {
        // need to create new hash table entry in known conns
        // make a duplicate key to store in the hash table
        if((key = bstrcpy((bstring)(node->key))) == NULL)
        {
            log_msg(LOG_ERR, "traverse_handle_new_conns_cb() Failed to duplicate key");
            rv = FWKNOPD_ERROR_MEMORY_ALLOCATION;
            goto cleanup;
        }

        // copy all new conns to known conns hash table
        if( (rv = hash_table_set(connection_hash_tbl, key, temp_conn)) != FWKNOPD_SUCCESS)
        {
            bdestroy(key);
            goto cleanup;
        }
    }

    log_msg(LOG_DEBUG, "traverse_handle_new_conns_cb() adding new conns to msg list\n");

    if( (rv = add_to_connection_list(&msg_conn_list, (connection_t)(node->data))) != FWKNOPD_SUCCESS)
        return rv;

    // count conns added to message list
    new_conns = (connection_t)(node->data);
    while(new_conns != NULL)
    {
#ifdef DEBUG_CONNECTION_TRACKER
        if(new_conns->end_time)
                new_unknown_conn_count_closed++;
        else
                new_unknown_conn_count_open++;
#endif
        msg_conn_list_count++;
        new_conns = new_conns->next;
    }

    node->data = NULL;
    hash_table_delete(latest_connection_hash_tbl, node->key);
    return rv;

cleanup:
    destroy_connection_list(temp_conn);
    return rv;
}



//static int conn_id_file_check(const char *file, int *exists)
//{
//    struct stat st;
//    uid_t caller_uid = 0;
//
//    // if file exists
//    if((stat(file, &st)) == 0)
//    {
//        *exists = 1;
//
//        // Make sure it is a regular file
//        if(S_ISREG(st.st_mode) != 1 && S_ISLNK(st.st_mode) != 1)
//        {
//            log_msg(LOG_WARNING,
//                "[-] file: %s is not a regular file or symbolic link.",
//                file
//            );
//            return FWKNOPD_ERROR_CONNTRACK;
//        }
//
//        if((st.st_mode & (S_IRWXU|S_IRWXG|S_IRWXO)) != (S_IRUSR|S_IWUSR))
//        {
//            log_msg(LOG_WARNING,
//                "[-] file: %s permissions should only be user read/write (0600, -rw-------)",
//                file
//            );
//        }
//
//        caller_uid = getuid();
//        if(st.st_uid != caller_uid)
//        {
//            log_msg(LOG_WARNING, "[-] file: %s (owner: %llu) not owned by current effective user id: %llu",
//                file, (unsigned long long)st.st_uid, (unsigned long long)caller_uid);
//        }
//    }
//    else
//    {
//        // if the path doesn't exist, just return, but otherwise something
//        // went wrong
//        if(errno != ENOENT)
//        {
//            log_msg(LOG_ERR, "[-] stat() against file: %s returned: %s",
//                file, strerror(errno));
//            return FWKNOPD_ERROR_CONNTRACK;
//        }
//
//        *exists = 0;
//    }
//
//    return FWKNOPD_SUCCESS;
//}
//
//
//static void store_last_conn_id(const fko_srv_options_t *opts)
//{
//    int     op_fd, num_bytes = 0;
//    char    buf[CONN_ID_BUF_LEN] = {0};
//
//    // Don't store it if it's zero
//    if(last_conn_id == 0)
//        return;
//
//    // Reset errno (just in case)
//    errno = 0;
//
//    // Open the PID file
//    op_fd = open(
//        opts->config[CONF_CONN_ID_FILE], O_WRONLY|O_CREAT, S_IRUSR|S_IWUSR
//    );
//
//    if(op_fd == -1)
//    {
//        perror("Error trying to open connection ID file: ");
//        return;
//    }
//
//    if(fcntl(op_fd, F_SETFD, FD_CLOEXEC) == -1)
//    {
//        close(op_fd);
//        perror("Unexpected error from fcntl: ");
//        return;
//    }
//
//    // Write last connection ID to the file
//    snprintf(buf, CONN_ID_BUF_LEN, "%"PRIu64"\n", last_conn_id);
//
//    log_msg(LOG_DEBUG, "[+] Writing last connection ID (%"PRIu64") to the lock file: %s",
//        last_conn_id, opts->config[CONF_CONN_ID_FILE]);
//
//    num_bytes = write(op_fd, buf, strlen(buf));
//
//    if(errno || num_bytes != strlen(buf))
//        perror("Connection ID file write error: ");
//
//    // Sync/flush regardless...
//    fsync(op_fd);
//
//    close(op_fd);
//
//    return;
//}
//
//static int get_set_last_conn_id(const fko_srv_options_t *opts)
//{
//    int rv = FWKNOPD_SUCCESS;
//    int exists = 0;
//    int     op_fd, bytes_read = 0;
//    char    buf[CONN_ID_BUF_LEN] = {0};
//    uint64_t conn_id            = 0;
//
//    log_msg(LOG_DEBUG, "get_set_last_conn_id() checking file perms...");
//    if( (rv = conn_id_file_check(opts->config[CONF_CONN_ID_FILE], &exists)) != FWKNOPD_SUCCESS)
//    {
//        log_msg(LOG_ERR, "conn_id_file_check() error\n");
//        return(rv);
//    }
//
//    if(!exists)
//    {
//        log_msg(LOG_WARNING, "get_set_last_conn_id() conn ID file does not yet exist, starting at zero");
//        last_conn_id = 0;
//        return FWKNOPD_SUCCESS;
//    }
//
//    log_msg(LOG_DEBUG, "get_set_last_conn_id() opening the file...");
//    op_fd = open(opts->config[CONF_CONN_ID_FILE], O_RDONLY);
//
//    if(op_fd == -1)
//    {
//        log_msg(LOG_ERR, "get_set_last_conn_id() ERROR - conn ID file exists but can't open");
//        last_conn_id = 0;
//        return FWKNOPD_ERROR_CONNTRACK;
//    }
//
//    log_msg(LOG_DEBUG, "get_set_last_conn_id() reading the file...");
//    bytes_read = read(op_fd, buf, CONN_ID_BUF_LEN);
//    if (bytes_read > 0)
//    {
//        buf[CONN_ID_BUF_LEN-1] = '\0';
//
//        log_msg(LOG_DEBUG, "get_set_last_conn_id() Got following string from the conn ID file: %s\n",
//                buf);
//
//        conn_id = strtoull_wrapper(buf, 0, UINT64_MAX, NO_EXIT_UPON_ERR, &rv);
//        if(rv != FKO_SUCCESS)
//        {
//            log_msg(LOG_ERR, "get_set_last_conn_id() ERROR converting conn ID "
//                    "string to uint64_t");
//        }
//        else
//        {
//            last_conn_id = conn_id;
//            log_msg(LOG_DEBUG, "get_set_last_conn_id() setting conn ID value: %"PRIu64"\n",
//                    last_conn_id);
//        }
//    }
//    else if (bytes_read < 0)
//    {
//        rv = FWKNOPD_ERROR_CONNTRACK;
//        perror("Error trying to read() PID file: ");
//    }
//
//    close(op_fd);
//
//    return rv;
//}



int init_connection_tracker(fko_srv_options_t *opts)
{
    int hash_table_len = 0;
    int is_err = FWKNOPD_SUCCESS;

    verbosity = LOG_DEFAULT_VERBOSITY + opts->verbose;

    // set the global connection ID variable
//    if( (is_err = get_set_last_conn_id(opts)) != FWKNOPD_SUCCESS)
//        return is_err;

    // connection table should be same length as access stanza hash table
    hash_table_len = strtol_wrapper(opts->config[CONF_ACC_STANZA_HASH_TABLE_LENGTH],
                           MIN_ACC_STANZA_HASH_TABLE_LENGTH,
                           MAX_ACC_STANZA_HASH_TABLE_LENGTH,
                           NO_EXIT_UPON_ERR,
                           &is_err);

    if(is_err != FKO_SUCCESS)
    {
        log_msg(LOG_ERR, "[*] var %s value '%s' not in the range %d-%d",
                "ACC_STANZA_HASH_TABLE_LENGTH",
                opts->config[CONF_ACC_STANZA_HASH_TABLE_LENGTH],
                MIN_ACC_STANZA_HASH_TABLE_LENGTH,
                MAX_ACC_STANZA_HASH_TABLE_LENGTH);
        clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
    }

    connection_hash_tbl = hash_table_create(hash_table_len,
            NULL, NULL, destroy_hash_node_cb);

    if(connection_hash_tbl == NULL)
    {
        log_msg(LOG_ERR,
            "[*] Fatal memory allocation error creating connection tracking hash table"
        );
        clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
    }

    latest_connection_hash_tbl = hash_table_create(hash_table_len,
            NULL, NULL, destroy_hash_node_cb);

    if(latest_connection_hash_tbl == NULL)
    {
        log_msg(LOG_ERR,
            "[*] Fatal memory allocation error creating 'latest' connection tracking hash table"
        );
        clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
    }

    return is_err;
}

void destroy_connection_tracker(fko_srv_options_t *opts)
{
//    store_last_conn_id(opts);

    if(connection_hash_tbl != NULL)
    {
        hash_table_destroy(connection_hash_tbl);
        connection_hash_tbl = NULL;
    }

    if(latest_connection_hash_tbl != NULL)
    {
        hash_table_destroy(latest_connection_hash_tbl);
        latest_connection_hash_tbl = NULL;
    }

    if(msg_conn_list != NULL)
    {
        destroy_connection_list(msg_conn_list);
        msg_conn_list = NULL;
    }
}

#ifdef DEBUG_CONNECTION_TRACKER
static int traverse_count_conns(hash_table_node_t *node, void *arg)
{
    int rv = FWKNOPD_SUCCESS;
    int *count = (int*)arg;
    connection_t temp_conn = NULL;

    log_msg(LOG_DEBUG, "traverse_count_conns() entered");

    if(node->data == NULL)
    {
        log_msg(LOG_ERR, "traverse_count_conns() node->data is NULL, shouldn't happen\n");
        hash_table_delete(latest_connection_hash_tbl, node->key);
        return rv;
    }

    temp_conn = (connection_t)(node->data);

    while(temp_conn)
    {
        (*count)++;
        temp_conn = temp_conn->next;
    }

    return rv;
}
#endif


int update_connections(fko_srv_options_t *opts)
{
    int res = FWKNOPD_SUCCESS;
    int pres_conn_count = 0;
    time_t now = 0;

    // did someone init the conn tracking tables
    if(connection_hash_tbl == NULL)
    {
        log_msg(LOG_ERR,
            "[*] Connection tracking was not initialized."
        );
        return res;
    }

#ifdef DEBUG_CONNECTION_TRACKER
    new_unknown_conn_count = 0;
    new_unknown_conn_count_closed = 0;
    new_unknown_conn_count_open = 0;
    new_unknown_conn_count_before_walk = 0;
    known_conn_cnt_before_update = 0;
    known_conn_cnt_before_update_closed = 0;
    known_conn_cnt_before_update_open = 0;
    known_conn_cnt_after_update = 0;
    known_conn_cnt_after_update_closed = 0;
    known_conn_cnt_after_update_open = 0;
    final_known_cnt = 0;
    known_conns_deleted_during_comp = 0;
    known_conns_deleted = 0;
#endif

    // first get list of current connections
    if( (res = check_conntrack(opts, &pres_conn_count)) != FWKNOPD_SUCCESS)
    {
        // pass errors up
        return res;
    }

    if(verbosity >= LOG_DEBUG)
    {
        log_msg(LOG_DEBUG, "After check_conntrack, dumping hash table "
                "of current (i.e. latest) connection items:");
        hash_table_traverse(latest_connection_hash_tbl, traverse_print_conn_items_cb, NULL);
        log_msg(LOG_DEBUG, "\n\n");
    }

    now = time(NULL);

#ifdef DEBUG_CONNECTION_TRACKER
    if( hash_table_traverse(connection_hash_tbl, traverse_count_conns, &known_conn_cnt_before_update)  != FWKNOPD_SUCCESS )
    {
        return FWKNOPD_ERROR_CONNTRACK;
    }
#endif

    // walk list of known connections
    if( hash_table_traverse(connection_hash_tbl, traverse_compare_latest_cb, &now)  != FWKNOPD_SUCCESS )
    {
        return FWKNOPD_ERROR_CONNTRACK;
    }

#ifdef DEBUG_CONNECTION_TRACKER
    if( hash_table_traverse(connection_hash_tbl, traverse_count_conns, &known_conn_cnt_after_update)  != FWKNOPD_SUCCESS )
    {
        return FWKNOPD_ERROR_CONNTRACK;
    }

    if( hash_table_traverse(latest_connection_hash_tbl, traverse_count_conns, &new_unknown_conn_count_before_walk)  != FWKNOPD_SUCCESS )
    {
        return FWKNOPD_ERROR_CONNTRACK;
    }
#endif

    // what's left in 'latest' conns are new, unknown conns
    // validate and possibly add to known list and to report for ctrl
    if( hash_table_traverse(latest_connection_hash_tbl, traverse_handle_new_conns_cb, opts)  != FWKNOPD_SUCCESS )
    {
        return FWKNOPD_ERROR_CONNTRACK;
    }

#ifdef DEBUG_CONNECTION_TRACKER
    if( hash_table_traverse(connection_hash_tbl, traverse_count_conns, &final_known_cnt)  != FWKNOPD_SUCCESS )
    {
        return FWKNOPD_ERROR_CONNTRACK;
    }

    log_msg(LOG_ALERT, "       Known conn count before update: %6d", known_conn_cnt_before_update);
    log_msg(LOG_ALERT, "  Known conn count before update OPEN: %6d", known_conn_cnt_before_update_open);
    log_msg(LOG_ALERT, "Known conn count before update CLOSED: %6d", known_conn_cnt_before_update_closed);
    log_msg(LOG_ALERT, "                  Known conns deleted: %6d", known_conns_deleted);
    log_msg(LOG_ALERT, "   Known conns deleted during compare: %6d", known_conns_deleted_during_comp);
    log_msg(LOG_ALERT, "        Known conn count after update: %6d", known_conn_cnt_after_update);
    log_msg(LOG_ALERT, "   Known conn count after update OPEN: %6d", known_conn_cnt_after_update_open);
    log_msg(LOG_ALERT, " Known conn count after update CLOSED: %6d", known_conn_cnt_after_update_closed);
    log_msg(LOG_ALERT, "   New unknown conn count before walk: %6d", new_unknown_conn_count_before_walk);
    log_msg(LOG_ALERT, "               New unknown conn count: %6d", new_unknown_conn_count);
    log_msg(LOG_ALERT, "          New unknown conn count OPEN: %6d", new_unknown_conn_count_open);
    log_msg(LOG_ALERT, "        New unknown conn count CLOSED: %6d", new_unknown_conn_count_closed);
    log_msg(LOG_ALERT, "                    Final known count: %6d", final_known_cnt);
    log_msg(LOG_ALERT, "\n\n");
#endif

    if(verbosity >= LOG_DEBUG)
    {
        log_msg(LOG_DEBUG, "Finished updating all connections");

        log_msg(LOG_DEBUG, "Dumping known connections hash table:");
        hash_table_traverse(connection_hash_tbl, traverse_print_conn_items_cb, NULL);

        log_msg(LOG_DEBUG, "\n\nDumping current connections hash table (should now be empty):");
        hash_table_traverse(latest_connection_hash_tbl, traverse_print_conn_items_cb, NULL);

        log_msg(LOG_DEBUG, "\n\nDumping message list for controller:");
        print_connection_list(msg_conn_list);

        log_msg(LOG_DEBUG, "\n\n");
    }

    return FWKNOPD_SUCCESS;
}

int validate_connections(fko_srv_options_t *opts)
{
    return hash_table_traverse(connection_hash_tbl, traverse_validate_connections_cb, opts);
}


static int make_json_from_conn_item(connection_t conn, json_object **jconn_r)
{
    json_object *jconn = json_object_new_object();

//    json_object_object_add(jconn, "connection_id", json_object_new_int64(conn->connection_id));
    json_object_object_add(jconn, "sdp_id", json_object_new_int(conn->sdp_id));
    json_object_object_add(jconn, "service_id", json_object_new_int(conn->service_id));
    json_object_object_add(jconn, "protocol", json_object_new_string(conn->protocol));
    json_object_object_add(jconn, "source_ip", json_object_new_string(conn->src_ip_str));
    json_object_object_add(jconn, "source_port", json_object_new_int(conn->src_port));
    json_object_object_add(jconn, "destination_ip", json_object_new_string(conn->dst_ip_str));
    json_object_object_add(jconn, "destination_port", json_object_new_int(conn->dst_port));
    json_object_object_add(jconn, "nat_destination_ip", json_object_new_string(conn->nat_dst_ip_str));
    json_object_object_add(jconn, "nat_destination_port", json_object_new_int(conn->nat_dst_port));
    json_object_object_add(jconn, "start_timestamp", json_object_new_int64(conn->start_time));
    json_object_object_add(jconn, "end_timestamp", json_object_new_int64(conn->end_time));

    *jconn_r = jconn;
    return FWKNOPD_SUCCESS;
}

static int send_connection_report(fko_srv_options_t *opts, connection_t msg_list)
{
    int rv = FWKNOPD_SUCCESS;
    json_object *jarray = NULL;
    json_object *jconn = NULL;
    connection_t this_conn = msg_list;
    int conn_count = 0;

#ifdef DEBUG_CONNECTION_TRACKER
    const char *json_string = NULL;
    float avg = 0;
    int msg_len = 0;
#endif

    if(msg_list == NULL)
        return rv;

    if(verbosity >= LOG_DEBUG)
    {
        log_msg(LOG_DEBUG, "\n\nDumping message list for controller:");
        print_connection_list(msg_list);
    }

    jarray = json_object_new_array();

    // send in blocks of MSG_CONN_LIST_COUNT_THRESHOLD connections max
    while(this_conn != NULL)
    {
        conn_count++;
        if( (rv = make_json_from_conn_item(this_conn, &jconn)) != FWKNOPD_SUCCESS)
        {
            json_object_put(jarray);
            return rv;
        }
        json_object_array_add(jarray, jconn);

        if(conn_count >= MSG_CONN_LIST_COUNT_THRESHOLD)
        {
            log_msg(LOG_WARNING, "Sending connection_update message (%d connections) to controller", conn_count);

#ifdef DEBUG_CONNECTION_TRACKER
            json_string = json_object_to_json_string(jarray);
            avg = msg_len/conn_count;
            log_msg(LOG_ALERT, "\nconnection update...");
            log_msg(LOG_ALERT, "                      connections: %10d", conn_count);
            log_msg(LOG_ALERT, "      data string length in bytes: %10d", msg_len);
            log_msg(LOG_ALERT, "average conn data length in bytes: %10.2f\n", avg);
#endif

            rv = sdp_ctrl_client_send_message(opts->ctrl_client, "connection_update", jarray);

            json_object_put(jarray);

            if(rv != SDP_SUCCESS)
                return rv;

            if(this_conn->next != NULL)
            {
                jarray = json_object_new_array();
                conn_count = 0;
            }
            else
                return rv;
        }
        this_conn = this_conn->next;
    }

    log_msg(LOG_WARNING, "Sending connection_update message (%d connections) to controller", conn_count);

#ifdef DEBUG_CONNECTION_TRACKER
    json_string = json_object_to_json_string(jarray);
    avg = msg_len/conn_count;
    log_msg(LOG_ALERT, "\nconnection update...");
    log_msg(LOG_ALERT, "                      connections: %10d", conn_count);
    log_msg(LOG_ALERT, "      data string length in bytes: %10d", msg_len);
    log_msg(LOG_ALERT, "average conn data length in bytes: %10.2f\n", avg);
#endif

    rv = sdp_ctrl_client_send_message(opts->ctrl_client, "connection_update", jarray);

    json_object_put(jarray);

    return rv;
}


int consider_reporting_connections(fko_srv_options_t *opts)
{
    int rv = FWKNOPD_SUCCESS;
    time_t now = time(NULL);
    int interval = strtol_wrapper(opts->config[CONF_CONN_REPORT_INTERVAL], 1,
            INT32_MAX, NO_EXIT_UPON_ERR, &rv);

    if(rv != FKO_SUCCESS)
    {
        log_msg(LOG_ERR, "consider_reporting_connections() ERROR retrieving "
                "reporting interval from server config.");
        return rv;
    }

    // if it's not time, just return success
    if(msg_conn_list_count < MSG_CONN_LIST_COUNT_THRESHOLD && now < next_ctrl_msg_due)
        return rv;

    // if nothing new to report, just return success
    if(msg_conn_list == NULL)
        return rv;

    // time to send

    if(verbosity >= LOG_DEBUG)
    {
        log_msg(LOG_DEBUG, "Time to send connection update");

        log_msg(LOG_DEBUG, "Dumping known connections hash table:");
        hash_table_traverse(connection_hash_tbl, traverse_print_conn_items_cb, NULL);

        log_msg(LOG_DEBUG, "\n\nDumping message list for controller:");
        print_connection_list(msg_conn_list);

        log_msg(LOG_DEBUG, "\n\n");
    }

    // send message
    if( (rv = send_connection_report(opts, msg_conn_list)) != FWKNOPD_SUCCESS)
    {
        if(rv == SDP_ERROR_MEMORY_ALLOCATION)
        {
            log_msg(LOG_ERR, "consider_reporting_connections() experienced a fatal memory error.");
            return rv;
        }
        else
        {
            log_msg(LOG_ERR, "consider_reporting_connections() failed to send a report. Dropping the message.");
        }
    }

    // free message list
    destroy_connection_list(msg_conn_list);
    msg_conn_list = NULL;
    msg_conn_list_count = 0;

    // update next_ctrl_msg_due
    next_ctrl_msg_due = now + interval;

    if(next_ctrl_msg_due < now)
    {
        log_msg(LOG_ERR, "consider_reporting_connections() variable next_ctrl_msg_due "
                "has overflowed, possibly due to a large report interval. Report "
                "interval is %d seconds.", interval);
        return FWKNOPD_ERROR_CONNTRACK;
    }

    return FWKNOPD_SUCCESS;
}



static int traverse_copy_open_conns_cb(hash_table_node_t *node, void *arg)
{
    int rv = FWKNOPD_SUCCESS;
    connection_t temp_conn = NULL;

    log_msg(LOG_DEBUG, "traverse_copy_open_conns_cb() entered");

    if(node->data == NULL)
    {
        log_msg(LOG_ERR, "traverse_copy_open_conns_cb() node->data is NULL, shouldn't happen\n");
        hash_table_delete(latest_connection_hash_tbl, node->key);
        return rv;
    }

    log_msg(LOG_DEBUG, "traverse_copy_open_conns_cb() node with open connections:");
    if(verbosity >= LOG_DEBUG)
    {
        print_connection_list(node->data);
    }

    if((rv = duplicate_connection_list((connection_t)(node->data), &temp_conn)) != FWKNOPD_SUCCESS)
    {
        return rv;
    }

    if( (rv = add_to_connection_list(&msg_conn_list, temp_conn)) != FWKNOPD_SUCCESS)
        destroy_connection_list(temp_conn);

    while(temp_conn != NULL)
    {
        msg_conn_list_count++;
        temp_conn = temp_conn->next;
    }

    if(msg_conn_list)
        log_msg(LOG_DEBUG, "traverse_copy_open_conns_cb() msg_conn_list is not null, which is good");
    else
        log_msg(LOG_DEBUG, "traverse_copy_open_conns_cb() msg_conn_list is null, which is bad");


    return rv;
}


/*
 *  This function serves a special purpose where the gateway has just
 *  reconnected to the controller and needs to report only currently known
 *  open connections. This will be called whenever the gateway reconnects
 *  to the controller, but will only send something if connection
 *  tracking was already initialized and has currently known open connections.
 */
int report_open_connections(fko_srv_options_t *opts)
{
    int rv = FWKNOPD_SUCCESS;

    // if the conn tracking table is not initialized
    // there are no known open connections, so do nothing
    if(connection_hash_tbl == NULL)
    {
        return rv;
    }

    // gather copies of all open connections into msg_list
    if( (rv = hash_table_traverse(connection_hash_tbl, traverse_copy_open_conns_cb, NULL))  != FWKNOPD_SUCCESS )
    {
        // free message list
        destroy_connection_list(msg_conn_list);
        msg_conn_list = NULL;
        msg_conn_list_count = 0;
        return rv;
    }

    if(msg_conn_list == NULL)
    {
        log_msg(LOG_DEBUG, "report_open_connections() found nothing to report.");
        return FWKNOPD_SUCCESS;
    }

    // send message
    rv = send_connection_report(opts, msg_conn_list);

    // free message list
    destroy_connection_list(msg_conn_list);
    msg_conn_list = NULL;
    msg_conn_list_count = 0;

    if(rv == SDP_ERROR_MEMORY_ALLOCATION)
    {
        log_msg(LOG_ERR, "report_open_connections() experienced a fatal memory error.");
        return rv;
    }
    else if(rv != FWKNOPD_SUCCESS)
    {
        log_msg(LOG_ERR, "report_open_connections() failed to send a report. Carrying on.");
        return FWKNOPD_SUCCESS;
    }
    else
    {
        log_msg(LOG_INFO, "report_open_connections() successfully sent report.");
    }

    return FWKNOPD_SUCCESS;
}

//#endif
