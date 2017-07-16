/*
 ******************************************************************************
 *
 * File:    access.c
 *
 * Purpose: Access.conf file processing for fwknop server.
 *
 *  Fwknop is developed primarily by the people listed in the file 'AUTHORS'.
 *  Copyright (C) 2009-2014 fwknop developers and contributors. For a full
 *  list of contributors, see the file 'CREDITS'.
 *
 *  License (GNU General Public License):
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version 2
 *  of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307
 *  USA
 *
 ******************************************************************************
*/
#include <sys/stat.h>

#if HAVE_SYS_SOCKET_H
  #include <sys/socket.h>
#endif

#include "fwknopd_common.h"
#include <arpa/inet.h>
#include "pwd.h"
#include "access.h"
#include "utils.h"
#include "log_msg.h"
#include "cmd_cycle.h"
#include "bstrlib.h"
#include <json-c/json.h>
#include "fwknopd_errors.h"
#include "sdp_ctrl_client.h"


#define FATAL_ERR -1

#ifndef SUCCESS
  #define SUCCESS    1
#endif

#ifdef HAVE_C_UNIT_TESTS
  #include "cunit_common.h"
  DECLARE_TEST_SUITE(access, "Access test suite");
#endif


static fko_srv_options_t *access_opts_g = NULL;
static int access_counter_g = 0;

// JSON message strings
const char *sdp_key_data_refresh        = "access_refresh";
const char *sdp_key_data_update         = "access_update";

/* Add an access string entry
*/
static void
add_acc_string(char **var, const char *val, FILE *file_ptr,
        fko_srv_options_t *opts)
{
    if(var == NULL)
    {
        log_msg(LOG_ERR, "[*] add_acc_string() called with NULL variable");
        if(file_ptr != NULL)
            fclose(file_ptr);
        clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
    }

    if(*var != NULL)
        free(*var);

    if((*var = strdup(val)) == NULL)
    {
        log_msg(LOG_ERR,
            "[*] Fatal memory allocation error adding access list entry: %s", *var
        );
        if(file_ptr != NULL)
            fclose(file_ptr);
        clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
    }
    return;
}

/* Add an access user entry
*/
static void
add_acc_user(char **user_var, uid_t *uid_var, struct passwd **upw,
        const char *val, const char *var_name, FILE *file_ptr,
        fko_srv_options_t *opts)
{
    struct passwd  *pw = NULL;

    add_acc_string(user_var, val, file_ptr, opts);

    errno = 0;
    *upw = pw = getpwnam(val);

    if(*upw == NULL || pw == NULL)
    {
        log_msg(LOG_ERR, "[*] Unable to determine UID for %s: %s.",
                var_name, errno ? strerror(errno) : "Not a user on this system");
        fclose(file_ptr);
        clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
    }

    *uid_var = pw->pw_uid;

    return;
}

/* Add an access group entry
*/
static void
add_acc_group(char **group_var, gid_t *gid_var,
        const char *val, const char *var_name, FILE *file_ptr,
        fko_srv_options_t *opts)
{
    struct passwd  *pw = NULL;

    add_acc_string(group_var, val, file_ptr, opts);

    errno = 0;
    pw = getpwnam(val);

    if(pw == NULL)
    {
        log_msg(LOG_ERR, "[*] Unable to determine GID for %s: %s.",
                var_name, errno ? strerror(errno) : "Not a group on this system");
        fclose(file_ptr);
        clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
    }

    *gid_var = pw->pw_gid;

    return;
}

/* Decode base64 encoded string into access entry
*/
static void
add_acc_b64_string(char **var, int *len, const char *val, FILE *file_ptr,
        fko_srv_options_t *opts)
{
    if((*var = strdup(val)) == NULL)
    {
        log_msg(LOG_ERR,
            "[*] Fatal memory allocation error adding access list entry: %s", *var
        );
        if(file_ptr != NULL)
            fclose(file_ptr);
        clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
    }
    memset(*var, 0x0, strlen(val));
    *len = fko_base64_decode(val, (unsigned char *) *var);

    if (*len < 0)
    {
        log_msg(LOG_ERR,
            "[*] base64 decoding returned error for: %s", *var
        );
        if(file_ptr != NULL)
            fclose(file_ptr);
        clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
    }
    return;
}

/* Add an access bool entry (unsigned char of 1 or 0)
*/
static unsigned char
add_acc_bool(unsigned char *var, const char *val)
{
    return(*var = (strncasecmp(val, "Y", 1) == 0) ? 1 : 0);
}

/* Add expiration time - convert date to epoch seconds
*/
static int
add_acc_expire_time(time_t *access_expire_time, const char *val)
{
    struct tm tm;

    memset(&tm, 0, sizeof(struct tm));

    if (sscanf(val, "%2d/%2d/%4d", &tm.tm_mon, &tm.tm_mday, &tm.tm_year) != 3)
    {

        log_msg(LOG_ERR,
            "[*] Fatal: invalid date value '%s' (need MM/DD/YYYY) for access stanza expiration time",
            val
        );
        return FWKNOPD_ERROR_BAD_STANZA_DATA;
    }

    if(tm.tm_mon > 0)
        tm.tm_mon -= 1;  /* 0-11 */

    /* number of years since 1900
    */
    if(tm.tm_year > 1900)
        tm.tm_year -= 1900;
    else
        if(tm.tm_year < 100)
            tm.tm_year += 100;

    *access_expire_time = mktime(&tm);

    return FWKNOPD_SUCCESS;
}

/* Add expiration time via epoch seconds defined in access.conf
*/
static int
add_acc_expire_time_epoch(time_t *access_expire_time, const char *val)
{
    char *endptr;
    unsigned long expire_time = 0;

    errno = 0;

    expire_time = (time_t) strtoul(val, &endptr, 10);

    if (errno == ERANGE || (errno != 0 && expire_time == 0))
    {
        log_msg(LOG_ERR,
            "Fatal: invalid epoch seconds value '%s' for access stanza expiration time",
            val
        );
        return FWKNOPD_ERROR_BAD_STANZA_DATA;
    }

    *access_expire_time = (time_t) expire_time;

    return FWKNOPD_SUCCESS;
}

#if defined(FIREWALL_FIREWALLD) || defined(FIREWALL_IPTABLES)
static int
add_acc_force_nat(acc_stanza_t *curr_acc, const char *val)
{
    char      ip_str[MAX_IPV4_STR_LEN] = {0};

    if (sscanf(val, "%15s %5u", ip_str, &curr_acc->force_nat_port) != 2)
    {
        log_msg(LOG_ERR,
            "[*] Fatal: invalid FORCE_NAT arg '%s', need <IP> <PORT>",
            val
        );
        return FWKNOPD_ERROR_BAD_STANZA_DATA;
    }

    if (curr_acc->force_nat_port > MAX_PORT)
    {
        log_msg(LOG_ERR,
            "[*] Fatal: invalid FORCE_NAT port '%d'", curr_acc->force_nat_port);
        return FWKNOPD_ERROR_BAD_STANZA_DATA;
    }

    if(! is_valid_ipv4_addr(ip_str))
    {
        log_msg(LOG_ERR,
            "[*] Fatal: invalid FORCE_NAT IP '%s'", ip_str);
        return FWKNOPD_ERROR_BAD_STANZA_DATA;
    }

    curr_acc->force_nat = 1;

    if(curr_acc->force_nat_ip != NULL)
        free(curr_acc->force_nat_ip );

    if((curr_acc->force_nat_ip = strndup(ip_str, MAX_IPV4_STR_LEN)) == NULL)
        return FKO_ERROR_MEMORY_ALLOCATION;

    return FWKNOPD_SUCCESS;
}

static int
add_acc_force_snat(acc_stanza_t *curr_acc, const char *val)
{
    char      ip_str[MAX_IPV4_STR_LEN] = {0};

    if (sscanf(val, "%15s", ip_str) != 1)
    {
        log_msg(LOG_ERR,
                "[*] Fatal: invalid FORCE_SNAT arg '%s', need <IP>", val);
        return FWKNOPD_ERROR_BAD_STANZA_DATA;
    }

    if(! is_valid_ipv4_addr(ip_str))
    {
        log_msg(LOG_ERR,
            "[*] Fatal: invalid FORCE_SNAT IP '%s'", ip_str);
        return FWKNOPD_ERROR_BAD_STANZA_DATA;
    }

    curr_acc->force_snat = 1;

    if(curr_acc->force_snat_ip != NULL)
        free(curr_acc->force_snat_ip );

    if((curr_acc->force_snat_ip = strndup(ip_str, MAX_IPV4_STR_LEN)) == NULL)
        return FKO_ERROR_MEMORY_ALLOCATION;

    return FWKNOPD_SUCCESS;
}

#endif

/* Take an IP or Subnet/Mask and convert it to mask for later
 * comparisons of incoming source IPs against this mask.
*/
static int
add_int_ent(acc_int_list_t **ilist, const char *ip)
{
    char                *ndx;
    char                ip_str[MAX_IPV4_STR_LEN] = {0};
    char                ip_mask_str[MAX_IPV4_STR_LEN] = {0};
    uint32_t            mask;
    int                 is_err, mask_len = 0, need_shift = 1;

    struct in_addr      in;
    struct in_addr      mask_in;

    acc_int_list_t      *last_sle, *new_sle, *tmp_sle;

    if((new_sle = calloc(1, sizeof(acc_int_list_t))) == NULL)
    {
        log_msg(LOG_ERR,
            "[*] Fatal memory allocation error adding stanza source_list entry"
        );
        exit(EXIT_FAILURE);
    }

    /* Convert the IP data into the appropriate IP + (optional) mask
    */
    if(strcasecmp(ip, "ANY") == 0)
    {
        new_sle->maddr = 0x0;
        new_sle->mask = 0x0;
    }
    else
    {
        /* See if we have a subnet component.  If so pull out the IP and
         * mask values, then create the final mask value.
        */
        if((ndx = strchr(ip, '/')) != NULL)
        {
            if(((ndx-ip)) >= MAX_IPV4_STR_LEN)
            {
                log_msg(LOG_ERR, "[*] Error parsing string to IP");
                free(new_sle);
                new_sle = NULL;
                return 0;
            }

            mask_len = strlen(ip) - (ndx-ip+1);

            if(mask_len > 2)
            {
                if(mask_len >= MIN_IPV4_STR_LEN && mask_len < MAX_IPV4_STR_LEN)
                {
                    /* IP formatted mask
                    */
                    strlcpy(ip_mask_str, (ip + (ndx-ip) + 1), mask_len+1);
                    if(inet_aton(ip_mask_str, &mask_in) == 0)
                    {
                        log_msg(LOG_ERR,
                            "[*] Fatal error parsing IP mask to int for: %s", ip_mask_str
                        );
                        free(new_sle);
                        new_sle = NULL;
                        return 0;
                    }
                    mask = ntohl(mask_in.s_addr);
                    need_shift = 0;
                }
                else
                {
                    log_msg(LOG_ERR, "[*] Invalid IP mask str '%s'.", ndx+1);
                    free(new_sle);
                    new_sle = NULL;
                    return 0;
                }
            }
            else
            {
                if(mask_len > 0)
                {
                    /* CIDR mask
                    */
                    mask = strtol_wrapper(ndx+1, 1, 32, NO_EXIT_UPON_ERR, &is_err);
                    if(is_err != FKO_SUCCESS)
                    {
                        log_msg(LOG_ERR, "[*] Invalid IP mask str '%s'.", ndx+1);
                        free(new_sle);
                        new_sle = NULL;
                        return 0;
                    }
                }
                else
                {
                    log_msg(LOG_ERR, "[*] Missing mask value.");
                    free(new_sle);
                    new_sle = NULL;
                    return 0;
                }
            }

            strlcpy(ip_str, ip, (ndx-ip)+1);
        }
        else
        {
            mask = 32;
            if(strnlen(ip, MAX_IPV4_STR_LEN+1) >= MAX_IPV4_STR_LEN)
            {
                log_msg(LOG_ERR, "[*] Error parsing string to IP");
                free(new_sle);
                new_sle = NULL;
                return 0;
            }
            strlcpy(ip_str, ip, sizeof(ip_str));
        }

        if(inet_aton(ip_str, &in) == 0)
        {
            log_msg(LOG_ERR,
                "[*] Fatal error parsing IP to int for: %s", ip_str
            );

            free(new_sle);
            new_sle = NULL;

            return 0;
        }

        /* Store our mask converted from CIDR to a 32-bit value.
        */
        if(mask == 32)
            new_sle->mask = 0xFFFFFFFF;
        else if(need_shift && (mask > 0 && mask < 32))
            new_sle->mask = (0xFFFFFFFF << (32 - mask));
        else
            new_sle->mask = mask;

        /* Store our masked address for comparisons with future incoming
         * packets.
        */
        new_sle->maddr = ntohl(in.s_addr) & new_sle->mask;
    }

    /* If this is not the first entry, we walk our pointer to the
     * end of the list.
    */
    if(*ilist == NULL)
    {
        *ilist = new_sle;
    }
    else
    {
        tmp_sle = *ilist;

        do {
            last_sle = tmp_sle;
        } while((tmp_sle = tmp_sle->next));

        last_sle->next = new_sle;
    }

    return 1;
}

/* Expand the access SOURCE string to a list of masks.
*/
static int
expand_acc_int_list(acc_int_list_t **ilist, char *ip)
{
    char           *ndx, *start;
    char            buf[ACCESS_BUF_LEN] = {0};
    int             res = 1;

    start = ip;

    for(ndx = start; *ndx; ndx++)
    {
        if(*ndx == ',')
        {
            /* Skip over any leading whitespace.
            */
            while(isspace(*start))
                start++;

            if(((ndx-start)+1) >= ACCESS_BUF_LEN)
                return 0;

            strlcpy(buf, start, (ndx-start)+1);

            res = add_int_ent(ilist, buf);
            if(res == 0)
                return res;

            start = ndx+1;
        }
    }

    /* Skip over any leading whitespace (once again for the last in the list).
    */
    while(isspace(*start))
        start++;

    if(((ndx-start)+1) >= ACCESS_BUF_LEN)
        return 0;

    strlcpy(buf, start, (ndx-start)+1);

    res = add_int_ent(ilist, buf);

    return res;
}

static int
parse_proto_and_port(char *pstr, int *proto, int *port)
{
    char    *ndx;
    char    proto_str[ACCESS_BUF_LEN] = {0};
    int     is_err;

    /* Parse the string into its components.
    */
    if((ndx = strchr(pstr, '/')) == NULL)
    {
        log_msg(LOG_ERR,
            "[*] Parse error on access port entry: %s", pstr);

        return(-1);
    }

    if(((ndx - pstr)+1) >= ACCESS_BUF_LEN)
    {
        log_msg(LOG_ERR,
            "[*] Parse error on access port entry: %s", pstr);
        return(-1);
    }

    strlcpy(proto_str, pstr, (ndx - pstr)+1);

    *port = strtol_wrapper(ndx+1, 0, MAX_PORT, NO_EXIT_UPON_ERR, &is_err);
    if(is_err != FKO_SUCCESS)
    {
        log_msg(LOG_ERR,
            "[*] Invalid port '%s' in access request, must be in [%d,%d]",
            pstr, 0, MAX_PORT);
        return(-1);
    }

    if(strcasecmp(proto_str, "tcp") == 0)
        *proto = PROTO_TCP;
    else if(strcasecmp(proto_str, "udp") == 0)
        *proto = PROTO_UDP;
    else
    {
        log_msg(LOG_ERR,
            "[*] Invalid protocol in access port entry: %s", pstr);
        return(-1);
    }

    return(0);
}

/* Take a proto/port string and convert it to appropriate integer values
 * for comparisons of incoming SPA requests.
*/
static int
add_port_list_ent(acc_port_list_t **plist, char *port_str)
{
    int                 proto_int, port;

    acc_port_list_t     *last_plist, *new_plist, *tmp_plist;

    /* Parse the string into its components and continue only if there
     * are no problems with the incoming string.
    */
    if(parse_proto_and_port(port_str, &proto_int, &port) != 0)
        return 0;

    if((new_plist = calloc(1, sizeof(acc_port_list_t))) == NULL)
    {
        log_msg(LOG_ERR,
            "[*] Fatal memory allocation error adding stanza port_list entry"
        );
        exit(EXIT_FAILURE);
    }

    /* If this is not the first entry, we walk our pointer to the
     * end of the list.
    */
    if(*plist == NULL)
    {
        *plist = new_plist;
    }
    else
    {
        tmp_plist = *plist;

        do {
            last_plist = tmp_plist;
        } while((tmp_plist = tmp_plist->next));

        last_plist->next = new_plist;
    }

    new_plist->proto = proto_int;
    new_plist->port  = port;

    return 1;
}

/* Add a string list entry to the given acc_string_list.
*/
static int
add_string_list_ent(acc_string_list_t **stlist, const char *str_str)
{
    acc_string_list_t   *last_stlist, *new_stlist, *tmp_stlist;

    if((new_stlist = calloc(1, sizeof(acc_string_list_t))) == NULL)
    {
        log_msg(LOG_ERR,
            "[*] Fatal memory allocation error creating string list entry"
        );
        return FATAL_ERR;
    }

    /* If this is not the first entry, we walk our pointer to the
     * end of the list.
    */
    if(*stlist == NULL)
    {
        *stlist = new_stlist;
    }
    else
    {
        tmp_stlist = *stlist;

        do {
            last_stlist = tmp_stlist;
        } while((tmp_stlist = tmp_stlist->next));

        last_stlist->next = new_stlist;
    }

    if(new_stlist->str != NULL)
        free(new_stlist->str);

    new_stlist->str = strdup(str_str);

    if(new_stlist->str == NULL)
    {
        log_msg(LOG_ERR,
            "[*] Fatal memory allocation error adding string list entry item"
        );
        return FATAL_ERR;
    }
    return SUCCESS;
}

/* Expand a proto/port access string to a list of access proto-port struct.
*/
int
expand_acc_port_list(acc_port_list_t **plist, char *plist_str)
{
    char           *ndx, *start;
    char            buf[ACCESS_BUF_LEN] = {0};

    start = plist_str;

    for(ndx = start; *ndx != '\0'; ndx++)
    {
        if(*ndx == ',')
        {
            /* Skip over any leading whitespace.
            */
            while(isspace(*start))
                start++;

            if(((ndx-start)+1) >= ACCESS_BUF_LEN)
                return 0;

            strlcpy(buf, start, (ndx-start)+1);

            if(add_port_list_ent(plist, buf) == 0)
                return 0;

            start = ndx+1;
        }
    }

    /* Skip over any leading whitespace (once again for the last in the list).
    */
    while(isspace(*start))
        start++;

    if(((ndx-start)+1) >= ACCESS_BUF_LEN)
        return 0;

    strlcpy(buf, start, (ndx-start)+1);

    if(add_port_list_ent(plist, buf) == 0)
        return 0;

    return 1;
}


static int
add_service_list_ent(acc_service_list_t **slist, char *buf)
{
    int is_err = 0;
    uint32_t id = 0;
    acc_service_list_t *new_entry = NULL;
    acc_service_list_t *last_entry = NULL;

    if((id = strtoul_wrapper(buf, 0, UINT32_MAX, NO_EXIT_UPON_ERR, &is_err)) == 0)
    {
        log_msg(LOG_ERR,
                "add_service_list_ent() did not find valid service id number in buf %s",
                buf);
        return 0;
    }

    if((new_entry = calloc(1, sizeof(acc_service_list_t))) == NULL)
    {
        log_msg(LOG_ERR,
            "[*] Fatal memory allocation error adding stanza port_list entry"
        );
        exit(EXIT_FAILURE);
    }

    new_entry->service_id = id;

    if(*slist == NULL)
    {
        *slist = new_entry;
    }
    else
    {
        last_entry = *slist;
        while(last_entry->next != NULL)
            last_entry = last_entry->next;

        last_entry->next = new_entry;
    }

    return 1;
}


/* Expand a service list string to a list of services.
*/
int
expand_acc_service_list(acc_service_list_t **slist_r, char *slist_str)
{
    char           *ndx, *start;
    char            buf[ACCESS_BUF_LEN] = {0};
    acc_service_list_t *slist = NULL;

    start = slist_str;
    *slist_r = NULL;

    for(ndx = start; *ndx != '\0'; ndx++)
    {
        if(*ndx == ',')
        {
            /* Skip over any leading whitespace.
            */
            while(isspace(*start))
                start++;

            if(((ndx-start)+1) >= ACCESS_BUF_LEN)
            {
            	free_acc_service_list(slist);
                return 0;
            }

            strlcpy(buf, start, (ndx-start)+1);

            if(add_service_list_ent(&slist, buf) == 0)
            {
            	free_acc_service_list(slist);
                return 0;
            }

            start = ndx+1;
        }
    }

    /* Skip over any leading whitespace (once again for the last in the list).
    */
    while(isspace(*start))
        start++;

    if(((ndx-start)+1) >= ACCESS_BUF_LEN)
    {
    	free_acc_service_list(slist);
        return 0;
    }

    strlcpy(buf, start, (ndx-start)+1);

    if(add_service_list_ent(&slist, buf) == 0)
    {
    	free_acc_service_list(slist);
        return 0;
    }

    *slist_r = slist;
    return 1;
}

/* Expand a comma-separated string into a simple acc_string_list.
*/
static int
expand_acc_string_list(acc_string_list_t **stlist, char *stlist_str)
{
    char           *ndx, *start;
    char            buf[MAX_LINE_LEN] = {0};

    start = stlist_str;

    for(ndx = start; *ndx; ndx++)
    {
        if(*ndx == ',')
        {
            /* Skip over any leading whitespace.
            */
            while(isspace(*start))
                start++;

            if(((ndx-start)+1) >= MAX_LINE_LEN)
                return FATAL_ERR;

            strlcpy(buf, start, (ndx-start)+1);
            if(add_string_list_ent(stlist, buf) != SUCCESS)
                return FATAL_ERR;

            start = ndx+1;
        }
    }

    /* Skip over any leading whitespace (once again for the last in the list).
    */
    while(isspace(*start))
        start++;

    if(((ndx-start)+1) >= MAX_LINE_LEN)
        return FATAL_ERR;

    strlcpy(buf, start, (ndx-start)+1);

    if(add_string_list_ent(stlist, buf) != SUCCESS)
        return FATAL_ERR;

    return SUCCESS;
}

/* Free the acc source_list
*/
static void
free_acc_int_list(acc_int_list_t *sle)
{
    acc_int_list_t    *last_sle;

    while(sle != NULL)
    {
        last_sle = sle;
        sle = last_sle->next;

        free(last_sle);
    }
}

/* Free a service_list
*/
void
free_acc_service_list(acc_service_list_t *sle)
{
    acc_service_list_t    *last_sle;

    while(sle != NULL)
    {
        last_sle = sle;
        sle = last_sle->next;

        free(last_sle);
    }
}

/* Free a port_list
*/
void
free_acc_port_list(acc_port_list_t *ple)
{
    acc_port_list_t    *last_ple;

    while(ple != NULL)
    {
        last_ple = ple;
        ple = last_ple->next;

        free(last_ple);
    }
}

/* Free a string_list
*/
static void
free_acc_string_list(acc_string_list_t *stl)
{
    acc_string_list_t    *last_stl;

    while(stl != NULL)
    {
        last_stl = stl;
        stl = last_stl->next;

        free(last_stl->str);
        free(last_stl);
    }
}

static void
zero_buf_wrapper(char *buf, int len)
{

    if(zero_buf(buf, len) != FKO_SUCCESS)
        log_msg(LOG_ERR,
                "[*] Could not zero out sensitive data buffer.");

    return;
}

/* Free any allocated content of an access stanza.
 *
 * NOTE: If a new access.conf parameter is created, and it is a string
 *       value, it also needs to be added to the list of items to check
 *       and free below.
*/
static void
free_acc_stanza_data(acc_stanza_t *acc)
{

    if(acc->source != NULL)
    {
        free(acc->source);
        free_acc_int_list(acc->source_list);
    }

    if(acc->destination != NULL)
    {
        free(acc->destination);
        free_acc_int_list(acc->destination_list);
    }

    if(acc->service_list_str != NULL)
    {
    	free(acc->service_list_str);
    }

    if(acc->service_list != NULL)
    {
        free_acc_service_list(acc->service_list);
    }

    if(acc->open_ports != NULL)
    {
        free(acc->open_ports);
        free_acc_port_list(acc->oport_list);
    }

    if(acc->restrict_ports != NULL)
    {
        free(acc->restrict_ports);
        free_acc_port_list(acc->rport_list);
    }

    if(acc->force_nat_ip != NULL)
        free(acc->force_nat_ip);

    if(acc->force_snat_ip != NULL)
        free(acc->force_snat_ip);

    if(acc->key != NULL)
    {
        zero_buf_wrapper(acc->key, acc->key_len);
        free(acc->key);
    }

    if(acc->key_base64 != NULL)
    {
        zero_buf_wrapper(acc->key_base64, strlen(acc->key_base64));
        free(acc->key_base64);
    }

    if(acc->hmac_key != NULL)
    {
        zero_buf_wrapper(acc->hmac_key, acc->hmac_key_len);
        free(acc->hmac_key);
    }

    if(acc->hmac_key_base64 != NULL)
    {
        zero_buf_wrapper(acc->hmac_key_base64, strlen(acc->hmac_key_base64));
        free(acc->hmac_key_base64);
    }

    if(acc->cmd_sudo_exec_user != NULL)
        free(acc->cmd_sudo_exec_user);

    if(acc->cmd_sudo_exec_group != NULL)
        free(acc->cmd_sudo_exec_group);

    if(acc->cmd_exec_user != NULL)
        free(acc->cmd_exec_user);

    if(acc->cmd_exec_group != NULL)
        free(acc->cmd_exec_group);

    if(acc->require_username != NULL)
        free(acc->require_username);

    if(acc->cmd_cycle_open != NULL)
        free(acc->cmd_cycle_open);

    if(acc->cmd_cycle_close != NULL)
        free(acc->cmd_cycle_close);

    if(acc->gpg_home_dir != NULL)
        free(acc->gpg_home_dir);

    if(acc->gpg_exe != NULL)
        free(acc->gpg_exe);

    if(acc->gpg_decrypt_id != NULL)
        free(acc->gpg_decrypt_id);

    if(acc->gpg_decrypt_pw != NULL)
        free(acc->gpg_decrypt_pw);

    if(acc->gpg_remote_id != NULL)
    {
        free(acc->gpg_remote_id);
        free_acc_string_list(acc->gpg_remote_id_list);
    }
    if(acc->gpg_remote_fpr != NULL)
    {
        free(acc->gpg_remote_fpr);
        free_acc_string_list(acc->gpg_remote_fpr_list);
    }
    return;
}


/* Expand one access entry that may be multi-value.
*/
static int
expand_one_acc_ent_list(acc_stanza_t *acc)
{
    /* Expand the source string to 32-bit integer IP + masks for each entry.
    */
    if(expand_acc_int_list(&(acc->source_list), acc->source) != SUCCESS)
    {
        log_msg(LOG_ERR, "[*] Fatal invalid SOURCE in access stanza");
        return 0;
    }

    if(acc->destination != NULL && strlen(acc->destination))
    {
        if(expand_acc_int_list(&(acc->destination_list), acc->destination) != SUCCESS)
        {
            log_msg(LOG_ERR, "[*] Fatal invalid DESTINATION in access stanza");
            return 0;
        }
    }

    if(acc->service_list_str != NULL && strlen(acc->service_list_str))
    {
        if(expand_acc_service_list(&(acc->service_list), acc->service_list_str) == 0)
        {
            log_msg(LOG_ERR, "[*] Fatal invalid SERVICE_LIST in access stanza");
            return 0;
        }
    }

    /* Now expand the open_ports string.
    */
    if(acc->open_ports != NULL && strlen(acc->open_ports))
    {
        if(expand_acc_port_list(&(acc->oport_list), acc->open_ports) != SUCCESS)
        {
            log_msg(LOG_ERR, "[*] Fatal invalid OPEN_PORTS in access stanza");
            return 0;
        }
    }

    if(acc->restrict_ports != NULL && strlen(acc->restrict_ports))
    {
        if(expand_acc_port_list(&(acc->rport_list), acc->restrict_ports) != SUCCESS)
        {
            log_msg(LOG_ERR, "[*] Fatal invalid RESTRICT_PORTS in access stanza");
            return 0;
        }
    }

    /* Expand the GPG_REMOTE_ID string.
    */
    if(acc->gpg_remote_id != NULL && strlen(acc->gpg_remote_id))
    {
        if(expand_acc_string_list(&(acc->gpg_remote_id_list),
                    acc->gpg_remote_id) != SUCCESS)
        {
            log_msg(LOG_ERR, "[*] Fatal invalid GPG_REMOTE_ID list in access stanza");
            return 0;
        }
    }

    /* Expand the GPG_FINGERPRINT_ID string.
    */
    if(acc->gpg_remote_fpr != NULL && strlen(acc->gpg_remote_fpr))
    {
        if(expand_acc_string_list(&(acc->gpg_remote_fpr_list),
                    acc->gpg_remote_fpr) != SUCCESS)
        {
            log_msg(LOG_ERR, "[*] Fatal invalid GPG_FINGERPRINT_ID list in access stanza");
            return 0;
        }
    }

    return SUCCESS;
}


static int
traverse_expand_hash_cb(hash_table_node_t *node, void *arg)
{
    int res = SUCCESS;
    acc_stanza_t *acc = (acc_stanza_t *)(node->data);
    res = expand_one_acc_ent_list(acc);
    if(res == SUCCESS)
        return 0;
    return 1;
}


/* Expand any access entries that may be multi-value.
*/
static void
expand_acc_ent_lists(fko_srv_options_t *opts)
{
    if(strncasecmp(opts->config[CONF_DISABLE_SDP_MODE], "Y", 1) == 0)
    {
        acc_stanza_t   *acc = opts->acc_stanzas;

        /* We need to do this for each stanza.
        */
        while(acc)
        {
            if(expand_one_acc_ent_list(acc) != SUCCESS)
                clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
            acc = acc->next;
        }
    }
    else
    {
        // hash_table_traverse returns 0 for success, unlike the functions in this file
        if( hash_table_traverse(opts->acc_stanza_hash_tbl, traverse_expand_hash_cb, NULL)    != 0 )
            clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
    }

    return;
}



void
free_acc_stanzas(fko_srv_options_t *opts)
{
    acc_stanza_t    *acc, *last_acc;

    /* Free any resources first (in case of reconfig). Assume non-NULL
     * entry needs to be freed.
    */
    acc = opts->acc_stanzas;

    while(acc != NULL)
    {
        last_acc = acc;
        acc = last_acc->next;

        free_acc_stanza_data(last_acc);
        free(last_acc);
    }

    return;
}

static void
destroy_hash_node_cb(hash_table_node_t *node)
{
  if(node->key != NULL) bdestroy((bstring)(node->key));
  if(node->data != NULL)
  {
      free_acc_stanza_data((acc_stanza_t*)(node->data));
      free(node->data);
  }
}

static int
traverse_dump_hash_cb(hash_table_node_t *node, void *dest)
{
    acc_stanza_t *acc = (acc_stanza_t *)(node->data);

    fprintf((FILE*)dest,
        "SDP_ID:  %"PRIu32"\n"
        "==============================================================\n"
        "                     SOURCE:  %s\n"
        "                DESTINATION:  %s\n"
        "               SERVICE_LIST:  %s\n"
        "                 OPEN_PORTS:  %s\n"
        "             RESTRICT_PORTS:  %s\n"
        "                        KEY:  %s\n"
        "                 KEY_BASE64:  %s\n"
        "                    KEY_LEN:  %d\n"
        "                   HMAC_KEY:  %s\n"
        "            HMAC_KEY_BASE64:  %s\n"
        "               HMAC_KEY_LEN:  %d\n"
        "           HMAC_DIGEST_TYPE:  %d\n"
        "          FW_ACCESS_TIMEOUT:  %i\n"
        "            ENABLE_CMD_EXEC:  %s\n"
        "       ENABLE_CMD_SUDO_EXEC:  %s\n"
        "         CMD_SUDO_EXEC_USER:  %s\n"
        "        CMD_SUDO_EXEC_GROUP:  %s\n"
        "              CMD_EXEC_USER:  %s\n"
        "             CMD_EXEC_GROUP:  %s\n"
        "             CMD_CYCLE_OPEN:  %s\n"
        "            CMD_CYCLE_CLOSE:  %s\n"
        "            CMD_CYCLE_TIMER:  %i\n"
        "           REQUIRE_USERNAME:  %s\n"
        "     REQUIRE_SOURCE_ADDRESS:  %s\n"
        "             FORCE_NAT (ip):  %s\n"
        "          FORCE_NAT (proto):  %s\n"
        "           FORCE_NAT (port):  %d\n"
        "            FORCE_SNAT (ip):  %s\n"
        "           FORCE_MASQUERADE:  %s\n"
        "               DISABLE_DNAT:  %s\n"
        "                FORWARD_ALL:  %s\n"
        "              ACCESS_EXPIRE:  %s"  /* asctime() adds a newline */
        "               GPG_HOME_DIR:  %s\n"
        "                    GPG_EXE:  %s\n"
        "             GPG_DECRYPT_ID:  %s\n"
        "             GPG_DECRYPT_PW:  %s\n"
        "            GPG_REQUIRE_SIG:  %s\n"
        "GPG_IGNORE_SIG_VERIFY_ERROR:  %s\n"
        "              GPG_REMOTE_ID:  %s\n"
        "         GPG_FINGERPRINT_ID:  %s\n",
        acc->sdp_id,
        acc->source,
        (acc->destination == NULL) ? "<not set>" : acc->destination,
        (acc->service_list_str == NULL) ? "<not set>" : acc->service_list_str,
        (acc->open_ports == NULL) ? "<not set>" : acc->open_ports,
        (acc->restrict_ports == NULL) ? "<not set>" : acc->restrict_ports,
        (acc->key == NULL) ? "<not set>" : "<HIDDEN>",
        (acc->key_base64 == NULL) ? "<not set>" : acc->key_base64, //"<HIDDEN>",
        acc->key_len ? acc->key_len : 0,
        (acc->hmac_key == NULL) ? "<not set>" : "<HIDDEN>",
        (acc->hmac_key_base64 == NULL) ? "<not set>" : acc->hmac_key_base64, //"<HIDDEN>",
        acc->hmac_key_len ? acc->hmac_key_len : 0,
        acc->hmac_type,
        acc->fw_access_timeout,
        acc->enable_cmd_exec ? "Yes" : "No",
        acc->enable_cmd_sudo_exec ? "Yes" : "No",
        (acc->cmd_sudo_exec_user == NULL) ? "<not set>" : acc->cmd_sudo_exec_user,
        (acc->cmd_sudo_exec_group == NULL) ? "<not set>" : acc->cmd_sudo_exec_group,
        (acc->cmd_exec_user == NULL) ? "<not set>" : acc->cmd_exec_user,
        (acc->cmd_exec_group == NULL) ? "<not set>" : acc->cmd_exec_group,
        (acc->cmd_cycle_open == NULL) ? "<not set>" : acc->cmd_cycle_open,
        (acc->cmd_cycle_close == NULL) ? "<not set>" : acc->cmd_cycle_close,
        acc->cmd_cycle_timer,
        (acc->require_username == NULL) ? "<not set>" : acc->require_username,
        acc->require_source_address ? "Yes" : "No",
        acc->force_nat ? acc->force_nat_ip : "<not set>",
        acc->force_nat && acc->force_nat_proto != NULL ? acc->force_nat_proto : "<not set>",
        acc->force_nat ? acc->force_nat_port : 0,
        acc->force_snat ? acc->force_snat_ip : "<not set>",
        acc->force_masquerade ? "Yes" : "No",
        acc->disable_dnat ? "Yes" : "No",
        acc->forward_all ? "Yes" : "No",
        (acc->access_expire_time > 0) ? asctime(localtime(&acc->access_expire_time)) : "<not set>\n",
        (acc->gpg_home_dir == NULL) ? "<not set>" : acc->gpg_home_dir,
        (acc->gpg_exe == NULL) ? "<not set>" : acc->gpg_exe,
        (acc->gpg_decrypt_id == NULL) ? "<not set>" : acc->gpg_decrypt_id,
        (acc->gpg_decrypt_pw == NULL) ? "<not set>" : "<see the access.conf file>",
        acc->gpg_require_sig ? "Yes" : "No",
        acc->gpg_ignore_sig_error  ? "Yes" : "No",
        (acc->gpg_remote_id == NULL) ? "<not set>" : acc->gpg_remote_id,
        (acc->gpg_remote_fpr == NULL) ? "<not set>" : acc->gpg_remote_fpr
    );

    fprintf((FILE*)dest, "\n");

    return 0;
}


/* Wrapper for free_acc_stanzas(), we may put additional initialization
 * code here.
*/
static void
acc_stanza_init(fko_srv_options_t *opts)
{
    /* Free any resources first (in case of reconfig). Assume non-NULL
     * entry needs to be freed.
    */
    free_acc_stanzas(opts);

    return;
}

/* Add a new stanza bay allocating the required memory at the required
 * location, yada-yada-yada.
*/
static acc_stanza_t*
acc_stanza_add(fko_srv_options_t *opts, char *val)
{
    acc_stanza_t    *acc     = opts->acc_stanzas;
    acc_stanza_t    *new_acc = calloc(1, sizeof(acc_stanza_t));
    acc_stanza_t    *last_acc;
    bstring          key     = NULL;
    int              hash_table_len = 0;
    int              is_err = 0;

    if(new_acc == NULL)
    {
        log_msg(LOG_ERR,
            "[*] Fatal memory allocation error adding access stanza"
        );
        clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
    }

    if(strncasecmp(opts->config[CONF_DISABLE_SDP_MODE], "Y", 1) == 0)
    {
        /* If this is not the first acc entry, we walk our acc pointer to the
         * end of the existing list.
        */
        if(acc == NULL)
        {
            opts->acc_stanzas = new_acc;
        }
        else
        {
            do {
                last_acc = acc;
            } while((acc = acc->next));

            last_acc->next = new_acc;
        }
    }
    else
    {
        if(opts->acc_stanza_hash_tbl == NULL)
        {
            //need to initialize hash table
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

            opts->acc_stanza_hash_tbl = hash_table_create(hash_table_len,
                    NULL, NULL, destroy_hash_node_cb);
            if(opts->acc_stanza_hash_tbl == NULL)
            {
                log_msg(LOG_ERR,
                    "[*] Fatal memory allocation error creating access stanza hash table"
                );
                free_acc_stanza_data(new_acc);
                free(new_acc);
                clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
            }
        }

        if( val == NULL || (strnlen(val, SDP_MAX_CLIENT_ID_STR_LEN) < 1))
        {
            log_msg(LOG_ERR,
                "[*] Fatal error - SDP_ID string invalid"
            );
            free_acc_stanza_data(new_acc);
            free(new_acc);
            clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
        }

        key = bfromcstr(val);

        if( hash_table_set(opts->acc_stanza_hash_tbl, key, new_acc) != FKO_SUCCESS )
        {
            log_msg(LOG_ERR,
                "[*] Fatal error creating access stanza hash table node"
            );
            bdestroy(key);
            free_acc_stanza_data(new_acc);
            free(new_acc);
            clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
        }
    }

    return(new_acc);
}

static void
set_one_acc_defaults(acc_stanza_t *acc)
{
    access_counter_g++;

    /* set default fw_access_timeout if necessary
    */
    if(acc->fw_access_timeout < 1)
        acc->fw_access_timeout = DEF_FW_ACCESS_TIMEOUT;

    /* set default gpg keyring path if necessary
    */
    if(acc->gpg_decrypt_pw != NULL)
    {
        if(acc->gpg_home_dir == NULL)
            add_acc_string(&(acc->gpg_home_dir),
                    access_opts_g->config[CONF_GPG_HOME_DIR], NULL, access_opts_g);

        if(! acc->gpg_require_sig)
        {
            if (acc->gpg_disable_sig)
            {
                log_msg(LOG_INFO,
                    "Warning: GPG_REQUIRE_SIG should really be enabled for stanza source: '%s' (#%d)",
                    acc->source, access_counter_g
                );
            }
            else
            {
                /* Make this the default unless explicitly disabled
                */
                acc->gpg_require_sig = 1;
            }
        }
        else
        {
            if (acc->gpg_disable_sig)
            {
                log_msg(LOG_INFO,
                    "Warning: GPG_REQUIRE_SIG and GPG_DISABLE_SIG are both set, will check sigs (stanza source: '%s' #%d)",
                    acc->source, access_counter_g
                );
            }
        }

        /* If signature checking is enabled, make sure we either have sig ID's or
         * fingerprint ID's to check
        */
        if(! acc->gpg_disable_sig
                && (acc->gpg_remote_id == NULL && acc->gpg_remote_fpr == NULL))
        {
            log_msg(LOG_INFO,
                "Warning: Must have either sig ID's or fingerprints to check via GPG_REMOTE_ID or GPG_FINGERPRINT_ID (stanza source: '%s' #%d)",
                acc->source, access_counter_g
            );
            clean_exit(access_opts_g, NO_FW_CLEANUP, EXIT_FAILURE);
        }
    }

    if(acc->encryption_mode == FKO_ENC_MODE_UNKNOWN)
        acc->encryption_mode = FKO_DEFAULT_ENC_MODE;

    /* if we're using an HMAC key and the HMAC digest type was not
     * set for HMAC_DIGEST_TYPE, then assume it's SHA256
    */

    if(acc->hmac_type == FKO_HMAC_UNKNOWN
            && acc->hmac_key_len > 0 && acc->hmac_key != NULL)
    {
        acc->hmac_type = FKO_DEFAULT_HMAC_MODE;
    }

    return;
}

static int
traverse_set_acc_defaults_cb(hash_table_node_t *node, void *arg)
{
    acc_stanza_t *acc = (acc_stanza_t *)(node->data);
    if(acc)
        set_one_acc_defaults(acc);
    return 0;
}


/* Scan the access options for entries that have not been set, but need
 * a default value.
*/
static void
set_acc_defaults(fko_srv_options_t *opts)
{
    acc_stanza_t    *acc = opts->acc_stanzas;
    access_counter_g = 0;
    access_opts_g = opts;

    if(strncasecmp(opts->config[CONF_DISABLE_SDP_MODE], "Y", 1) == 0)
    {
        while(acc)
        {
            set_one_acc_defaults(acc);
            acc = acc->next;
        }
    }
    else
    {
        hash_table_traverse(opts->acc_stanza_hash_tbl, traverse_set_acc_defaults_cb, NULL);
    }

    access_opts_g = NULL;
    return;
}

/* Perform some sanity checks on an acc stanza data.
*/
static int
acc_data_is_valid(fko_srv_options_t *opts,
        struct passwd *user_pw, struct passwd *sudo_user_pw,
        acc_stanza_t * const acc)
{
    if(acc == NULL)
    {
        log_msg(LOG_ERR,
            "[*] acc_data_is_valid() called with NULL acc stanza");
        return(0);
    }

    if(((acc->key == NULL || acc->key_len == 0)
      && ((acc->gpg_decrypt_pw == NULL || !strlen(acc->gpg_decrypt_pw))
          && acc->gpg_allow_no_pw == 0))
      || (acc->use_rijndael == 0 && acc->use_gpg == 0 && acc->gpg_allow_no_pw == 0))
    {
        log_msg(LOG_ERR,
            "[*] No keys found for access stanza source: '%s'", acc->source
        );
        return(0);
    }

    if(acc->use_rijndael && acc->key != NULL)
    {
        if((acc->encryption_mode == FKO_ENC_MODE_CBC_LEGACY_IV)
                && (acc->key_len > 16))
        {
            log_msg(LOG_INFO,
                "Warning: truncating encryption key in legacy mode to 16 bytes for access stanza source: '%s'",
                acc->source
            );
            acc->key_len = 16;
        }
    }

    if((acc->hmac_key_len) != 0 && (acc->hmac_key != NULL))
    {
        if((acc->key != NULL) && (acc->key_len != 0)
                && (acc->key_len == acc->hmac_key_len))
        {
            if(memcmp(acc->key, acc->hmac_key, acc->hmac_key_len) == 0)
            {
                log_msg(LOG_ERR,
                    "[*] The encryption passphrase and HMAC key should not be identical for access stanza source: '%s'",
                    acc->source
                );
                return(0);
            }
        }
        else if((acc->gpg_allow_no_pw == 0)
                && acc->gpg_decrypt_pw != NULL
                && (strlen(acc->gpg_decrypt_pw) == acc->hmac_key_len))
        {
            if(memcmp(acc->gpg_decrypt_pw, acc->hmac_key, acc->hmac_key_len) == 0)
            {
                log_msg(LOG_ERR,
                    "[*] The encryption passphrase and HMAC key should not be identical for access stanza source: '%s'",
                    acc->source
                );
                return(0);
            }
        }
    }

#if defined(FIREWALL_FIREWALLD) || defined(FIREWALL_IPTABLES)
    if((acc->force_snat == 1 || acc->force_masquerade == 1)
            && acc->force_nat == 0)
    {
        if(acc->forward_all == 1)
        {
            if(add_acc_force_nat(acc, "0.0.0.0 0") != FWKNOPD_SUCCESS)
                return(0);
        }
        else
        {
            log_msg(LOG_ERR,
                    "[*] FORCE_SNAT/FORCE_MASQUERADE requires either FORCE_NAT or FORWARD_ALL: '%s'",
                    acc->source
            );
            return(0);
        }
    }
#endif

    if(acc->require_source_address == 0)
    {
        log_msg(LOG_INFO,
            "Warning: REQUIRE_SOURCE_ADDRESS not enabled for access stanza source: '%s'",
            acc->source
        );
    }

    if(user_pw != NULL && acc->cmd_exec_uid != 0 && acc->cmd_exec_gid == 0)
    {
        log_msg(LOG_INFO,
            "Setting gid to group associated with CMD_EXEC_USER '%s' for setgid() execution in stanza source: '%s'",
            acc->cmd_exec_user,
            acc->source
        );
        acc->cmd_exec_gid = user_pw->pw_gid;
    }

    if(sudo_user_pw != NULL
            && acc->cmd_sudo_exec_uid != 0 && acc->cmd_sudo_exec_gid == 0)
    {
        log_msg(LOG_INFO,
            "Setting gid to group associated with CMD_SUDO_EXEC_USER '%s' in stanza source: '%s'",
            acc->cmd_sudo_exec_user,
            acc->source
        );
        acc->cmd_sudo_exec_gid = sudo_user_pw->pw_gid;
    }

    if(acc->cmd_cycle_open != NULL)
    {
        if(acc->cmd_cycle_close == NULL)
        {
            log_msg(LOG_ERR,
                "[*] Cannot set CMD_CYCLE_OPEN without also setting CMD_CYCLE_CLOSE: '%s'",
                acc->source
            );
            return(0);
        }

        /* Allow the string "NONE" to short-circuit close command execution.
        */
        if(strncmp(acc->cmd_cycle_close, "NONE", 4) == 0)
            acc->cmd_cycle_do_close = 0;

        if(acc->cmd_cycle_timer == 0 && acc->cmd_cycle_do_close)
        {
            log_msg(LOG_ERR,
                "[*] Must set the CMD_CYCLE_TIMER for command cycle functionality: '%s'",
                acc->source
            );
            return(0);
        }
        if(strlen(acc->cmd_cycle_open) >= CMD_CYCLE_BUFSIZE)
        {
            log_msg(LOG_ERR,
                "[*] CMD_CYCLE_OPEN command is too long: '%s'",
                acc->source
            );
            return(0);
        }
    }

    if(acc->cmd_cycle_close != NULL)
    {
        if(acc->cmd_cycle_open == NULL)
        {
            log_msg(LOG_ERR,
                "[*] Cannot set CMD_CYCLE_CLOSE without also setting CMD_CYCLE_OPEN: '%s'",
                acc->source
            );
            return(0);
        }
        if(strlen(acc->cmd_cycle_close) >= CMD_CYCLE_BUFSIZE)
        {
            log_msg(LOG_ERR,
                "[*] CMD_CYCLE_CLOSE command is too long: '%s'",
                acc->source
            );
            return(0);
        }
    }

    /* For any non-command access stanza, we enable global firewall handling
    */
    if(!acc->enable_cmd_exec && !acc->enable_cmd_sudo_exec &&
            acc->cmd_cycle_open == NULL)
        opts->enable_fw = 1;

    return(1);
}


/* Take a json doc and make an acc stanza data struct from it
 *
 */
static int
make_acc_stanza_from_json(fko_srv_options_t *opts, json_object *jdata, acc_stanza_t **r_stanza)
{
    int rv = FWKNOPD_SUCCESS;
    char *tmp;
    struct passwd  *user_pw = NULL;
    struct passwd  *sudo_user_pw = NULL;
    struct passwd  *tmp_pw = NULL;
    char *service_list = NULL;
    acc_stanza_t *stanza = calloc(1, sizeof(acc_stanza_t));

    if((rv = sdp_get_json_int_field("sdp_id", jdata, (int*)&(stanza->sdp_id))) != SDP_SUCCESS)
    {
        log_msg(LOG_ERR, "Did not find SDP Client ID in access stanza, invalid stanza entry");
        goto cleanup;
    }

    if(sdp_get_json_string_field("source", jdata, &(stanza->source)) != SDP_SUCCESS)
    {
        // log_msg(LOG_WARNING, "Did not find source in access stanza, setting to ANY");
        if((stanza->source = strndup("ANY", 4)) == NULL)
        {
            rv = FKO_ERROR_MEMORY_ALLOCATION;
            goto cleanup;
        }
    }

    if( sdp_get_json_string_field("service_list", jdata, &service_list) == SDP_SUCCESS)
    {
        // save the string, mainly just for printing
        stanza->service_list_str = service_list;

        //if(expand_acc_service_list(&(stanza->service_list), service_list) == 0)
        //{
        //    log_msg(LOG_ERR, "Failed to parse service list in access stanza, invalid stanza entry");
        //    rv = FWKNOPD_ERROR_BAD_STANZA_DATA;
        //    goto cleanup;
        //}
    }

    sdp_get_json_string_field("destination", jdata, &(stanza->destination));
    sdp_get_json_string_field("open_ports", jdata, &(stanza->open_ports));
    sdp_get_json_string_field("restrict_ports", jdata, &(stanza->restrict_ports));

    if(sdp_get_json_string_field("spa_encryption_key", jdata, &(stanza->key)) == SDP_SUCCESS)
    {
        if((stanza->key_len = strnlen(stanza->key, MAX_KEY_LEN + 1)) > MAX_KEY_LEN)
        {
            log_msg(LOG_ERR, "Key length exceeds max length of %d bytes", MAX_KEY_LEN);
            rv = FWKNOPD_ERROR_BAD_STANZA_DATA;
            goto cleanup;
        }

        add_acc_bool(&(stanza->use_rijndael), "Y");
    }

    if(sdp_get_json_string_field("spa_encryption_key_base64", jdata, &(stanza->key_base64)) == SDP_SUCCESS)
    {
        if(strnlen(stanza->key_base64, MAX_B64_KEY_LEN + 1) > MAX_B64_KEY_LEN)
        {
            log_msg(LOG_ERR, "B64 key length exceeds max length %d bytes", MAX_B64_KEY_LEN);
            rv = FWKNOPD_ERROR_BAD_STANZA_DATA;
            goto cleanup;
        }
        // make space for decoded version of the key
        // decode function does not watch for buffer overwrite, so oversize the buffer
        if((stanza->key = calloc(1, MAX_B64_KEY_LEN)) == NULL)
        {
            rv = SDP_ERROR_MEMORY_ALLOCATION;
            goto cleanup;
        }
        // perform decode and get key len
        if((stanza->key_len = fko_base64_decode(stanza->key_base64, (unsigned char*)stanza->key)) < 0)
        {
            log_msg(LOG_ERR, "Failed to decode base64 key");
            rv = FWKNOPD_ERROR_BAD_STANZA_DATA;
            goto cleanup;
        }

        if(stanza->key_len > MAX_KEY_LEN)
        {
            log_msg(LOG_ERR, "Decoded key length is %d bytes, exceeds max length %d bytes", stanza->key_len, MAX_KEY_LEN);
            rv = FWKNOPD_ERROR_BAD_STANZA_DATA;
            goto cleanup;
        }

        add_acc_bool(&(stanza->use_rijndael), "Y");
    }

    if(sdp_get_json_string_field("hmac_type", jdata, &tmp) == SDP_SUCCESS)
    {
        if((stanza->hmac_type = hmac_digest_strtoint(tmp)) < 0)
        {
            log_msg(LOG_ERR,
                "HMAC_DIGEST_TYPE argument '%s' must be one of {md5,sha1,sha256,sha384,sha512}",
                tmp);
            free(tmp);
            goto cleanup;
        }
        free(tmp);
    }

    if(sdp_get_json_string_field("spa_hmac_key", jdata, &(stanza->hmac_key)) == SDP_SUCCESS)
    {
        if((stanza->hmac_key_len = strnlen(stanza->key, MAX_KEY_LEN + 1)) > MAX_KEY_LEN)
        {
            log_msg(LOG_ERR, "Key length exceeds max length of %d bytes", MAX_KEY_LEN);
            rv = FWKNOPD_ERROR_BAD_STANZA_DATA;
            goto cleanup;
        }
    }

    if(sdp_get_json_string_field("spa_hmac_key_base64", jdata, &(stanza->hmac_key_base64)) == SDP_SUCCESS)
    {
        if(strnlen(stanza->hmac_key_base64, MAX_B64_KEY_LEN + 1) > MAX_B64_KEY_LEN)
        {
            log_msg(LOG_ERR, "B64 key length exceeds max length %d bytes", MAX_B64_KEY_LEN);
            rv = FWKNOPD_ERROR_BAD_STANZA_DATA;
            goto cleanup;
        }
        // make space for decoded version of the key
        // decode function does not watch for buffer overwrite, so oversize the buffer
        if((stanza->hmac_key = calloc(1, MAX_B64_KEY_LEN)) == NULL)
        {
            rv = SDP_ERROR_MEMORY_ALLOCATION;
            goto cleanup;
        }
        // perform decode and get key len
        if((stanza->hmac_key_len = fko_base64_decode(stanza->hmac_key_base64, (unsigned char*)stanza->hmac_key)) < 0)
        {
            log_msg(LOG_ERR, "Failed to decode base64 key");
            rv = FWKNOPD_ERROR_BAD_STANZA_DATA;
            goto cleanup;
        }

        if(stanza->hmac_key_len > MAX_KEY_LEN)
        {
            log_msg(LOG_ERR, "Decoded key length is %d bytes, exceeds max length %d bytes", stanza->hmac_key_len, MAX_KEY_LEN);
            rv = FWKNOPD_ERROR_BAD_STANZA_DATA;
            goto cleanup;
        }
    }

    if(sdp_get_json_int_field("fw_access_timeout", jdata, &(stanza->fw_access_timeout)) == SDP_SUCCESS)
    {
        if(stanza->fw_access_timeout < 0 || stanza->fw_access_timeout > RCHK_MAX_FW_TIMEOUT)
        {
            log_msg(LOG_ERR,
                "fw_access_timeout value %d not in range [0 - %d].",
                stanza->fw_access_timeout, RCHK_MAX_FW_TIMEOUT);
            rv = FWKNOPD_ERROR_BAD_STANZA_DATA;
            goto cleanup;
        }
    }

    if(sdp_get_json_string_field("encryption_mode", jdata, &tmp) == SDP_SUCCESS)
    {
        if((stanza->encryption_mode = enc_mode_strtoint(tmp)) < 0)
        {
            log_msg(LOG_ERR,
                "Unrecognized encryption_mode '%s', use {CBC,CTR,legacy,Asymmetric}",
                tmp);
            free(tmp);
            goto cleanup;
        }
        free(tmp);
    }

    if(sdp_get_json_string_field("enable_cmd_exec", jdata, &tmp) == SDP_SUCCESS)
    {
        add_acc_bool(&(stanza->enable_cmd_exec), tmp);
        free(tmp);
    }

    if(sdp_get_json_string_field("enable_cmd_sudo_exec", jdata, &tmp) == SDP_SUCCESS)
    {
        add_acc_bool(&(stanza->enable_cmd_sudo_exec), tmp);
        free(tmp);
    }

    if(sdp_get_json_string_field("cmd_sudo_exec_user", jdata, &(stanza->cmd_sudo_exec_user)) == SDP_SUCCESS)
    {
        errno = 0;
        sudo_user_pw = getpwnam(stanza->cmd_sudo_exec_user);

        if(sudo_user_pw == NULL)
        {
            log_msg(LOG_ERR, "Unable to determine UID for %s: %s.",
                    stanza->cmd_sudo_exec_user,
                    errno ? strerror(errno) : "Not a user on this system");
            goto cleanup;
        }

        stanza->cmd_sudo_exec_uid = sudo_user_pw->pw_uid;
    }

    if(sdp_get_json_string_field("cmd_exec_user", jdata, &(stanza->cmd_exec_user)) == SDP_SUCCESS)
    {
        errno = 0;
        user_pw = getpwnam(stanza->cmd_exec_user);

        if(user_pw == NULL)
        {
            log_msg(LOG_ERR, "Unable to determine UID for %s: %s.",
                    stanza->cmd_exec_user,
                    errno ? strerror(errno) : "Not a user on this system");
            goto cleanup;
        }

        stanza->cmd_exec_uid = user_pw->pw_uid;
    }

    if(sdp_get_json_string_field("cmd_sudo_exec_group", jdata, &(stanza->cmd_sudo_exec_group)) == SDP_SUCCESS)
    {
        errno = 0;
        tmp_pw = getpwnam(stanza->cmd_sudo_exec_group);

        if(tmp_pw == NULL)
        {
            log_msg(LOG_ERR, "Unable to determine GID for %s: %s.",
                    stanza->cmd_sudo_exec_group,
                    errno ? strerror(errno) : "Not a group on this system");
            goto cleanup;
        }

        stanza->cmd_sudo_exec_gid = tmp_pw->pw_gid;
    }

    if(sdp_get_json_string_field("cmd_exec_group", jdata, &(stanza->cmd_exec_group)) == SDP_SUCCESS)
    {
        errno = 0;
        tmp_pw = getpwnam(stanza->cmd_exec_group);

        if(tmp_pw == NULL)
        {
            log_msg(LOG_ERR, "Unable to determine GID for %s: %s.",
                    stanza->cmd_exec_group,
                    errno ? strerror(errno) : "Not a group on this system");
            goto cleanup;
        }

        stanza->cmd_exec_gid = tmp_pw->pw_gid;
    }

    if(sdp_get_json_string_field("cmd_cycle_open", jdata, &(stanza->cmd_cycle_open)) == SDP_SUCCESS)
    {
        stanza->cmd_cycle_do_close = 1;
    }

    sdp_get_json_string_field("cmd_cycle_close", jdata, &(stanza->cmd_cycle_close));
    sdp_get_json_int_field("cmd_cycle_timer", jdata, &(stanza->cmd_cycle_timer));
    sdp_get_json_string_field("require_username", jdata, &(stanza->require_username));

    if(sdp_get_json_string_field("require_source_address", jdata, &tmp) == SDP_SUCCESS)
    {
        add_acc_bool(&(stanza->require_source_address), tmp);
        free(tmp);
    }

    if(sdp_get_json_string_field("require_source", jdata, &tmp) == SDP_SUCCESS)
    {
        add_acc_bool(&(stanza->require_source_address), tmp);
        free(tmp);
    }

    if(sdp_get_json_string_field("gpg_home_dir", jdata, &(stanza->gpg_home_dir)) == SDP_SUCCESS)
    {
        if(!is_valid_dir(stanza->gpg_home_dir))
        {
            log_msg(LOG_ERR,
                "GPG_HOME_DIR directory '%s' stat()/existence problem in stanza source '%s'",
                stanza->gpg_home_dir, stanza->source);
            rv = FWKNOPD_ERROR_BAD_STANZA_DATA;
            goto cleanup;
        }
    }

    sdp_get_json_string_field("gpg_exe", jdata, &(stanza->gpg_exe));
    sdp_get_json_string_field("gpg_decrypt_id", jdata, &(stanza->gpg_decrypt_id));

    if((sdp_get_json_string_field("gpg_decrypt_pw", jdata, &(stanza->gpg_decrypt_pw))) == SDP_SUCCESS)
    {
        add_acc_bool(&(stanza->use_gpg), "Y");
    }

    if(sdp_get_json_string_field("gpg_allow_no_pw", jdata, &tmp) == SDP_SUCCESS)
    {
        add_acc_bool(&(stanza->gpg_allow_no_pw), tmp);
        free(tmp);
        if(stanza->gpg_allow_no_pw == 1)
        {
            add_acc_bool(&(stanza->use_gpg), "Y");
            if((stanza->gpg_decrypt_pw = strndup("", 1)) == NULL)
            {
                rv = FKO_ERROR_MEMORY_ALLOCATION;
                goto cleanup;
            }
        }
    }

    if(sdp_get_json_string_field("gpg_require_sig", jdata, &tmp) == SDP_SUCCESS)
    {
        add_acc_bool(&(stanza->gpg_require_sig), tmp);
        free(tmp);
    }

    if(sdp_get_json_string_field("gpg_disable_sig", jdata, &tmp) == SDP_SUCCESS)
    {
        add_acc_bool(&(stanza->gpg_disable_sig), tmp);
        free(tmp);
    }

    if(sdp_get_json_string_field("gpg_ignore_sig_error", jdata, &tmp) == SDP_SUCCESS)
    {
        add_acc_bool(&(stanza->gpg_ignore_sig_error), tmp);
        free(tmp);
    }

    sdp_get_json_string_field("gpg_remote_id", jdata, &(stanza->gpg_remote_id));
    sdp_get_json_string_field("gpg_remote_fpr", jdata, &(stanza->gpg_remote_fpr));

    if(sdp_get_json_string_field("access_expire_time", jdata, &tmp) == SDP_SUCCESS)
    {
        if((rv = add_acc_expire_time(&(stanza->access_expire_time), tmp)) != FWKNOPD_SUCCESS)
        {
            free(tmp);
            goto cleanup;
        }
        free(tmp);
    }

    if(sdp_get_json_string_field("access_expire_epoch", jdata, &tmp) == SDP_SUCCESS)
    {
        if((rv = add_acc_expire_time_epoch(&(stanza->access_expire_time), tmp)) != FWKNOPD_SUCCESS)
        {
            free(tmp);
            goto cleanup;
        }
        free(tmp);
    }

    if(sdp_get_json_string_field("force_nat", jdata, &tmp) == SDP_SUCCESS)
    {
#if FIREWALL_FIREWALLD
        if(strncasecmp(opts->config[CONF_ENABLE_FIREWD_FORWARDING], "Y", 1) !=0
            && (strncasecmp(opts->config[CONF_ENABLE_FIREWD_LOCAL_NAT], "Y", 1) !=0 ))
        {
            log_msg(LOG_ERR,
                "[*] FORCE_NAT requires either ENABLE_FIREWD_FORWARDING or ENABLE_FIREWD_LOCAL_NAT in fwknopd.conf");
            free(tmp);
            rv = FWKNOPD_ERROR_BAD_STANZA_DATA;
            goto cleanup;
        }
        if((rv = add_acc_force_nat(stanza, tmp)) != FWKNOPD_SUCCESS)
        {
            free(tmp);
            goto cleanup;
        }
#elif FIREWALL_IPTABLES
        if(strncasecmp(opts->config[CONF_ENABLE_IPT_FORWARDING], "Y", 1) !=0
            && (strncasecmp(opts->config[CONF_ENABLE_IPT_LOCAL_NAT], "Y", 1) !=0 ))
        {
            log_msg(LOG_ERR,
                "[*] FORCE_NAT requires ENABLE_IPT_FORWARDING ENABLE_IPT_LOCAL_NAT in fwknopd.conf");
            free(tmp);
            rv = FWKNOPD_ERROR_BAD_STANZA_DATA;
            goto cleanup;
        }
        if((rv = add_acc_force_nat(stanza, tmp)) != FWKNOPD_SUCCESS)
        {
            free(tmp);
            goto cleanup;
        }
#else
        log_msg(LOG_ERR,
            "[*] FORCE_NAT not supported.");
        free(tmp);
        rv = FWKNOPD_ERROR_BAD_STANZA_DATA;
        goto cleanup;
#endif
        free(tmp);
    }

    if(sdp_get_json_string_field("force_snat", jdata, &tmp) == SDP_SUCCESS)
    {
#if FIREWALL_FIREWALLD
        if(strncasecmp(opts->config[CONF_ENABLE_FIREWD_FORWARDING], "Y", 1) !=0
            && (strncasecmp(opts->config[CONF_ENABLE_FIREWD_LOCAL_NAT], "Y", 1) !=0 ))
        {
            log_msg(LOG_ERR,
                "[*] FORCE_SNAT requires either ENABLE_FIREWD_FORWARDING or ENABLE_FIREWD_LOCAL_NAT in fwknopd.conf");
            free(tmp);
            rv = FWKNOPD_ERROR_BAD_STANZA_DATA;
            goto cleanup;
        }
        if((rv = add_acc_force_snat(stanza, tmp)) != FWKNOPD_SUCCESS)
        {
            free(tmp);
            goto cleanup;
        }
#elif FIREWALL_IPTABLES
        if(strncasecmp(opts->config[CONF_ENABLE_IPT_FORWARDING], "Y", 1) !=0
            && (strncasecmp(opts->config[CONF_ENABLE_IPT_LOCAL_NAT], "Y", 1) !=0 ))
        {
            log_msg(LOG_ERR,
                "[*] FORCE_SNAT requires ENABLE_IPT_FORWARDING ENABLE_IPT_LOCAL_NAT in fwknopd.conf");
            free(tmp);
            rv = FWKNOPD_ERROR_BAD_STANZA_DATA;
            goto cleanup;
        }
        if((rv = add_acc_force_snat(stanza, tmp)) != FWKNOPD_SUCCESS)
        {
            free(tmp);
            goto cleanup;
        }
#else
        log_msg(LOG_ERR,
            "[*] FORCE_SNAT not supported.");
        free(tmp);
        rv = FWKNOPD_ERROR_BAD_STANZA_DATA;
        goto cleanup;
#endif
        free(tmp);
    }

    if(sdp_get_json_string_field("force_masquerade", jdata, &tmp) == SDP_SUCCESS)
    {
        add_acc_bool(&(stanza->force_masquerade), tmp);
        add_acc_bool(&(stanza->force_snat), tmp);
        free(tmp);
    }

    if(sdp_get_json_string_field("disable_dnat", jdata, &tmp) == SDP_SUCCESS)
    {
        add_acc_bool(&(stanza->disable_dnat), tmp);
        free(tmp);
    }

    if(sdp_get_json_string_field("forward_all", jdata, &tmp) == SDP_SUCCESS)
    {
        add_acc_bool(&(stanza->forward_all), tmp);
        free(tmp);
    }

    // do sanity check on data
    if(!acc_data_is_valid(opts, user_pw, sudo_user_pw, stanza))
    {
        log_msg(LOG_ERR, "[*] Validation failed on stanza for SDP ID %d", stanza->sdp_id);
        rv = FWKNOPD_ERROR_BAD_STANZA_DATA;
    }

    if(expand_one_acc_ent_list(stanza) != SUCCESS)
    {
        log_msg(LOG_ERR, "[*] Access list expansion failed on stanza for SDP ID %d", stanza->sdp_id);
        rv = FWKNOPD_ERROR_BAD_STANZA_DATA;
    }

    set_one_acc_defaults(stanza);

cleanup:
    if(rv != FWKNOPD_SUCCESS)
    {
        free_acc_stanza_data(stanza);
        free(stanza);
        *r_stanza = NULL;
    }
    else
    {
        *r_stanza = stanza;
    }
    return rv;
}

/* Take a json data array from a controller message
 * remove stanzas from the hash table
 */
static void
remove_access_stanzas(hash_table_t *acc_table, int access_array_len, json_object *jdata)
{
    int rv = FKO_SUCCESS;
    int idx;
    int sdp_id = 0;
    json_object *jentry = NULL;
    bstring key = NULL;
    char id[SDP_MAX_CLIENT_ID_STR_LEN + 1] = {0};

    // walk through the access array
    for(idx = 0; idx < access_array_len; idx++)
    {
        jentry = json_object_array_get_idx(jdata, idx);
        if((rv = sdp_get_json_int_field("sdp_id", jentry, &sdp_id)) != SDP_SUCCESS)
        {
            log_msg(LOG_ERR, "Did not find sdp_id field in data array entry.");
            continue;
        }

        // convert the sdp id integer to a bstring
        snprintf(id, SDP_MAX_CLIENT_ID_STR_LEN, "%d", sdp_id);
        key = bfromcstr(id);

        if( hash_table_delete(acc_table, key) != FKO_SUCCESS )
        {
            log_msg(LOG_WARNING, "Did not find hash table node with SDP ID %d to remove. Continuing.", sdp_id);
        }
        else
        {
            log_msg(LOG_NOTICE, "Removed access stanza for SDP ID %d from access list.", sdp_id);
        }

        bdestroy(key);
    }
}

/* Take a json data array from a controller message
 * add/replace stanzas in the hash table
 */
static int
modify_access_table(fko_srv_options_t *opts, int access_array_len, json_object *jdata)
{
    int rv = FWKNOPD_SUCCESS;
    acc_stanza_t *new_acc = NULL;
    int idx = 0;
    int nodes = 0;
    json_object *jstanza = NULL;
    bstring key = NULL;
    char id[SDP_MAX_CLIENT_ID_STR_LEN + 1] = {0};

    // walk through the access array
    for(idx = 0; idx < access_array_len; idx++)
    {
        jstanza = json_object_array_get_idx(jdata, idx);
        if((rv = make_acc_stanza_from_json(opts, jstanza, &new_acc)) != FWKNOPD_SUCCESS)
        {
            if(rv == FKO_ERROR_MEMORY_ALLOCATION)
            {
                log_msg(LOG_ERR, "Memory allocation error while parsing json data, time to die");
                return FKO_ERROR_MEMORY_ALLOCATION;
            }

            log_msg(LOG_ERR, "Failed to parse json stanza, attempting to carry on");
            continue;
        }

        // convert the sdp id integer to a bstring
        snprintf(id, SDP_MAX_CLIENT_ID_STR_LEN, "%d", new_acc->sdp_id);
        key = bfromcstr(id);

        if( hash_table_set(opts->acc_stanza_hash_tbl, key, new_acc) != FKO_SUCCESS )
        {
            log_msg(LOG_ERR,
                "Fatal error creating access stanza hash table node"
            );
            bdestroy(key);
            free_acc_stanza_data(new_acc);
            free(new_acc);
            return FKO_ERROR_MEMORY_ALLOCATION;
        }

        log_msg(LOG_NOTICE, "Added access entry for SDP ID %d", new_acc->sdp_id);
        nodes++;
    }

    if(nodes > 0)
    {
        log_msg(LOG_INFO, "Created %d hash table nodes from %d json stanzas", nodes, access_array_len);
        rv = FWKNOPD_SUCCESS;
    }
    else
        log_msg(LOG_WARNING, "Failed to create any hash table nodes from %d json stanzas", access_array_len);

    return rv;

}

/* Take a json data array from a controller message
 * Alter/recreate the hash table based on the action
 */
int
process_access_msg(fko_srv_options_t *opts, int action, json_object *jdata)
{
    int rv = FWKNOPD_SUCCESS;
    int hash_table_len = 0;
    int access_array_len = 0;
    int is_err = 0;

    if(jdata == NULL || json_object_get_type(jdata) == json_type_null)
    {
        log_msg(LOG_ERR, "process_access_msg(): jdata is invalid");
        return FWKNOPD_ERROR_BAD_MSG;
    }

    access_array_len = json_object_array_length(jdata);
    if(access_array_len <= 0)
    {
        log_msg(LOG_ERR, "Received access message with zero length data array.");
        return FWKNOPD_ERROR_BAD_MSG;
    }

    log_msg(LOG_DEBUG, "jdata contains %d objects", access_array_len);


    // lock the hash table mutex
    if(pthread_mutex_lock(&(opts->acc_hash_tbl_mutex)))
    {
        log_msg(LOG_ERR, "Mutex lock error.");
        return FWKNOPD_ERROR_MUTEX;
    }

    if(action == CTRL_ACTION_ACCESS_REMOVE)
    {
        if(opts->acc_stanza_hash_tbl == NULL)
        {
            //table is not initialized, nothing to do
            log_msg(LOG_WARNING, "Received access remove message, but access table not "
                    "initialized. Nothing to do.");
            pthread_mutex_unlock(&(opts->acc_hash_tbl_mutex));
            return FWKNOPD_ERROR_UNTIMELY_MSG;
        }

        remove_access_stanzas(opts->acc_stanza_hash_tbl, access_array_len, jdata);
        pthread_mutex_unlock(&(opts->acc_hash_tbl_mutex));

        return FWKNOPD_SUCCESS;
    }

    // if this is an access data refresh, destroy the hash table
    if(action == CTRL_ACTION_ACCESS_REFRESH)
    {
        if(opts->acc_stanza_hash_tbl != NULL)
        {
            // destroy the table
            hash_table_destroy(opts->acc_stanza_hash_tbl);
            opts->acc_stanza_hash_tbl = NULL;
        }
    }

    // create the hash table if necessary
    if(opts->acc_stanza_hash_tbl == NULL)
    {
        //need to initialize hash table
        hash_table_len = strtol_wrapper(opts->config[CONF_ACC_STANZA_HASH_TABLE_LENGTH],
                               MIN_ACC_STANZA_HASH_TABLE_LENGTH,
                               MAX_ACC_STANZA_HASH_TABLE_LENGTH,
                               NO_EXIT_UPON_ERR,
                               &is_err);

        if(is_err != FKO_SUCCESS)
        {
            // this error should be impossible because the config variable
            // is checked at startup

            pthread_mutex_unlock(&(opts->acc_hash_tbl_mutex));

            log_msg(LOG_ERR, "[*] var %s value '%s' not in the range %d-%d",
                    "ACC_STANZA_HASH_TABLE_LENGTH",
                    opts->config[CONF_ACC_STANZA_HASH_TABLE_LENGTH],
                    MIN_ACC_STANZA_HASH_TABLE_LENGTH,
                    MAX_ACC_STANZA_HASH_TABLE_LENGTH);

            return FWKNOPD_ERROR_BAD_CONFIG;
        }

        opts->acc_stanza_hash_tbl = hash_table_create(hash_table_len,
                NULL, NULL, destroy_hash_node_cb);
        if(opts->acc_stanza_hash_tbl == NULL)
        {
            pthread_mutex_unlock(&(opts->acc_hash_tbl_mutex));

            log_msg(LOG_ERR,
                "[*] Fatal memory allocation error creating access stanza hash table"
            );
            return FKO_ERROR_MEMORY_ALLOCATION;
        }
    }

    // control message is either REFRESH or UPDATE
    // in either case, use data array to modify the table
    if((rv = modify_access_table(opts, access_array_len, jdata)) != FWKNOPD_SUCCESS)
    {
        log_msg(LOG_ERR, "modify_access_table was unsuccessful");
    }

    // release lock on the table
    pthread_mutex_unlock(&(opts->acc_hash_tbl_mutex));

    return rv;
}



/* Read and parse the access file, populating the access data as we go.
*/
void
parse_access_file(fko_srv_options_t *opts)
{
    FILE           *file_ptr;
    char           *ndx;
    int             got_source = 0, is_err;
    int             got_sdp_id=0;
    unsigned int    num_lines = 0;

    char            access_line_buf[MAX_LINE_LEN] = {0};
    char            var[MAX_LINE_LEN] = {0};
    char            val[MAX_LINE_LEN] = {0};

    struct passwd  *user_pw = NULL;
    struct passwd  *sudo_user_pw = NULL;
    struct stat     st;

    acc_stanza_t   *curr_acc = NULL;

    /* First see if the access file exists.  If it doesn't, complain
     * and bail.
    */
    if(stat(opts->config[CONF_ACCESS_FILE], &st) != 0)
    {
        log_msg(LOG_ERR, "[*] Access file: '%s' was not found.",
            opts->config[CONF_ACCESS_FILE]);

        clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
    }

    if(verify_file_perms_ownership(opts->config[CONF_ACCESS_FILE]) != 1)
        clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);

    /* A note on security here: Coverity flags the following fopen() as a
     * Time of check time of use (TOCTOU) bug with a low priority due to the
     * previous stat() call above.  I.e., the access.conf file on disk could
     * have been changed between the stat() and the fopen() causing a TOCTOU
     * bug.  While technically this is true, the return value of fopen() is
     * also checked below so stat() success does not imply we assume fopen()
     * success.  Also, we could just remove the stat() and
     * verify_file_perms_ownership() calls above to "fix" the bug, but this
     * would actually make things easier for an attacker that has already
     * compromised the local system since access.conf could be changed to, say,
     * a symbolic link (for which verify_file_perms_ownership() throws a
     * warning), and then there is no race at all before the fopen().  I.e.
     * forcing an attacker to do the race makes things harder for them.
    */
    if ((file_ptr = fopen(opts->config[CONF_ACCESS_FILE], "r")) == NULL)
    {
        log_msg(LOG_ERR, "[*] Could not open access file: %s",
            opts->config[CONF_ACCESS_FILE]);
        perror(NULL);

        clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
    }

    /* Initialize the access list.
    */
    acc_stanza_init(opts);

    /* Now walk through access file pulling the access entries into the
     * current stanza.
    */
    while ((fgets(access_line_buf, MAX_LINE_LEN, file_ptr)) != NULL)
    {
        num_lines++;
        access_line_buf[MAX_LINE_LEN-1] = '\0';

        /* Get past comments and empty lines (note: we only look at the
         * first character.
        */
        if(IS_EMPTY_LINE(access_line_buf[0]))
            continue;

        if(sscanf(access_line_buf, "%s %[^;\n\r]", var, val) != 2)
        {
            log_msg(LOG_ERR,
                "[*] Invalid access file entry in %s at line %i.\n - '%s'",
                opts->config[CONF_ACCESS_FILE], num_lines, access_line_buf
            );
            fclose(file_ptr);
            clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
        }

        /* Remove any colon that may be on the end of the var
        */
        if((ndx = strrchr(var, ':')) != NULL)
            *ndx = '\0';

        /* Even though sscanf should automatically add a terminating
         * NULL byte, an assumption is made that the input arrays are
         * big enough, so we'll force a terminating NULL byte regardless
        */
        var[MAX_LINE_LEN-1] = 0x0;
        val[MAX_LINE_LEN-1] = 0x0;

        if (opts->verbose > 3)
            log_msg(LOG_DEBUG,
                "ACCESS FILE: %s, LINE: %s\tVar: %s, Val: '%s'",
                opts->config[CONF_ACCESS_FILE], access_line_buf, var, val
            );

        /* Process the entry.
         *
         * NOTE: If a new access.conf parameter is created.  It also needs
         *       to be accounted for in the following if/if else construct.
        */
        if(CONF_VAR_IS(var, "SOURCE"))
        {
            if(strncasecmp(opts->config[CONF_DISABLE_SDP_MODE], "Y", 1) == 0)
            {
                /* If this is not the first stanza, sanity check the previous
                 * stanza for the minimum required data.
                */
                if(curr_acc != NULL) {
                    if(!acc_data_is_valid(opts, user_pw, sudo_user_pw, curr_acc))
                    {
                        log_msg(LOG_ERR, "[*] Data error in access file: '%s'",
                            opts->config[CONF_ACCESS_FILE]);
                        fclose(file_ptr);
                        clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
                    }
                }

                /* Start new stanza.
                */
                curr_acc = acc_stanza_add(opts, NULL);
            }
            else if (curr_acc == NULL)
            {
                /* The stanza must start with "SDP_ID" variable
                 * in SDP mode
                */
                continue;
            }

            add_acc_string(&(curr_acc->source), val, file_ptr, opts);
            got_source++;
        }
        else if(CONF_VAR_IS(var, "SDP_ID"))
        {
            // Don't need this field in legacy mode, so ignore completely
            if(strncasecmp(opts->config[CONF_DISABLE_SDP_MODE], "Y", 1) == 0)
                continue;

            /* If this is not the first stanza, sanity check the previous
             * stanza for the minimum required data.
            */
            if(curr_acc != NULL) {
                if(!acc_data_is_valid(opts, user_pw, sudo_user_pw, curr_acc))
                {
                    log_msg(LOG_ERR, "[*] Data error in access file: '%s'",
                        opts->config[CONF_ACCESS_FILE]);
                    fclose(file_ptr);
                    clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
                }
            }

            /* Start new stanza.
            */
            curr_acc = acc_stanza_add(opts, val);
            curr_acc->sdp_id = (uint32_t)strtol_wrapper(val, 0,
                                        UINT32_MAX, NO_EXIT_UPON_ERR, &is_err);
            if(is_err != FKO_SUCCESS)
            {
                log_msg(LOG_ERR,
                    "[*] SDP_ID value not in range in access file: '%s'",
                    opts->config[CONF_ACCESS_FILE] );
                fclose(file_ptr);
                clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
            }
            got_sdp_id++;
        }
        else if (curr_acc == NULL)
        {
            /* The stanza must start with "SOURCE" or "SDP_ID" variable
             * depending on mode
            */
            continue;
        }
        else if(CONF_VAR_IS(var, "DESTINATION"))
            add_acc_string(&(curr_acc->destination), val, file_ptr, opts);
        else if(CONF_VAR_IS(var, "SERVICE_LIST"))
            add_acc_string(&(curr_acc->service_list_str), val, file_ptr, opts);
        else if(CONF_VAR_IS(var, "OPEN_PORTS"))
            add_acc_string(&(curr_acc->open_ports), val, file_ptr, opts);
        else if(CONF_VAR_IS(var, "RESTRICT_PORTS"))
            add_acc_string(&(curr_acc->restrict_ports), val, file_ptr, opts);
        else if(CONF_VAR_IS(var, "KEY"))
        {
            if(strcasecmp(val, "__CHANGEME__") == 0)
            {
                log_msg(LOG_ERR,
                    "[*] KEY value is not properly set in stanza source '%s' in access file: '%s'",
                    curr_acc->source, opts->config[CONF_ACCESS_FILE]);
                fclose(file_ptr);
                clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
            }
            add_acc_string(&(curr_acc->key), val, file_ptr, opts);
            curr_acc->key_len = strlen(curr_acc->key);
            add_acc_bool(&(curr_acc->use_rijndael), "Y");
        }
        else if(CONF_VAR_IS(var, "KEY_BASE64"))
        {
            if(strcasecmp(val, "__CHANGEME__") == 0)
            {
                log_msg(LOG_ERR,
                    "[*] KEY_BASE64 value is not properly set in stanza source '%s' in access file: '%s'",
                    curr_acc->source, opts->config[CONF_ACCESS_FILE]);
                fclose(file_ptr);
                clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
            }
            if (! is_base64((unsigned char *) val, strlen(val)))
            {
                log_msg(LOG_ERR,
                    "[*] KEY_BASE64 argument '%s' doesn't look like base64-encoded data.",
                    val);
                fclose(file_ptr);
                clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
            }
            add_acc_string(&(curr_acc->key_base64), val, file_ptr, opts);
            add_acc_b64_string(&(curr_acc->key), &(curr_acc->key_len),
                    curr_acc->key_base64, file_ptr, opts);
            add_acc_bool(&(curr_acc->use_rijndael), "Y");
        }
        /* HMAC digest type */
        else if(CONF_VAR_IS(var, "HMAC_DIGEST_TYPE"))
        {
            curr_acc->hmac_type = hmac_digest_strtoint(val);
            if(curr_acc->hmac_type < 0)
            {
                log_msg(LOG_ERR,
                    "[*] HMAC_DIGEST_TYPE argument '%s' must be one of {md5,sha1,sha256,sha384,sha512}",
                    val);
                fclose(file_ptr);
                clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
            }
        }
        else if(CONF_VAR_IS(var, "HMAC_KEY_BASE64"))
        {
            if(strcasecmp(val, "__CHANGEME__") == 0)
            {
                log_msg(LOG_ERR,
                    "[*] HMAC_KEY_BASE64 value is not properly set in stanza source '%s' in access file: '%s'",
                    curr_acc->source, opts->config[CONF_ACCESS_FILE]);
                fclose(file_ptr);
                clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
            }
            if (! is_base64((unsigned char *) val, strlen(val)))
            {
                log_msg(LOG_ERR,
                    "[*] HMAC_KEY_BASE64 argument '%s' doesn't look like base64-encoded data.",
                    val);
                fclose(file_ptr);
                clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
            }
            add_acc_string(&(curr_acc->hmac_key_base64), val, file_ptr, opts);
            add_acc_b64_string(&(curr_acc->hmac_key), &(curr_acc->hmac_key_len),
                    curr_acc->hmac_key_base64, file_ptr, opts);
        }
        else if(CONF_VAR_IS(var, "HMAC_KEY"))
        {
            if(strcasecmp(val, "__CHANGEME__") == 0)
            {
                log_msg(LOG_ERR,
                    "[*] HMAC_KEY value is not properly set in stanza source '%s' in access file: '%s'",
                    curr_acc->source, opts->config[CONF_ACCESS_FILE]);
                fclose(file_ptr);
                clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
            }
            add_acc_string(&(curr_acc->hmac_key), val, file_ptr, opts);
            curr_acc->hmac_key_len = strlen(curr_acc->hmac_key);
        }
        else if(CONF_VAR_IS(var, "FW_ACCESS_TIMEOUT"))
        {
            curr_acc->fw_access_timeout = strtol_wrapper(val, 0,
                    RCHK_MAX_FW_TIMEOUT, NO_EXIT_UPON_ERR, &is_err);
            if(is_err != FKO_SUCCESS)
            {
                log_msg(LOG_ERR,
                    "[*] FW_ACCESS_TIMEOUT value not in range.");
                fclose(file_ptr);
                clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
            }
        }
        else if(CONF_VAR_IS(var, "ENCRYPTION_MODE"))
        {
            if((curr_acc->encryption_mode = enc_mode_strtoint(val)) < 0)
            {
                log_msg(LOG_ERR,
                    "[*] Unrecognized ENCRYPTION_MODE '%s', use {CBC,CTR,legacy,Asymmetric}",
                    val);
                fclose(file_ptr);
                clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
            }
        }
        else if(CONF_VAR_IS(var, "ENABLE_CMD_EXEC"))
        {
            add_acc_bool(&(curr_acc->enable_cmd_exec), val);
        }
        else if(CONF_VAR_IS(var, "ENABLE_CMD_SUDO_EXEC"))
        {
            add_acc_bool(&(curr_acc->enable_cmd_sudo_exec), val);
        }
        else if(CONF_VAR_IS(var, "CMD_SUDO_EXEC_USER"))
            add_acc_user(&(curr_acc->cmd_sudo_exec_user),
                        &(curr_acc->cmd_sudo_exec_uid), &sudo_user_pw,
                        val, "CMD_SUDO_EXEC_USER", file_ptr, opts);
        else if(CONF_VAR_IS(var, "CMD_SUDO_EXEC_GROUP"))
            add_acc_group(&(curr_acc->cmd_sudo_exec_group),
                        &(curr_acc->cmd_sudo_exec_gid), val,
                        "CMD_SUDO_EXEC_GROUP", file_ptr, opts);
        else if(CONF_VAR_IS(var, "CMD_EXEC_USER"))
            add_acc_user(&(curr_acc->cmd_exec_user),
                        &(curr_acc->cmd_exec_uid), &user_pw,
                        val, "CMD_EXEC_USER", file_ptr, opts);
        else if(CONF_VAR_IS(var, "CMD_EXEC_GROUP"))
            add_acc_group(&(curr_acc->cmd_exec_group),
                        &(curr_acc->cmd_exec_gid), val,
                        "CMD_EXEC_GROUP", file_ptr, opts);
        else if(CONF_VAR_IS(var, "CMD_CYCLE_OPEN"))
        {
            add_acc_string(&(curr_acc->cmd_cycle_open), val, file_ptr, opts);
            curr_acc->cmd_cycle_do_close = 1; /* default, will be validated */
        }
        else if(CONF_VAR_IS(var, "CMD_CYCLE_CLOSE"))
            add_acc_string(&(curr_acc->cmd_cycle_close), val, file_ptr, opts);
        else if(CONF_VAR_IS(var, "CMD_CYCLE_TIMER"))
        {
            curr_acc->cmd_cycle_timer = strtol_wrapper(val,
                    RCHK_MIN_CMD_CYCLE_TIMER, RCHK_MAX_CMD_CYCLE_TIMER,
                    NO_EXIT_UPON_ERR, &is_err);
            if(is_err != FKO_SUCCESS)
            {
                log_msg(LOG_ERR,
                    "[*] CMD_CYCLE_TIMER value not in range [1,%d].",
                    RCHK_MAX_CMD_CYCLE_TIMER);
                fclose(file_ptr);
                clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
            }
        }
        else if(CONF_VAR_IS(var, "REQUIRE_USERNAME"))
            add_acc_string(&(curr_acc->require_username), val, file_ptr, opts);
        else if(CONF_VAR_IS(var, "REQUIRE_SOURCE_ADDRESS"))
            add_acc_bool(&(curr_acc->require_source_address), val);
        else if(CONF_VAR_IS(var, "REQUIRE_SOURCE"))  /* synonym for REQUIRE_SOURCE_ADDRESS */
            add_acc_bool(&(curr_acc->require_source_address), val);
        else if(CONF_VAR_IS(var, "GPG_HOME_DIR"))
        {
            if (is_valid_dir(val))
            {
                add_acc_string(&(curr_acc->gpg_home_dir), val, file_ptr, opts);
            }
            else
            {
                log_msg(LOG_ERR,
                    "[*] GPG_HOME_DIR directory '%s' stat()/existence problem in stanza source '%s' in access file: '%s'",
                    val, curr_acc->source, opts->config[CONF_ACCESS_FILE]);
                fclose(file_ptr);
                clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
            }
        }
        else if(CONF_VAR_IS(var, "GPG_EXE"))
            add_acc_string(&(curr_acc->gpg_exe), val, file_ptr, opts);
        else if(CONF_VAR_IS(var, "GPG_DECRYPT_ID"))
            add_acc_string(&(curr_acc->gpg_decrypt_id), val, file_ptr, opts);
        else if(CONF_VAR_IS(var, "GPG_DECRYPT_PW"))
        {
            if(strcasecmp(val, "__CHANGEME__") == 0)
            {
                log_msg(LOG_ERR,
                    "[*] GPG_DECRYPT_PW value is not properly set in stanza source '%s' in access file: '%s'",
                    curr_acc->source, opts->config[CONF_ACCESS_FILE]);
                fclose(file_ptr);
                clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
            }
            add_acc_string(&(curr_acc->gpg_decrypt_pw), val, file_ptr, opts);
            add_acc_bool(&(curr_acc->use_gpg), "Y");
        }
        else if(CONF_VAR_IS(var, "GPG_ALLOW_NO_PW"))
        {
            add_acc_bool(&(curr_acc->gpg_allow_no_pw), val);
            if(curr_acc->gpg_allow_no_pw == 1)
            {
                add_acc_bool(&(curr_acc->use_gpg), "Y");
                add_acc_string(&(curr_acc->gpg_decrypt_pw), "", file_ptr, opts);
            }
        }
        else if(CONF_VAR_IS(var, "GPG_REQUIRE_SIG"))
        {
            add_acc_bool(&(curr_acc->gpg_require_sig), val);
        }
        else if(CONF_VAR_IS(var, "GPG_DISABLE_SIG"))
        {
            add_acc_bool(&(curr_acc->gpg_disable_sig), val);
        }
        else if(CONF_VAR_IS(var, "GPG_IGNORE_SIG_VERIFY_ERROR"))
        {
            add_acc_bool(&(curr_acc->gpg_ignore_sig_error), val);
        }
        else if(CONF_VAR_IS(var, "GPG_REMOTE_ID"))
            add_acc_string(&(curr_acc->gpg_remote_id), val, file_ptr, opts);
        else if(CONF_VAR_IS(var, "GPG_FINGERPRINT_ID"))
            add_acc_string(&(curr_acc->gpg_remote_fpr), val, file_ptr, opts);
        else if(CONF_VAR_IS(var, "ACCESS_EXPIRE"))
        {
            if (add_acc_expire_time(&(curr_acc->access_expire_time), val) != FWKNOPD_SUCCESS)
            {
                fclose(file_ptr);
                clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
            }
        }
        else if(CONF_VAR_IS(var, "ACCESS_EXPIRE_EPOCH"))
        {
            if (add_acc_expire_time_epoch(&(curr_acc->access_expire_time), val) != FWKNOPD_SUCCESS)
            {
                fclose(file_ptr);
                clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
            }
        }
        else if(CONF_VAR_IS(var, "FORCE_NAT"))
        {
#if FIREWALL_FIREWALLD
            if(strncasecmp(opts->config[CONF_ENABLE_FIREWD_FORWARDING], "Y", 1) !=0
                && (strncasecmp(opts->config[CONF_ENABLE_FIREWD_LOCAL_NAT], "Y", 1) !=0 ))
            {
                log_msg(LOG_ERR,
                    "[*] FORCE_NAT requires either ENABLE_FIREWD_FORWARDING or ENABLE_FIREWD_LOCAL_NAT in fwknopd.conf");
                fclose(file_ptr);
                clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
            }
            if(add_acc_force_nat(curr_acc, val) != FWKNOPD_SUCCESS)
            {
                fclose(file_ptr);
                clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
            }
#elif FIREWALL_IPTABLES
            if(strncasecmp(opts->config[CONF_ENABLE_IPT_FORWARDING], "Y", 1) !=0
                && (strncasecmp(opts->config[CONF_ENABLE_IPT_LOCAL_NAT], "Y", 1) !=0 ))
            {
                log_msg(LOG_ERR,
                    "[*] FORCE_NAT requires ENABLE_IPT_FORWARDING ENABLE_IPT_LOCAL_NAT in fwknopd.conf");
                fclose(file_ptr);
                clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
            }
            if(add_acc_force_nat(curr_acc, val) != FWKNOPD_SUCCESS)
            {
                fclose(file_ptr);
                clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
            }
#else
            log_msg(LOG_ERR,
                "[*] FORCE_NAT not supported.");
            fclose(file_ptr);
            clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
#endif
        }
        else if(CONF_VAR_IS(var, "FORCE_SNAT"))
        {
#if FIREWALL_FIREWALLD
            if(strncasecmp(opts->config[CONF_ENABLE_FIREWD_FORWARDING], "Y", 1) !=0
                && (strncasecmp(opts->config[CONF_ENABLE_FIREWD_LOCAL_NAT], "Y", 1) !=0 ))
            {
                log_msg(LOG_ERR,
                    "[*] FORCE_SNAT requires either ENABLE_FIREWD_FORWARDING or ENABLE_FIREWD_LOCAL_NAT in fwknopd.conf");
                fclose(file_ptr);
                clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
            }
            if(add_acc_force_snat(curr_acc, val) != FWKNOPD_SUCCESS)
            {
                fclose(file_ptr);
                clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
            }
#elif FIREWALL_IPTABLES
            if(strncasecmp(opts->config[CONF_ENABLE_IPT_FORWARDING], "Y", 1) !=0
                && (strncasecmp(opts->config[CONF_ENABLE_IPT_LOCAL_NAT], "Y", 1) !=0 ))
            {
                log_msg(LOG_ERR,
                    "[*] FORCE_SNAT requires ENABLE_IPT_FORWARDING ENABLE_IPT_LOCAL_NAT in fwknopd.conf");
                fclose(file_ptr);
                clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
            }
            if(add_acc_force_snat(curr_acc, val) != FWKNOPD_SUCCESS)
            {
                fclose(file_ptr);
                clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
            }
#else
            log_msg(LOG_ERR,
                "[*] FORCE_SNAT not supported.");
            fclose(file_ptr);
            clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
#endif
        }
        else if(CONF_VAR_IS(var, "FORCE_MASQUERADE"))
        {
            add_acc_bool(&(curr_acc->force_masquerade), val);
            add_acc_bool(&(curr_acc->force_snat), val);
        }
        else if(CONF_VAR_IS(var, "DISABLE_DNAT"))
        {
            add_acc_bool(&(curr_acc->disable_dnat), val);
        }
        else if(CONF_VAR_IS(var, "FORWARD_ALL"))
        {
            add_acc_bool(&(curr_acc->forward_all), val);
        }
        else
        {
            log_msg(LOG_ERR,
                "[*] Ignoring unknown access parameter: '%s' in %s",
                var, opts->config[CONF_ACCESS_FILE]
            );
        }
    }

    fclose(file_ptr);

    /* Basic check to ensure that we got at least one SOURCE stanza with
     * a valid KEY defined (valid meaning it has a value that is not
     * "__CHANGEME__".
    */
    if(got_source == 0)
    {
        log_msg(LOG_ERR,
            "[*] Could not find valid SOURCE stanza in access file: '%s'",
            opts->config[CONF_ACCESS_FILE]);
        clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
    }

    /* Sanity check the last stanza
    */
    if(!acc_data_is_valid(opts, user_pw, sudo_user_pw, curr_acc))
    {
        log_msg(LOG_ERR,
            "[*] Data error in access file: '%s'",
            opts->config[CONF_ACCESS_FILE]);
        clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
    }

    /* Expand our the expandable fields into their respective data buckets.
    */
    expand_acc_ent_lists(opts);

    /* Make sure default values are set where needed.
    */
    set_acc_defaults(opts);

    return;
}

int
compare_addr_list(acc_int_list_t *ip_list, const uint32_t ip)
{
    int match = 0;

    while(ip_list)
    {
        if((ip & ip_list->mask) == (ip_list->maddr & ip_list->mask))
        {
            match = 1;
            break;
        }

        ip_list = ip_list->next;
    }

    return(match);
}

/* Compare the contents of 2 port lists.  Return true on a match.
 * Match depends on the match_any flag.  if match_any is 1 then any
 * entry in the incoming data need only match one item to return true.
 * Otherwise all entries in the incoming data must have a corresponding
 * match in the access port_list.
*/
static int
compare_port_list(acc_port_list_t *in, acc_port_list_t *ac, const int match_any)
{
    int a_cnt = 0;
    int i_cnt = 0;

    acc_port_list_t *tlist;
    while(in)
    {
        i_cnt++;

        tlist = ac;
        while(tlist)
        {
            if(in->proto == tlist->proto && in->port == tlist->port)
            {
                a_cnt++;
                if(match_any == 1)
                    return(1);
            }
            tlist = tlist->next;
        }
        in = in->next;
    }

    return(i_cnt == a_cnt);
}

/* Take a service string (or mulitple comma-separated strings) and check
 * them against the list for the given access stanza.
 *
 * Return 1 if we are allowed
*/
int
acc_check_service_access(acc_stanza_t *acc, char *service_str)
{
    int             res = 1, this_res = 0;

    acc_service_list_t *in_service_list  = NULL;
    acc_service_list_t *this_requested_service = NULL;
    acc_service_list_t *this_permitted_service = NULL;

    if((res = expand_acc_service_list(&in_service_list, service_str)) == 0 ||
        in_service_list == NULL)
    {
        log_msg(LOG_ERR,
            "[*] Unable to create acc_service_list from incoming data: %s",
            service_str
        );
        return(0);
    }

    this_requested_service = in_service_list;

    while(this_requested_service != NULL)
    {
        this_res = 0;
        this_permitted_service = acc->service_list;

        while(this_permitted_service != NULL)
        {
            if(this_permitted_service->service_id == this_requested_service->service_id)
            {
                this_res = 1;
                break;
            }
            this_permitted_service = this_permitted_service->next;
        }

        if(this_res != 1)
        {
            res = 0;
            break;
        }

        this_requested_service = this_requested_service->next;
    }

    free_acc_service_list(in_service_list);
    return(res);
}



/* Take a proto/port string (or mulitple comma-separated strings) and check
 * them against the list for the given access stanza.
 *
 * Return 1 if we are allowed
*/
int
acc_check_port_access(acc_stanza_t *acc, char *port_str)
{
    int             res = 1, ctr = 0;

    char            buf[ACCESS_BUF_LEN] = {0};
    char           *ndx, *start;

    acc_port_list_t *o_pl   = acc->oport_list;
    acc_port_list_t *r_pl   = acc->rport_list;

    acc_port_list_t *in_pl  = NULL;

    start = port_str;

    /* Create our own internal port_list from the incoming SPA data
     * for comparison.
    */
    for(ndx = start; *ndx != '\0'; ndx++)
    {
        if(*ndx == ',')
        {
            if((ctr >= ACCESS_BUF_LEN)
                    || (((ndx-start)+1) >= ACCESS_BUF_LEN))
            {
                log_msg(LOG_ERR,
                    "[*] Unable to create acc_port_list from incoming data: %s",
                    port_str
                );
                free_acc_port_list(in_pl);
                return(0);
            }
            strlcpy(buf, start, (ndx-start)+1);
            if(add_port_list_ent(&in_pl, buf) == 0)
            {
                log_msg(LOG_ERR, "[*] Invalid proto/port string");
                free_acc_port_list(in_pl);
                return(0);
            }

            start = ndx+1;
            ctr = 0;
        }
        ctr++;
    }
    if((ctr >= ACCESS_BUF_LEN)
            || (((ndx-start)+1) >= ACCESS_BUF_LEN))
    {
        log_msg(LOG_ERR,
            "[*] Unable to create acc_port_list from incoming data: %s",
            port_str
        );
        free_acc_port_list(in_pl);
        return(0);
    }
    strlcpy(buf, start, (ndx-start)+1);
    if(add_port_list_ent(&in_pl, buf) == 0)
    {
        log_msg(LOG_ERR, "[*] Invalid proto/port string");
        free_acc_port_list(in_pl);
        return 0;
    }

    if(in_pl == NULL)
    {
        log_msg(LOG_ERR,
            "[*] Unable to create acc_port_list from incoming data: %s", port_str
        );
        return(0);
    }

    /* Start with restricted ports (if any).  Any match (even if only one
     * entry) means not allowed.
    */
    if((acc->rport_list != NULL) && (compare_port_list(in_pl, r_pl, 1)))
    {
        res = 0;
        goto cleanup_and_bail;
    }

    /* For open port list, all must match.
    */
    if((acc->oport_list != NULL) && (!compare_port_list(in_pl, o_pl, 0)))
            res = 0;

cleanup_and_bail:
    free_acc_port_list(in_pl);
    return(res);
}

/* Dump the configuration
*/
void
dump_access_list(fko_srv_options_t *opts)
{
    int             i = 0;

    acc_stanza_t    *acc = opts->acc_stanzas;

    int opened = 0;
    FILE *dest = NULL;

    if(opts->config[CONF_CONFIG_DUMP_OUTPUT_PATH] != NULL &&
       opts->foreground == 0)
    {
        dest = fopen(opts->config[CONF_CONFIG_DUMP_OUTPUT_PATH], "a");
        if(dest == NULL)
        {
            fprintf(stdout, "ERROR opening file for dump_config output: %s\n",
                    opts->config[CONF_CONFIG_DUMP_OUTPUT_PATH]);
            dest = stdout;
        }
        else
        {
            opened = 1;
        }
    }
    else
    {
        dest = stdout;
    }


    fprintf(dest, "Current fwknopd access settings:\n");

    if(strncasecmp(opts->config[CONF_DISABLE_SDP_MODE], "N", 1) == 0)
    {
        if(! opts->acc_stanza_hash_tbl)
        {
            fprintf(dest, "\n    ** No Access Settings Defined **\n\n");
            return;
        }

        // lock the hash table mutex
        if(pthread_mutex_lock(&(opts->acc_hash_tbl_mutex)))
        {
            fprintf(dest, "Mutex lock error.");
            return;
        }

        hash_table_traverse(opts->acc_stanza_hash_tbl, traverse_dump_hash_cb, dest);

        pthread_mutex_unlock(&(opts->acc_hash_tbl_mutex));
    }
    else
    {
        if(!acc)
        {
            fprintf(dest, "\n    ** No Access Settings Defined **\n\n");
            return;
        }

        while(acc)
        {
            fprintf(dest,
                "SOURCE (%i):  %s\n"
                "==============================================================\n"
                "                DESTINATION:  %s\n"
                "                 OPEN_PORTS:  %s\n"
                "             RESTRICT_PORTS:  %s\n"
                "                        KEY:  %s\n"
                "                 KEY_BASE64:  %s\n"
                "                    KEY_LEN:  %d\n"
                "                   HMAC_KEY:  %s\n"
                "            HMAC_KEY_BASE64:  %s\n"
                "               HMAC_KEY_LEN:  %d\n"
                "           HMAC_DIGEST_TYPE:  %d\n"
                "          FW_ACCESS_TIMEOUT:  %i\n"
                "            ENABLE_CMD_EXEC:  %s\n"
                "       ENABLE_CMD_SUDO_EXEC:  %s\n"
                "         CMD_SUDO_EXEC_USER:  %s\n"
                "        CMD_SUDO_EXEC_GROUP:  %s\n"
                "              CMD_EXEC_USER:  %s\n"
                "             CMD_EXEC_GROUP:  %s\n"
                "             CMD_CYCLE_OPEN:  %s\n"
                "            CMD_CYCLE_CLOSE:  %s\n"
                "            CMD_CYCLE_TIMER:  %i\n"
                "           REQUIRE_USERNAME:  %s\n"
                "     REQUIRE_SOURCE_ADDRESS:  %s\n"
                "             FORCE_NAT (ip):  %s\n"
                "          FORCE_NAT (proto):  %s\n"
                "           FORCE_NAT (port):  %d\n"
                "            FORCE_SNAT (ip):  %s\n"
                "           FORCE_MASQUERADE:  %s\n"
                "               DISABLE_DNAT:  %s\n"
                "                FORWARD_ALL:  %s\n"
                "              ACCESS_EXPIRE:  %s"  /* asctime() adds a newline */
                "               GPG_HOME_DIR:  %s\n"
                "                    GPG_EXE:  %s\n"
                "             GPG_DECRYPT_ID:  %s\n"
                "             GPG_DECRYPT_PW:  %s\n"
                "            GPG_REQUIRE_SIG:  %s\n"
                "GPG_IGNORE_SIG_VERIFY_ERROR:  %s\n"
                "              GPG_REMOTE_ID:  %s\n"
                "         GPG_FINGERPRINT_ID:  %s\n",
                ++i,
                acc->source,
                (acc->destination == NULL) ? "<not set>" : acc->destination,
                (acc->open_ports == NULL) ? "<not set>" : acc->open_ports,
                (acc->restrict_ports == NULL) ? "<not set>" : acc->restrict_ports,
                (acc->key == NULL) ? "<not set>" : "<see the access.conf file>",
                (acc->key_base64 == NULL) ? "<not set>" : "<see the access.conf file>",
                acc->key_len ? acc->key_len : 0,
                (acc->hmac_key == NULL) ? "<not set>" : "<see the access.conf file>",
                (acc->hmac_key_base64 == NULL) ? "<not set>" : "<see the access.conf file>",
                acc->hmac_key_len ? acc->hmac_key_len : 0,
                acc->hmac_type,
                acc->fw_access_timeout,
                acc->enable_cmd_exec ? "Yes" : "No",
                acc->enable_cmd_sudo_exec ? "Yes" : "No",
                (acc->cmd_sudo_exec_user == NULL) ? "<not set>" : acc->cmd_sudo_exec_user,
                (acc->cmd_sudo_exec_group == NULL) ? "<not set>" : acc->cmd_sudo_exec_group,
                (acc->cmd_exec_user == NULL) ? "<not set>" : acc->cmd_exec_user,
                (acc->cmd_exec_group == NULL) ? "<not set>" : acc->cmd_exec_group,
                (acc->cmd_cycle_open == NULL) ? "<not set>" : acc->cmd_cycle_open,
                (acc->cmd_cycle_close == NULL) ? "<not set>" : acc->cmd_cycle_close,
                acc->cmd_cycle_timer,
                (acc->require_username == NULL) ? "<not set>" : acc->require_username,
                acc->require_source_address ? "Yes" : "No",
                acc->force_nat ? acc->force_nat_ip : "<not set>",
                acc->force_nat && acc->force_nat_proto != NULL ? acc->force_nat_proto : "<not set>",
                acc->force_nat ? acc->force_nat_port : 0,
                acc->force_snat ? acc->force_snat_ip : "<not set>",
                acc->force_masquerade ? "Yes" : "No",
                acc->disable_dnat ? "Yes" : "No",
                acc->forward_all ? "Yes" : "No",
                (acc->access_expire_time > 0) ? asctime(localtime(&acc->access_expire_time)) : "<not set>\n",
                (acc->gpg_home_dir == NULL) ? "<not set>" : acc->gpg_home_dir,
                (acc->gpg_exe == NULL) ? "<not set>" : acc->gpg_exe,
                (acc->gpg_decrypt_id == NULL) ? "<not set>" : acc->gpg_decrypt_id,
                (acc->gpg_decrypt_pw == NULL) ? "<not set>" : "<see the access.conf file>",
                acc->gpg_require_sig ? "Yes" : "No",
                acc->gpg_ignore_sig_error  ? "Yes" : "No",
                (acc->gpg_remote_id == NULL) ? "<not set>" : acc->gpg_remote_id,
                (acc->gpg_remote_fpr == NULL) ? "<not set>" : acc->gpg_remote_fpr
            );

            fprintf(dest, "\n");

            acc = acc->next;
        }
    }

    fprintf(dest, "\n");
    fflush(dest);

    if(opened)
    {
        fclose(dest);
    }

}  // END dump_access_list

#ifdef HAVE_C_UNIT_TESTS

DECLARE_UTEST(compare_port_list, "check compare_port_list function")
{
    acc_port_list_t *in1_pl = NULL;
    acc_port_list_t *in2_pl = NULL;
    acc_port_list_t *acc_pl = NULL;

    /* Match any test */
    free_acc_port_list(in1_pl);
    free_acc_port_list(acc_pl);
    add_port_list_ent(&in1_pl, "udp/6002");
    add_port_list_ent(&in2_pl, "udp/6002, udp/6003");
    add_port_list_ent(&acc_pl, "udp/6002, udp/6003");
    CU_ASSERT(compare_port_list(in1_pl, acc_pl, 1) == 1);    /* Only one match is needed from access port list - 1 */
    CU_ASSERT(compare_port_list(in2_pl, acc_pl, 1) == 1);    /* Only match is needed from access port list - 2 */
    CU_ASSERT(compare_port_list(in1_pl, acc_pl, 0) == 1);    /* All ports must match access port list - 1 */
    CU_ASSERT(compare_port_list(in2_pl, acc_pl, 0) == 1);    /* All ports must match access port list - 2 */
    CU_ASSERT(compare_port_list(acc_pl, in1_pl, 0) == 0);    /* All ports must match in1 port list - 1 */
    CU_ASSERT(compare_port_list(acc_pl, in2_pl, 0) == 1);    /* All ports must match in2 port list - 2 */
}

int register_ts_access(void)
{
    ts_init(&TEST_SUITE(access), TEST_SUITE_DESCR(access), NULL, NULL);
    ts_add_utest(&TEST_SUITE(access), UTEST_FCT(compare_port_list), UTEST_DESCR(compare_port_list));

    return register_ts(&TEST_SUITE(access));
}
#endif /* HAVE_C_UNIT_TESTS */

/***EOF***/
