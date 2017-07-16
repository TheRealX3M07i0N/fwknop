/*
 * control_client.c
 *
 *  Created on: Oct 20, 2016
 *      Author: Daniel Bailey
 */

//#include "utils.h"
//#include "config_init.h"
#include "fwknopd_common.h"
#include "fwknopd_errors.h"
#include "service.h"
#include "access.h"
#include "log_msg.h"
#include "connection_tracker.h"
#include "sdp_ctrl_client.h"
#include "control_client.h"

static int process_data_msg(fko_srv_options_t *opts, int action, json_object *jdata)
{
    int rv = FWKNOPD_SUCCESS;

    if(
        action == CTRL_ACTION_ACCESS_REMOVE  ||
        action == CTRL_ACTION_ACCESS_REFRESH ||
        action == CTRL_ACTION_ACCESS_UPDATE
    )
    {
        rv = process_access_msg(opts, action, jdata);

        // arriving here means we got and attempted to process an access message
        if(rv != FWKNOPD_SUCCESS)
        {
            log_msg(LOG_ERR, "Failed to get access data from controller.");
            sdp_ctrl_client_send_data_error(opts->ctrl_client);
        }
        else
        {
            if(action == CTRL_ACTION_ACCESS_REFRESH)
                log_msg(LOG_INFO, "Succeeded in retrieving and installing access configuration");
            else
                log_msg(LOG_INFO, "Succeeded in modifying access data.");
            sdp_ctrl_client_send_data_ack(opts->ctrl_client, CTRL_ACTION_ACCESS_ACK);
        }
    }
    else if(
        action == CTRL_ACTION_SERVICE_REMOVE  ||
        action == CTRL_ACTION_SERVICE_REFRESH ||
        action == CTRL_ACTION_SERVICE_UPDATE
    )
    {
        rv = process_service_msg(opts, action, jdata);

        // arriving here means we got and attempted to process a service data message
        if(rv != FWKNOPD_SUCCESS)
        {
            log_msg(LOG_ERR, "Failed to get service data from controller.");
            sdp_ctrl_client_send_data_error(opts->ctrl_client);
        }
        else
        {
            if(action == CTRL_ACTION_SERVICE_REFRESH)
                log_msg(LOG_INFO, "Succeeded in retrieving and installing service configuration");
            else
                log_msg(LOG_INFO, "Succeeded in modifying service data.");
            sdp_ctrl_client_send_data_ack(opts->ctrl_client, CTRL_ACTION_SERVICE_ACK);
        }
    }

    return rv;
}


static int handle_data_msg(fko_srv_options_t *opts, int action, json_object *jdata)
{
    int rv = FWKNOPD_SUCCESS;

    // if a data message is received, process that
    if((rv = process_data_msg(opts, action, jdata)) == FWKNOPD_ERROR_MUTEX)
    {
        log_msg(LOG_ERR, "SDP Control Client thread mutex error. Aborting.");

        return rv;
    }
    else if(rv == FKO_ERROR_MEMORY_ALLOCATION)
    {
        log_msg(LOG_ERR, "SDP Control Client thread memory allocation error. Aborting.");

        return rv;
    }
    else if(rv != FWKNOPD_SUCCESS)
    {
        log_msg(LOG_ERR, "Error processing data from controller. Carrying on.");
        //sdp_ctrl_client_send_data_error(opts->ctrl_client);
    }
    else
    {
        //log_msg(LOG_INFO, "Succeeded in modifying access data.");
        //sdp_ctrl_client_send_access_ack(opts->ctrl_client);

        if(opts->verbose > 1 && opts->foreground)
        {
            dump_service_list(opts);
            dump_access_list(opts);
        }
    }

    return FWKNOPD_SUCCESS;
}


int get_management_data_from_controller(fko_srv_options_t *opts)
{
    int rv = FWKNOPD_SUCCESS;
    int action = INVALID_CTRL_ACTION;
    json_object *jdata = NULL;
    int err = 0;
    int got_access_data = 0;
    int got_service_data = 0;
    int wait_time = strtol_wrapper(opts->config[CONF_MAX_WAIT_ACC_DATA],
                    1, RCHK_MAX_WAIT_ACC_DATA, NO_EXIT_UPON_ERR, &err);
    time_t stop_time = time(NULL) + wait_time;

    if(opts == NULL)
    {
        log_msg(LOG_ERR, "fwknop not properly initialized");
        return FWKNOPD_ERROR_BAD_CONFIG;
    }

    if((rv = sdp_ctrl_client_new(opts->config[CONF_SDP_CTRL_CLIENT_CONF],
                                 opts->config[CONF_FWKNOP_CLIENT_CONF],
                                 opts->foreground,
                                 &(opts->ctrl_client))) != SDP_SUCCESS)
    {
        log_msg(LOG_ERR, "Failed to create new SDP ctrl client");
        return rv;
    }

    while(1)
    {
        // connect if necessary
        if(sdp_ctrl_client_connection_status(opts->ctrl_client) == SDP_COM_DISCONNECTED)
        {
            if((rv = sdp_ctrl_client_connect(opts->ctrl_client)) != SDP_SUCCESS)
            {
                break;
            }
        }

        // check for incoming messages
        if((rv = sdp_ctrl_client_check_inbox(opts->ctrl_client, &action, (void**)&jdata)) != SDP_SUCCESS)
            break;

        // if data was returned, process it
        if(jdata != NULL)
        {
            log_msg(LOG_DEBUG, "sdp_ctrl_client_check_inbox returned management data, processing");

            rv = process_data_msg(opts, action, jdata);

            if(jdata != NULL && json_object_get_type(jdata) != json_type_null)
            {
                json_object_put(jdata);
                jdata = NULL;
            }

            if(rv == FWKNOPD_SUCCESS)
            {
                if(action == CTRL_ACTION_ACCESS_REFRESH)
                    got_access_data = 1;
                else if(action == CTRL_ACTION_SERVICE_REFRESH)
                    got_service_data = 1;
            }

            if(got_access_data && got_service_data)
                break;
        }

        // reset action
        action = INVALID_CTRL_ACTION;

        // do not begin sending requests until controller is ready
        if( !(sdp_ctrl_client_controller_status(opts->ctrl_client)) )
            continue;

        // if new connection or just time, update credentials
        if((rv = sdp_ctrl_client_consider_cred_update(opts->ctrl_client)) != SDP_SUCCESS)
            break;

        // if built for remote gateway, handle service updates
        if((rv = sdp_ctrl_client_consider_service_refresh(opts->ctrl_client)) != SDP_SUCCESS)
            break;

        // if built for remote gateway, handle access updates
        if((rv = sdp_ctrl_client_consider_access_refresh(opts->ctrl_client)) != SDP_SUCCESS)
            break;

        // watch the time
        if( (time(NULL) > stop_time) )
        {
            // if we timed out, then we did not get the management data we needed
            log_msg(LOG_ERR, "Failed to get service and/or access data from controller.");
            return FWKNOPD_ERROR_CTRL_COM;
        }

        sleep(1);
    }

    return rv;
}



void *control_client_thread_func(void *arg)
{
    int rv = FWKNOPD_SUCCESS;
    int action = INVALID_CTRL_ACTION;
    int send_open_conn_report = 0;
    json_object *jdata = NULL;
    fko_srv_options_t *opts = (fko_srv_options_t*)arg;

    if(opts == NULL ||
       opts->ctrl_client == NULL ||
       opts->ctrl_client->initialized != 1)
    {
        log_msg(LOG_ERR, "Attempted to start SDP control client "
                "thread without proper initializations. Aborting.");

        // send kill signal for main thread to catch and exit safely
        kill(getpid(), SIGTERM);
        return NULL;
    }

    // If connection tracking is enabled, initialize it
    if(strncmp(opts->config[CONF_DISABLE_CONNECTION_TRACKING], "N", 1) == 0)
    {
		if( (rv = init_connection_tracker(opts)) != FWKNOPD_SUCCESS)
		{
			log_msg(LOG_ERR,
				"[*] Failed to initialize connection tracking."
			);
			// send kill signal for main thread to catch and exit safely
			kill(getpid(), SIGTERM);
			return NULL;
		}
    }

    while(1)
    {
        // connect if necessary
        if(sdp_ctrl_client_connection_status(opts->ctrl_client) == SDP_COM_DISCONNECTED)
        {
            if((rv = sdp_ctrl_client_connect(opts->ctrl_client)) != SDP_SUCCESS)
            {
                break;
            }

            // after any loss of connection, the controller marks all of the
            // gateway's connections as closed, so we need to resend just
            // the open connections if there are any as soon as possible
            send_open_conn_report = 1;
        }

        // check for incoming messages
        if((rv = sdp_ctrl_client_check_inbox(opts->ctrl_client, &action, (void**)&jdata)) != SDP_SUCCESS)
            break;

        // if data was returned, process it
        if(jdata != NULL)
        {
            log_msg(LOG_DEBUG, "sdp_ctrl_client_check_inbox returned access data, processing");

            rv = handle_data_msg(opts, action, jdata);

            if(jdata != NULL && json_object_get_type(jdata) != json_type_null)
            {
                json_object_put(jdata);
                jdata = NULL;
            }

            if(rv != FWKNOPD_SUCCESS)
                break;

            if(strncmp(opts->config[CONF_DISABLE_CONNECTION_TRACKING], "N", 1) == 0)
            {
                if((rv = validate_connections(opts)) != FWKNOPD_SUCCESS)
                    break;
            }
        }

        // do not begin sending requests until controller is ready
        if( !(sdp_ctrl_client_controller_status(opts->ctrl_client)) )
            continue;

        // after any loss of connection, the controller marks all of the
        // gateway's connections as closed, so we need to resend just
        // the open connections if there are any as soon as possible
        if(send_open_conn_report)
        {
            send_open_conn_report = 0;

            if((rv = report_open_connections(opts)) != FWKNOPD_SUCCESS)
            {
                break;
            }
        }

        // if new connection or just time, update credentials
        if((rv = sdp_ctrl_client_consider_cred_update(opts->ctrl_client)) != SDP_SUCCESS)
            break;

        // if built for remote gateway, handle service updates
        if((rv = sdp_ctrl_client_consider_service_refresh(opts->ctrl_client)) != SDP_SUCCESS)
            break;

        // if built for remote gateway, handle access updates
        if((rv = sdp_ctrl_client_consider_access_refresh(opts->ctrl_client)) != SDP_SUCCESS)
            break;

        // is a keep alive due
        if((rv = sdp_ctrl_client_consider_keep_alive(opts->ctrl_client)) != SDP_SUCCESS)
            break;

        // If connection tracking is enabled
        if(strncmp(opts->config[CONF_DISABLE_CONNECTION_TRACKING], "N", 1) == 0)
        {
            if((rv = update_connections(opts)) != FWKNOPD_SUCCESS)
                break;

            if((rv = consider_reporting_connections(opts)) != FWKNOPD_SUCCESS)
                break;
        }

        sleep(1);
    }

    // send kill signal for main thread to catch and exit safely
    kill(getpid(), SIGTERM);

    return NULL;
}


