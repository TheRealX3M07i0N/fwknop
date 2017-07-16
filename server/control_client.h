/*
 * control_client.h
 *
 *  Created on: Oct 20, 2016
 *      Author: Daniel Bailey
 */

#ifndef SERVER_CONTROL_CLIENT_H_
#define SERVER_CONTROL_CLIENT_H_

int get_management_data_from_controller(fko_srv_options_t *opts);
void *control_client_thread_func(void *arg);

#endif /* SERVER_CONTROL_CLIENT_H_ */
