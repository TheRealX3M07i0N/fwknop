/*
 * service.h
 *
 *  Created on: Nov 26, 2016
 *      Author: Daniel Bailey
 */

#ifndef SERVICE_H_
#define SERVICE_H_

#define PROTO_TCP   6
#define PROTO_UDP   17

int create_service_table(fko_srv_options_t *opts);
void destroy_service_table(fko_srv_options_t *opts);
int process_service_msg(fko_srv_options_t *opts, int action, json_object *jdata);
int get_service_data(fko_srv_options_t *opts, uint32_t service_id, service_data_t**r_service_data);
void free_service_data_list(service_data_list_t *service_data_list);
int get_service_data_list(fko_srv_options_t *opts, char *service_str, service_data_list_t **r_service_data_list);
int get_service_id_by_details(fko_srv_options_t *opts, char *protocol, int port, char *nat_ip, int nat_port, uint32_t *r_id);
void dump_service_list(fko_srv_options_t *opts);

#endif /* SERVICE_H_ */
