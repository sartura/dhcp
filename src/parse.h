/**
 * @file parse.h
 * @author Mislav Novakovic <mislav.novakovic@sartur.hr>
 * @brief header file for parse.c.
 *
 * @copyright
 * Copyright (C) 2017 Deutsche Telekom AG.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef PARSE_H
#define PARSE_H

#include <sr_uci.h>

int sync_datastores(sr_ctx_t *ctx);
int fill_dhcp_v6_data(sr_ctx_t *ctx, char *xpath, sr_val_t **values,
                      size_t *values_cnt);
int fill_dhcp_v4_data(sr_ctx_t *ctx, char *xpath, sr_val_t **values,
                      size_t *values_cnt);

int sr_list_option_cb(sr_ctx_t *, sr_change_oper_t, sr_val_t *, sr_val_t *,
                      char *, char *);

int sr_leasetime_cb(sr_ctx_t *, sr_change_oper_t, sr_val_t *, sr_val_t *,
                    char *, char *);
int uci_leasetime_cb(sr_ctx_t *, char *, char *, sr_edit_flag_t, void *);

int sr_stop_cb(sr_ctx_t *, sr_change_oper_t, sr_val_t *, sr_val_t *, char *,
               char *);
int uci_stop_cb(sr_ctx_t *, char *, char *, sr_edit_flag_t, void *);

int uci_dhcpv6_boolean_cb(sr_ctx_t *, char *, char *, sr_edit_flag_t, void *);
int uci_dhcpv6_option_cb(sr_ctx_t *, char *, char *, sr_edit_flag_t, void *);

extern sr_uci_mapping_t table_sr_uci[];

#endif /* PARSE_H */
