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

#include "dhcp.h"

int sync_datastores(ctx_t *ctx);
int load_startup_datastore(ctx_t *ctx);
int sysrepo_to_uci(ctx_t *ctx, sr_change_oper_t op, sr_val_t *old_val, sr_val_t *new_val, sr_notif_event_t event);

int fill_dhcp_v6_data(ctx_t *ctx, char *xpath, sr_val_t **values, size_t *values_cnt);
int fill_dhcp_v4_data(ctx_t *ctx, char *xpath, sr_val_t **values, size_t *values_cnt);

typedef struct ubus_ctx_s {
	ctx_t *ctx;
	sr_val_t **values;
	size_t *values_cnt;
} ubus_ctx_t;

#endif /* PARSE_H */
