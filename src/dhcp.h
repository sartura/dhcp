/**
 * @file dhcp.h
 * @author Mislav Novakovic <mislav.novakovic@sartur.hr>
 * @brief header file for dhcp.c.
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

#ifndef DHCP_H
#define DHCP_H

#include <sysrepo.h>
#include <sysrepo/plugins.h>

#include <uci.h>

#define MAX_UCI_PATH 64

typedef struct ctx_s {
	const char *yang_model;
	const char *config_file_dhcp;
	const char *config_file_network;
	struct uci_context *uctx;
	struct uci_package *package;
	sr_session_ctx_t *sess;
	sr_subscription_ctx_t *sub;
	sr_conn_ctx_t *startup_conn;
	sr_session_ctx_t *startup_sess;
} ctx_t;

#endif /* DHCP_H */
