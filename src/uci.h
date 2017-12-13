/**
 * @file uci.h
 * @author Mislav Novakovic <mislav.novakovic@sartur.hr>
 * @brief header file for uci.c.
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

#ifndef UCI_H
#define UCI_H

#include <uci.h>

#include "dhcp.h"

int uci_del(ctx_t *ctx, const char *uci);
int set_uci_section(ctx_t *ctx, char *uci);
int get_uci_item(struct uci_context *uctx, char *ucipath, char **value);
int set_uci_item(struct uci_context *uctx, char *ucipath, char *value);

#endif /* UCI_H */
