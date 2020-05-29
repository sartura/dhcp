/**
 * @file srpu.h
 * @author Luka Paulic <luka.paulic@sartura.hr>
 * @brief srpu - sysrepo parse uci header file for setting/getting data to/from UCI from/to sysrepo.
 *
 * @copyright
 * Copyright (C) 2020 Deutsche Telekom AG.
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

#ifndef SRPU_H_ONCE
#define SRPU_H_ONCE

#include <stdlib.h>

typedef enum {
#define SRPU_ERROR_TABLE                              \
	XM(SRPU_ERR_OK, 0, "Success")                     \
	XM(SRPU_ERR_ARGUMENT, -1, "Invalid argumnet")     \
	XM(SRPU_ERR_NOT_EXISTS, -2, "Entry not in table") \
	XM(SRPU_ERR_UCI, -3, "Internal UCI error")
#define XM(ENUM, CODE, DESCRIPTION) ENUM = CODE,
	SRPU_ERROR_TABLE
#undef XM
} srpu_error_e;

typedef char *(*srpu_transform_data_cb)(const char *uci_value, void *private_data);

typedef struct {
	const char *xpath_template;
	const char *uci_path_template;
	srpu_transform_data_cb transform_sysrepo_data_cb;
	srpu_transform_data_cb transform_uci_data_cb;
} srpu_uci_xpath_uci_template_map_t;

int srpu_init(void);
void srpu_cleanup(void);

const char *srpu_error_description_get(srpu_error_e error);

int srpu_uci_path_list_get(const char *uci_config, const char **uci_section_list, size_t uci_section_list_size, char ***uci_path_list, size_t *uci_path_list_size);

int srpu_xpath_to_uci_path_convert(const char *xpath, srpu_uci_xpath_uci_template_map_t *xpath_uci_template_map, char **uci_path);
int srpu_uci_to_xpath_path_convert(const char *uci_path, srpu_uci_xpath_uci_template_map_t *uci_xpath_template_map, char **xpath);

int srpu_transfor_sysrepo_data_cb_get(const char *xpath, srpu_uci_xpath_uci_template_map_t *xpath_uci_template_map, srpu_transform_data_cb *transform_sysrepo_data_cb);
int srpu_transfor_uci_data_cb_get(const char *uci, srpu_uci_xpath_uci_template_map_t *uci_xpath_template_map, srpu_transform_data_cb *transform_uci_data_cb);

int srpu_uci_section_create(const char *uci_path);
int srpu_uci_section_delete(const char *uci_path);
int srpu_uci_option_set(const char *uci_path, const char *uci_value, srpu_transform_data_cb transform_sysrepo_data_cb);
int srpu_uci_option_remove(const char *uci_path);
int srpu_uci_list_set(const char *uci_path, const char *uci_value, srpu_transform_data_cb transform_sysrepo_data_cb);
int srpu_uci_list_remove(const char *uci_path, const char *uci_value);
int srpu_uci_element_value_get(const char *uci_path, srpu_transform_data_cb transform_uci_data_cb, char ***uci_value_list, size_t *uci_value_list_size);

#endif /* SRPU_H_ONCE */
