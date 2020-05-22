/**
 * @file srpu.h
 * @author Luka Paulic <luka.paulic@sartura.hr>
 * @brief header file for srpu.c.
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

typedef struct {
	const char *xpath_template;
	const char *uci_path_template;
} srpu_uci_xpath_uci_template_map_t;

typedef char *(srpu_transform_uci_data_cb)(const char *uci_value, void *private_data);

int srpu_init(void);
void srpu_cleanup(void);

int srpu_uci_path_list_get(const char *uci_config, const char **uci_section_list, size_t uci_section_list_size, const char ***uci_path_list, size_t *uci_path_list_size);

int srpu_xpath_to_uci_path_convert(const char *xpath, srpu_uci_xpath_uci_template_map_t xpath_uci_template_map, char **uci_path);
int srpu_uci_to_xpath_path_convert(const char *uci_path, srpu_uci_xpath_uci_template_map_t uci_xpath_template_map, char **xpath);

int srpu_uci_section_create(const char *uci_path);
int srpu_uci_section_delete(const char *uci_path);
int srpu_uci_option_set(const char *uci_path, const char *uci_value);
int srpu_uci_option_remove(const char *uci_path);
int srpu_uci_list_set(const char *uci_path, const char *uci_value_old, const char *uci_value_new);
int srpu_uci_list_remove(const char *uci_path, const char *uci_value);

#endif /* SRPU_H_ONCE */