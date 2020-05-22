#include <stdlib.h>

#include <uci.h>

#include "srpu.h"

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