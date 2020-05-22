#include <stdlib.h>
#include <string.h>

#include <uci.h>

#include "srpu.h"

int srpu_init(void)
{
	// TODO: implement

	return 0;
}

void srpu_cleanup(void)
{
	// TODO: implement
}

int srpu_uci_path_list_get(const char *uci_config, const char **uci_section_list, size_t uci_section_list_size, const char ***uci_path_list, size_t *uci_path_list_size)
{
	if (uci_config == NULL) {
		return -1;
	}

	if (uci_section_list == NULL) {
		return -1;
	}

	if (uci_path_list == NULL) {
		return -1;
	}

	// TODO: implement

	*uci_path_list = NULL;
	*uci_path_list_size = 0;

	return 0;
}

int srpu_xpath_to_uci_path_convert(const char *xpath, srpu_uci_xpath_uci_template_map_t *xpath_uci_template_map, char **uci_path)
{
	if (xpath == NULL) {
		return -1;
	}

	if (xpath_uci_template_map == NULL) {
		return -1;
	}

	if (uci_path == NULL) {
		return -1;
	}

	// TODO: implement

	*uci_path = strdup("uci dummy data");

	return 0;
}

int srpu_uci_to_xpath_path_convert(const char *uci_path, srpu_uci_xpath_uci_template_map_t *uci_xpath_template_map, char **xpath)
{
	if (uci_path == NULL) {
		return -1;
	}

	if (uci_xpath_template_map == NULL) {
		return -1;
	}

	if (xpath == NULL) {
		return -1;
	}

	// TODO: implement

	*xpath = strdup("xpath dummy data");

	return 0;
}

int srpu_transfor_sysrepo_data_cb_get(const char *xpath, srpu_uci_xpath_uci_template_map_t *xpath_uci_template_map, srpu_transform_data_cb *transform_sysrepo_data_cb)
{
	if (xpath == NULL) {
		return -1;
	}

	if (xpath_uci_template_map == NULL) {
		return -1;
	}

	*transform_sysrepo_data_cb = NULL;

	return 0;
}

int srpu_transfor_uci_data_cb_get(const char *uci, srpu_uci_xpath_uci_template_map_t *uci_xpath_template_map, srpu_transform_data_cb *transform_uci_data_cb)
{
	if (uci == NULL) {
		return -1;
	}

	if (uci_xpath_template_map == NULL) {
		return -1;
	}

	*transform_uci_data_cb = NULL;

	return 0;
}

int srpu_uci_section_create(const char *uci_path)
{
	if (uci_path == NULL) {
		return -1;
	}

	// TODO: implement

	return 0;
}

int srpu_uci_section_delete(const char *uci_path)
{
	if (uci_path == NULL) {
		return -1;
	}

	// TODO: implement

	return 0;
}

int srpu_uci_option_set(const char *uci_path, const char *uci_value, srpu_transform_data_cb transform_sysrepo_data_cb)
{
	if (uci_path == NULL) {
		return -1;
	}

	if (uci_value == NULL) {
		return -1;
	}

	// TODO: implement

	return 0;
}

int srpu_uci_option_get(const char *uci_path, srpu_transform_data_cb transform_uci_data_cb, char **uci_value)
{
	if (uci_path == NULL) {
		return -1;
	}

	if (uci_value == NULL) {
		return -1;
	}

	// TODO: implement

	*uci_value = strdup("dummy");

	return 0;
}

int srpu_uci_option_remove(const char *uci_path)
{
	if (uci_path == NULL) {
		return -1;
	}

	// TODO: implement

	return 0;
}

int srpu_uci_list_set(const char *uci_path, const char *uci_value, srpu_transform_data_cb transform_sysrepo_data_cb)
{
	if (uci_path == NULL) {
		return -1;
	}

	if (uci_value == NULL) {
		return -1;
	}

	// TODO: implement

	return 0;
}

int srpu_uci_list_get(const char *uci_path, srpu_transform_data_cb transform_uci_data_cb, char **uci_value_list, size_t *uci_value_list_size)
{
	if (uci_path == NULL) {
		return -1;
	}

	*uci_value_list = NULL;
	*uci_value_list_size = 0;

	// TODO: implement

	return 0;
}

int srpu_uci_list_remove(const char *uci_path, const char *uci_value)
{
	if (uci_path == NULL) {
		return -1;
	}

	if (uci_value == NULL) {
		return -1;
	}

	// TODO: implement

	return 0;
}
