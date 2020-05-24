#include <stdlib.h>
#include <string.h>

#include <uci.h>

#include "srpu.h"

int srpu_init(void)
{
	// TODO: implement

	return SRPU_ERR_OK;
}

void srpu_cleanup(void)
{
	// TODO: implement
}

const char *srpu_error_description_get(srpu_error_e error)
{
	switch (error) {
#define XM(ENUM, CODE, DESCRIPTION) \
	case ENUM:                      \
		return DESCRIPTION;

		SRPU_ERROR_TABLE
#undef XM

		default:
			return "unknown error code";
	}
}

int srpu_uci_path_list_get(const char *uci_config, const char **uci_section_list, size_t uci_section_list_size, const char ***uci_path_list, size_t *uci_path_list_size)
{
	if (uci_config == NULL) {
		return SRPU_ERR_ARGUMENT;
	}

	if (uci_section_list == NULL) {
		return SRPU_ERR_ARGUMENT;
	}

	if (uci_path_list == NULL) {
		return SRPU_ERR_ARGUMENT;
	}

	// TODO: implement

	*uci_path_list = NULL;
	*uci_path_list_size = 0;

	return SRPU_ERR_OK;
}

int srpu_xpath_to_uci_path_convert(const char *xpath, srpu_uci_xpath_uci_template_map_t *xpath_uci_template_map, char **uci_path)
{
	if (xpath == NULL) {
		return SRPU_ERR_ARGUMENT;
	}

	if (xpath_uci_template_map == NULL) {
		return SRPU_ERR_ARGUMENT;
	}

	if (uci_path == NULL) {
		return SRPU_ERR_ARGUMENT;
	}

	// TODO: implement
	// special error if not found in table

	*uci_path = strdup("uci dummy data");

	return SRPU_ERR_OK;
}

int srpu_uci_to_xpath_path_convert(const char *uci_path, srpu_uci_xpath_uci_template_map_t *uci_xpath_template_map, char **xpath)
{
	if (uci_path == NULL) {
		return SRPU_ERR_ARGUMENT;
	}

	if (uci_xpath_template_map == NULL) {
		return SRPU_ERR_ARGUMENT;
	}

	if (xpath == NULL) {
		return SRPU_ERR_ARGUMENT;
	}

	// TODO: implement

	*xpath = strdup("xpath dummy data");

	return SRPU_ERR_OK;
}

int srpu_transfor_sysrepo_data_cb_get(const char *xpath, srpu_uci_xpath_uci_template_map_t *xpath_uci_template_map, srpu_transform_data_cb *transform_sysrepo_data_cb)
{
	if (xpath == NULL) {
		return SRPU_ERR_ARGUMENT;
	}

	if (xpath_uci_template_map == NULL) {
		return SRPU_ERR_ARGUMENT;
	}

	*transform_sysrepo_data_cb = NULL;

	return SRPU_ERR_OK;
}

int srpu_transfor_uci_data_cb_get(const char *uci, srpu_uci_xpath_uci_template_map_t *uci_xpath_template_map, srpu_transform_data_cb *transform_uci_data_cb)
{
	if (uci == NULL) {
		return SRPU_ERR_ARGUMENT;
	}

	if (uci_xpath_template_map == NULL) {
		return SRPU_ERR_ARGUMENT;
	}

	*transform_uci_data_cb = NULL;

	return SRPU_ERR_OK;
}

int srpu_uci_section_create(const char *uci_path)
{
	if (uci_path == NULL) {
		return SRPU_ERR_ARGUMENT;
	}

	// TODO: implement

	return SRPU_ERR_OK;
}

int srpu_uci_section_delete(const char *uci_path)
{
	if (uci_path == NULL) {
		return SRPU_ERR_ARGUMENT;
	}

	// TODO: implement

	return SRPU_ERR_OK;
}

int srpu_uci_option_set(const char *uci_path, const char *uci_value, srpu_transform_data_cb transform_sysrepo_data_cb)
{
	if (uci_path == NULL) {
		return SRPU_ERR_ARGUMENT;
	}

	if (uci_value == NULL) {
		return SRPU_ERR_ARGUMENT;
	}

	// TODO: implement

	return SRPU_ERR_OK;
}

int srpu_uci_option_get(const char *uci_path, srpu_transform_data_cb transform_uci_data_cb, char **uci_value)
{
	if (uci_path == NULL) {
		return SRPU_ERR_ARGUMENT;
	}

	if (uci_value == NULL) {
		return SRPU_ERR_ARGUMENT;
	}

	// TODO: implement

	*uci_value = strdup("dummy");

	return SRPU_ERR_OK;
}

int srpu_uci_option_remove(const char *uci_path)
{
	if (uci_path == NULL) {
		return SRPU_ERR_ARGUMENT;
	}

	// TODO: implement

	return SRPU_ERR_OK;
}

int srpu_uci_list_set(const char *uci_path, const char *uci_value, srpu_transform_data_cb transform_sysrepo_data_cb)
{
	if (uci_path == NULL) {
		return SRPU_ERR_ARGUMENT;
	}

	if (uci_value == NULL) {
		return SRPU_ERR_ARGUMENT;
	}

	// TODO: implement

	return SRPU_ERR_OK;
}

int srpu_uci_list_get(const char *uci_path, srpu_transform_data_cb transform_uci_data_cb, char **uci_value_list, size_t *uci_value_list_size)
{
	if (uci_path == NULL) {
		return SRPU_ERR_ARGUMENT;
	}

	*uci_value_list = NULL;
	*uci_value_list_size = 0;

	// TODO: implement

	return SRPU_ERR_OK;
}

int srpu_uci_list_remove(const char *uci_path, const char *uci_value)
{
	if (uci_path == NULL) {
		return SRPU_ERR_ARGUMENT;
	}

	if (uci_value == NULL) {
		return SRPU_ERR_ARGUMENT;
	}

	// TODO: implement

	return SRPU_ERR_OK;
}
