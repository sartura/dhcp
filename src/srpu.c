#include <stdio.h>

#include <stdlib.h>
#include <string.h>

#include <uci.h>

#include "srpu.h"
#include "utils/memory.h"

static struct uci_context *srpu_uci_context;

int srpu_init(void)
{
	int error = SRPU_ERR_OK;

	srpu_uci_context = uci_alloc_context();
	if (srpu_uci_context == NULL) {
		return SRPU_ERR_UCI;
	}

	error = uci_set_confdir(srpu_uci_context, "/opt/sysrepofs/etc/config"); // TODO: in make configurable in CMake
	if (error) {
		srpu_cleanup();
		return SRPU_ERR_UCI;
	}

	return SRPU_ERR_OK;
}

void srpu_cleanup(void)
{
	if (srpu_uci_context) {
		uci_free_context(srpu_uci_context);
		srpu_uci_context = NULL;
	}
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

int srpu_uci_path_list_get(const char *uci_config, const char **uci_section_list, size_t uci_section_list_size, char ***uci_path_list, size_t *uci_path_list_size)
{
	int error = SRPU_ERR_OK;
	struct uci_package *package = NULL;
	struct uci_element *element_section = NULL;
	struct uci_section *section = NULL;
	char *section_name = NULL;
	size_t section_name_size = 0;
	struct uci_element *element_option = NULL;
	struct uci_option *option = NULL;
	char **uci_path_list_tmp = NULL;
	size_t uci_path_list_size_tmp = 0;
	size_t uci_path_size = 0;
	size_t anonymous_section_index = 0;
	bool anonymous_section_exists = 0;
	size_t anonymous_section_list_size = 0;
	struct anonymous_section {
		char *type;
		size_t index;
	} *anonymous_section_list = NULL;

	if (uci_config == NULL) {
		return SRPU_ERR_ARGUMENT;
	}

	if (uci_section_list == NULL) {
		return SRPU_ERR_ARGUMENT;
	}

	if (uci_path_list == NULL) {
		return SRPU_ERR_ARGUMENT;
	}

	error = uci_load(srpu_uci_context, uci_config, &package);
	if (error) {
		return SRPU_ERR_UCI;
	}

	uci_foreach_element(&package->sections, element_section)
	{
		section = uci_to_section(element_section);
		for (size_t i = 0; i < uci_section_list_size; i++) {
			if (strcmp(section->type, uci_section_list[i]) == 0) {
				if (section->anonymous) { // hande name conversion from cfgXXXXX to @section_type[index] for anonymous sections
					anonymous_section_index = 0;
					anonymous_section_exists = false;
					for (size_t j = 0; j < anonymous_section_list_size; j++) {
						if (strcmp(anonymous_section_list[j].type, section->type) == 0) { // get the next index for the anonymous section
							anonymous_section_index = anonymous_section_list[j].index++;
							anonymous_section_exists = true;
						}
					}

					if (anonymous_section_exists == false) { // add the anonymous section to the list if first occurrence
						anonymous_section_list = xrealloc(anonymous_section_list, (anonymous_section_list_size + 1) * sizeof(struct anonymous_section));
						anonymous_section_list[anonymous_section_list_size].type = strdup(section->type);
						anonymous_section_list[anonymous_section_list_size].index = 0;
						anonymous_section_index = anonymous_section_list[anonymous_section_list_size].index++;
						anonymous_section_list_size++;
					}

					section_name_size = strlen(section->type) + 1 + 2 + 20 + 1;
					section_name = xmalloc(section_name_size);
					snprintf(section_name, section_name_size, "@%s[%zu]", section->type, anonymous_section_index);
				} else {
					section_name = xstrdup(section->e.name);
				}

				uci_foreach_element(&section->options, element_option)
				{
					option = uci_to_option(element_option);

					uci_path_list_tmp = xrealloc(uci_path_list_tmp, (uci_path_list_size_tmp + 1) * sizeof(char *));

					uci_path_size = strlen(uci_config) + 1 + strlen(section_name) + 1 + strlen(option->e.name) + 1;
					uci_path_list_tmp[uci_path_list_size_tmp] = xmalloc(uci_path_size);
					snprintf(uci_path_list_tmp[uci_path_list_size_tmp], uci_path_size, "%s.%s.%s", uci_config, section_name, option->e.name);

					printf("%s\n", uci_path_list_tmp[uci_path_list_size_tmp]);

					uci_path_list_size_tmp++;
				}

				FREE_SAFE(section_name);

				break;
			}
		}
	}

	*uci_path_list = uci_path_list_tmp;
	*uci_path_list_size = uci_path_list_size_tmp;

	for (size_t i = 0; i < anonymous_section_list_size; i++) {
		FREE_SAFE(anonymous_section_list[i].type);
	}

	FREE_SAFE(anonymous_section_list);

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

int srpu_uci_element_value_get(const char *uci_path, srpu_transform_data_cb transform_uci_data_cb, char ***uci_value_list, size_t *uci_value_list_size)
{
	if (uci_path == NULL) {
		return SRPU_ERR_ARGUMENT;
	}

	*uci_value_list = NULL;
	*uci_value_list_size = 0;

	// TODO: implement

	return SRPU_ERR_OK;
}
