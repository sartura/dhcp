#include <inttypes.h>
#include <string.h>

#include <uci.h>

#include "transform_data.h"
#include "utils/memory.h"

char *transform_data_boolean_to_zero_one_transform(const char *value, void *private_data)
{
	if (strcmp(value, "true") == 0) {
		return xstrdup("1");
	} else {
		return xstrdup("0");
	}
}

char *transform_data_zero_one_to_boolean_transform(const char *value, void *private_data)
{
	if (strcmp(value, "1") == 0) {
		return xstrdup("true");
	} else {
		return xstrdup("false");
	}
}

char *transform_data_boolean_to_zero_one_negated_transform(const char *value, void *private_data)
{
	if (strcmp(value, "true") == 0) {
		return xstrdup("0");
	} else {
		return xstrdup("1");
	}
}

char *transform_data_zero_one_to_boolean_negated_transform(const char *value, void *private_data)
{
	if (strcmp(value, "1") == 0) {
		return xstrdup("false");
	} else {
		return xstrdup("true");
	}
}

char *transform_data_limit_to_stop_transform(const char *value, void *private_data)
{
	int error = 0;
	char *uci_section_name = (char *) private_data;
	size_t uci_path_size = 0;
	char *uci_path = NULL;
	struct uci_context *uci_context = NULL;
	struct uci_ptr uci_ptr = {0};
	char *start = NULL;
	uint32_t uci_ip_limit = 0;
	uint32_t uci_ip_start = 0;
	uint32_t stop = 0;
	char sysrepo_stop[20 + 1] = {0};

	if (uci_section_name == NULL) {
		return NULL;
	}

	uci_path_size = strlen("dhcp.") + strlen(uci_section_name) + strlen(".start") + 1;
	uci_path = xcalloc(1, uci_path_size);
	snprintf(uci_path, uci_path_size, "dhcp.%s.start", uci_section_name);

	uci_context = uci_alloc_context();
	if (uci_context == NULL) {
		goto out;
	}

	error = uci_lookup_ptr(uci_context, &uci_ptr, uci_path, true);
	if (error && error != UCI_ERR_NOTFOUND) {
		goto out;
	} else if (error == UCI_ERR_NOTFOUND || (uci_ptr.flags & UCI_LOOKUP_COMPLETE) == 0) {
		start = "100";
	} else {
		start = uci_ptr.o->v.string;
	}

	sscanf(value, "%" PRIu32, &uci_ip_limit);
	sscanf(start, "%" PRIu32, &uci_ip_start);

	stop = uci_ip_limit + uci_ip_start - 1;
	snprintf(sysrepo_stop, sizeof(sysrepo_stop), "%" PRIu32, stop);

out:
	FREE_SAFE(uci_path);

	if (uci_context) {
		uci_free_context(uci_context);
	}

	return sysrepo_stop[0] ? xstrdup(sysrepo_stop) : NULL;
}

char *transform_data_stop_to_limit_transform(const char *value, void *private_data)
{
	int error = 0;
	leasetime_data_t *leasetime_data = (leasetime_data_t *) private_data;
	size_t xpath_size = 0;
	char *xpath = NULL;
	struct lyd_node *node = NULL;
	struct lyd_node_leaf_list *start_node = NULL;
	uint32_t sysrepo_stop = 0;
	uint32_t limit = 0;
	char uci_limit[20 + 1] = {0};

	if (leasetime_data == NULL) {
		return NULL;
	}

	if (leasetime_data->uci_section_name == NULL) {
		return NULL;
	}

	if (leasetime_data->sr_session == NULL) {
		return NULL;
	}

	xpath_size = strlen("/terastream-dhcp:dhcp-servers/dhcp-server[name='") + strlen(leasetime_data->uci_section_name) + strlen("']/start") + 1;
	xpath = xcalloc(1, xpath_size);
	snprintf(xpath, xpath_size, "/terastream-dhcp:dhcp-servers/dhcp-server[name='%s']/start", leasetime_data->uci_section_name);

	error = sr_get_data(leasetime_data->sr_session, xpath, 0, 0, 0, &node);
	if (error) {
		goto out;
	}

	sscanf(value, "%" PRIu32, &sysrepo_stop);
	start_node = (struct lyd_node_leaf_list *) node->child->child->next;

	limit = sysrepo_stop - start_node->value.uint32 + 1;
	snprintf(uci_limit, sizeof(uci_limit), "%" PRIu32, limit);

out:
	FREE_SAFE(xpath);
	lyd_free(node);

	return uci_limit[0] ? xstrdup(uci_limit) : NULL;
}

char *transform_data_seconds_to_leasetime_transform(const char *value, void *private_data)
{
	size_t leasetime_size = 0;
	char *leasetime = NULL;

	leasetime_size = strlen(value) + 1 + 1;
	leasetime = xcalloc(1, leasetime_size);
	snprintf(leasetime, leasetime_size, "%ss", value);

	return leasetime;
}

char *transform_data_leasetime_to_seconds_transform(const char *value, void *private_data)
{
	double leasetime = 0.0;
	char seconds[20 + 1] = {0};

	if (strcmp(value, "infinite") == 0) {
		leasetime = (double) UINT32_MAX;
	} else {
		sscanf(value, "%lf", &leasetime);
	}

	if (strchr(value, 's')) {
		leasetime *= 1;
	} else if (strchr(value, 'm')) {
		leasetime *= 60;
	} else if (strchr(value, 'h')) {
		leasetime *= 3600;
	} else if (strchr(value, 'd')) {
		leasetime *= 24 * 3600;
	} else if (strchr(value, 'w')) {
		leasetime *= 7 * 24 * 3600;
	} else {
		return NULL;
	}

	if (leasetime < 60.0) {
		leasetime = 60.0;
	}

	snprintf(seconds, sizeof(seconds), "%lf", leasetime);

	return xstrdup(seconds);
}

char *transform_data_dhcpv6_interface_only_transform(const char *value, void *private_data)
{
	int error = 0;
	char *dhcpv6_interface_data = NULL;
	char *uci_section_name = (char *) private_data;
	size_t uci_path_size = 0;
	char *uci_path = NULL;
	struct uci_context *uci_context = NULL;
	struct uci_ptr uci_ptr = {0};

	if (uci_section_name == NULL) {
		return NULL;
	}

	uci_path_size = strlen("network.") + strlen(uci_section_name) + strlen(".proto") + 1;
	uci_path = xcalloc(1, uci_path_size);
	snprintf(uci_path, uci_path_size, "network.%s.proto", uci_section_name);

	uci_context = uci_alloc_context();
	if (uci_context == NULL) {
		goto out;
	}

	error = uci_lookup_ptr(uci_context, &uci_ptr, uci_path, true);
	if (error || (uci_ptr.flags * UCI_LOOKUP_COMPLETE) == 0) {
		goto out;
	}

	dhcpv6_interface_data = xstrdup(uci_ptr.o->v.string);

out:
	FREE_SAFE(uci_path);

	if (uci_context) {
		uci_free_context(uci_context);
	}

	return dhcpv6_interface_data ? dhcpv6_interface_data : xstrdup("");
}

char *transform_data_dhcpv6_interface_only_boolean_transform(const char *value, void *private_data)
{
	int error = 0;
	char *dhcpv6_interface_data = NULL;
	char *uci_section_name = (char *) private_data;
	size_t uci_path_size = 0;
	char *uci_path = NULL;
	struct uci_context *uci_context = NULL;
	struct uci_ptr uci_ptr = {0};

	if (uci_section_name == NULL) {
		return NULL;
	}

	uci_path_size = strlen("network.") + strlen(uci_section_name) + strlen(".proto") + 1;
	uci_path = xcalloc(1, uci_path_size);
	snprintf(uci_path, uci_path_size, "network.%s.proto", uci_section_name);

	uci_context = uci_alloc_context();
	if (uci_context == NULL) {
		goto out;
	}

	error = uci_lookup_ptr(uci_context, &uci_ptr, uci_path, true);
	if (error || (uci_ptr.flags * UCI_LOOKUP_COMPLETE) == 0) {
		dhcpv6_interface_data = "0";
	} else {
		dhcpv6_interface_data = uci_ptr.o->v.string;
	}

out:
	FREE_SAFE(uci_path);

	if (uci_context) {
		uci_free_context(uci_context);
	}

	return transform_data_zero_one_to_boolean_transform(dhcpv6_interface_data, NULL);
}
