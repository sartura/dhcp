#include <inttypes.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <sysrepo.h>
#include <sysrepo/xpath.h>

#include "srpu.h"

#define ARRAY_SIZE(X) (sizeof((X)) / sizeof((X)[0]))

#define DHCP_YANG_MODEL "terastream-dhcp"
#define SYSREPOCFG_EMPTY_CHECK_COMMAND "sysrepocfg -X -d running -m " DHCP_YANG_MODEL

int dhcp_plugin_init_cb(sr_session_ctx_t *session, void **private_data);
void dhcp_plugin_cleanup_cb(sr_session_ctx_t *session, void *private_data);

static int dhcp_module_change_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, sr_event_t event, uint32_t request_id, void *private_data);

srpu_uci_xpath_uci_template_map_t dhcp_xpath_uci_uci_path_template_map[] = {
	{"/terastream-dhcp:dhcp-servers/dhcp-server[name='%s']/name", "dhcp.%s", NULL, NULL},
	{"/terastream-dhcp:dhcp-servers/dhcp-server[name='%s']/enable", "dhcp.%s.ignore", NULL, NULL},
	{"/terastream-dhcp:dhcp-servers/dhcp-server[name='%s']/interface", "dhcp.%s.interface", NULL, NULL},
	{"/terastream-dhcp:dhcp-servers/dhcp-server[name='%s']/start", "dhcp.%s.start", NULL, NULL},
	{"/terastream-dhcp:dhcp-servers/dhcp-server[name='%s']/stop", "dhcp.%s.limit", NULL, NULL},
	{"/terastream-dhcp:dhcp-servers/dhcp-server[name='%s']/leasetime", "dhcp.%s.leasetime", NULL, NULL},
	{"/terastream-dhcp:dhcp-servers/dhcp-server[name='%s']/dhcpv6", "dhcp.%s.dhcpv6", NULL, NULL},
	{"/terastream-dhcp:dhcp-servers/dhcp-server[name='%s']/ra", "dhcp.%s.ra", NULL, NULL},
	{"/terastream-dhcp:dhcp-servers/dhcp-server[name='%s']/ra_management", "dhcp.%s.ra_management", NULL, NULL},
	{"/terastream-dhcp:dhcp-servers/dhcp-server[name='%s']/sntp", "dhcp.%s.sntp", NULL, NULL},
	{"/terastream-dhcp:dhcp-servers/dhcp-server[name='%s']/dhcp_option", "dhcp.%s.dhcp_option", NULL, NULL},
	{"/terastream-dhcp:dhcp-servers/dhcp-server[name='%s']/dynamicdhcp", "dhcp.%s.dynamicdhcp", NULL, NULL},
	{"/terastream-dhcp:dhcp-servers/dhcp-server[name='%s']/force", "dhcp.%s.force", NULL, NULL},
	{"/terastream-dhcp:dhcp-servers/dhcp-server[name='%s']/ndp", "dhcp.%s.ndp", NULL, NULL},
	{"/terastream-dhcp:dhcp-servers/dhcp-server[name='%s']/master", "dhcp.%s.master", NULL, NULL},
	{"/terastream-dhcp:dhcp-servers/dhcp-server[name='%s']/networkid", "dhcp.%s.networkid", NULL, NULL},
};

static const char *dhcp_uci_sections[] = {"dhcp", "domain"};
static const char *network_uci_sections[] = {"network", "interface"};

static struct {
	const char *uci_file;
	const char **uci_section_list;
	size_t uci_section_list_size;
} dhcp_config_files[] = {
	{"dhcp", dhcp_uci_sections, ARRAY_SIZE(dhcp_uci_sections)},
	{"network", network_uci_sections, ARRAY_SIZE(network_uci_sections)},
};

int dhcp_plugin_init_cb(sr_session_ctx_t *session, void **private_data)
{
	int error = 0;
	sr_conn_ctx_t *connection = NULL;
	sr_session_ctx_t *startup_session = NULL;
	FILE *sysrepocfg_DS_empty_check = NULL;
	char **uci_path_list = NULL;
	size_t uci_path_list_size = 0;
	char *xpath = NULL;
	srpu_transform_data_cb transform_uci_data_cb = NULL;
	char **uci_value_list = NULL;
	size_t uci_value_list_size = 0;
	sr_subscription_ctx_t *subscrption = NULL;

	*private_data = NULL;

	SRP_LOG_INFMSG("start session to startup datastore");

	connection = sr_session_get_connection(session);
	error = sr_session_start(connection, SR_DS_STARTUP, &startup_session);
	if (error) {
		SRP_LOG_ERR("sr_session_start error (%d): %s", error, sr_strerror(error));
		goto error_out;
	}

	*private_data = startup_session;

	sysrepocfg_DS_empty_check = popen(SYSREPOCFG_EMPTY_CHECK_COMMAND, "r");
	if (sysrepocfg_DS_empty_check == NULL) {
		SRP_LOG_ERRMSG("popen error");
		error = -1;
		goto error_out;
	}

	if (fgetc(sysrepocfg_DS_empty_check) == EOF) { // running DS is empty load UCI data to Sysrepo running DS
		for (size_t i = 0; i < ARRAY_SIZE(dhcp_config_files); i++) {
			error = srpu_uci_path_list_get(dhcp_config_files[i].uci_file, dhcp_config_files[i].uci_section_list, dhcp_config_files[i].uci_section_list_size, &uci_path_list, &uci_path_list_size);
			if (error) {
				SRP_LOG_ERR("srpu_uci_path_list_get error (%d): %s", error, srpu_error_description_get(error));
				goto error_out;
			}

			for (size_t j = 0; j < uci_path_list_size; j++) {
				error = srpu_uci_to_xpath_path_convert(uci_path_list[j], dhcp_xpath_uci_uci_path_template_map, &xpath);
				if (error && error != SRPU_ERR_NOT_EXISTS) {
					SRP_LOG_ERR("srpu_uci_to_xpath_path_convert error (%d): %s", error, srpu_error_description_get(error));
					goto error_out;
				} else if (error == SRPU_ERR_NOT_EXISTS) {
					continue;
				}

				error = srpu_transfor_uci_data_cb_get(uci_path_list[j], dhcp_xpath_uci_uci_path_template_map, &transform_uci_data_cb);
				if (error) {
					SRP_LOG_ERR("srpu_transfor_uci_data_cb_get error (%d): %s", error, srpu_error_description_get(error));
					goto error_out;
				}

				error = srpu_uci_element_value_get(uci_path_list[j], transform_uci_data_cb, &uci_value_list, &uci_value_list_size);
				if (error) {
					SRP_LOG_ERR("srpu_uci_element_value_get error (%d): %s", error, srpu_error_description_get(error));
					goto error_out;
				}

				for (size_t k = 0; k < uci_value_list_size; k++) {
					error = sr_set_item_str(session, xpath, uci_value_list[k], NULL, SR_EDIT_DEFAULT);
					if (error) {
						SRP_LOG_ERR("sr_set_item_str error (%d): %s", error, sr_strerror(error));
						goto error_out;
					}
				}
			}
		}

		error = sr_apply_changes(session, 0, 0);
		if (error) {
			SRP_LOG_ERR("sr_apply_changes error (%d): %s", error, sr_strerror(error));
			goto error_out;
		}
	}

	SRP_LOG_INFMSG("subscribing to module change");

	error = sr_module_change_subscribe(session, DHCP_YANG_MODEL, "/" DHCP_YANG_MODEL ":*//*", dhcp_module_change_cb, *private_data, 0, SR_SUBSCR_DEFAULT, &subscrption);
	if (error) {
		SRP_LOG_ERR("sr_module_change_subscribe error (%d): %s", error, sr_strerror(error));
		goto error_out;
	}

	// TODO: subscribe to get items

	return SR_ERR_OK;

error_out:
	error = sr_unsubscribe(subscrption);
	if (error) {
		SRP_LOG_ERR("sr_unsubscribe error (%d): %s", error, sr_strerror(error));
	}

	return SR_ERR_CALLBACK_FAILED;
}

void dhcp_plugin_cleanup_cb(sr_session_ctx_t *session, void *private_data)
{
	sr_session_ctx_t *startup_session = (sr_session_ctx_t *) private_data;

	if (startup_session) {
		sr_session_stop(startup_session);
	}

	SRP_LOG_INFMSG("plugin cleanup finished");
}

static int dhcp_module_change_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, sr_event_t event, uint32_t request_id, void *private_data)
{
	int error = 0;
	sr_session_ctx_t *startup_session = (sr_session_ctx_t *) private_data;
	sr_change_iter_t *dhcp_server_change_iter = NULL;
	sr_change_oper_t operation = SR_OP_CREATED;
	const struct lyd_node *node = NULL;
	const char *prev_value = NULL;
	const char *prev_list = NULL;
	bool prev_default = false;
	char *node_xpath = NULL;
	const char *node_value = NULL;
	char *uci_path = NULL;
	struct lyd_node_leaf_list *node_leaf_list;
	struct lys_node_leaf *schema_node_leaf;

	srpu_transform_data_cb transform_sysrepo_data_cb = NULL;

	SRP_LOG_INF("module_name: %s, xpath: %s, request_id: %" PRIu32, module_name, xpath, request_id);

	if (event == SR_EV_ABORT) {
		SRP_LOG_ERR("aborting changes for: %s", xpath);
		error = -1;
		goto out;
	}

	if (event == SR_EV_DONE) {
		error = sr_copy_config(startup_session, DHCP_YANG_MODEL, SR_DS_RUNNING, 0, 0);
		if (error) {
			SRP_LOG_ERR("sr_copy_config error (%d): %s", error, sr_strerror(error));
			goto out;
		}
	}

	if (event == SR_EV_CHANGE) {
		error = sr_get_changes_iter(session, xpath, &dhcp_server_change_iter);
		if (error) {
			SRP_LOG_ERR("sr_get_changes_iter error (%d): %s", error, sr_strerror(error));
			goto out;
		}

		while (sr_get_change_tree_next(session, dhcp_server_change_iter, &operation, &node, &prev_value, &prev_list, &prev_default) == SR_ERR_OK) {
			node_xpath = lyd_path(node);

			error = srpu_xpath_to_uci_path_convert(node_xpath, dhcp_xpath_uci_uci_path_template_map, &uci_path);
			if (error && error != SRPU_ERR_NOT_EXISTS) {
				SRP_LOG_ERR("srpu_xpath_to_uci_path_convert error (%d): %s", error, srpu_error_description_get(error));
				goto out;
			} else if (error == SRPU_ERR_NOT_EXISTS) {
				continue;
			}

			error = srpu_transfor_sysrepo_data_cb_get(node_xpath, dhcp_xpath_uci_uci_path_template_map, &transform_sysrepo_data_cb);
			if (error) {
				SRP_LOG_ERR("srpu_transfor_sysrepo_data_cb_get error (%d): %s", error, srpu_error_description_get(error));
				goto out;
			}

			if (node->schema->nodetype == LYS_LEAF || node->schema->nodetype == LYS_LEAFLIST) {
				node_leaf_list = (struct lyd_node_leaf_list *) node;
				node_value = node_leaf_list->value_str;
				if (node_value == NULL) {
					schema_node_leaf = (struct lys_node_leaf *) node_leaf_list->schema;
					node_value = schema_node_leaf->dflt ? schema_node_leaf->dflt : "";
				}
			}

			if (node->schema->nodetype == LYS_LIST) {
				if (operation == SR_OP_CREATED) {
					error = srpu_uci_section_create(uci_path);
					if (error) {
						SRP_LOG_ERR("srpu_uci_section_create error (%d): %s", error, srpu_error_description_get(error));
						goto out;
					}
				} else if (operation == SR_OP_DELETED) {
					error = srpu_uci_section_delete(uci_path);
					if (error) {
						SRP_LOG_ERR("srpu_uci_section_delete error (%d): %s", error, srpu_error_description_get(error));
						goto out;
					}
				}
			} else if (node->schema->nodetype == LYS_LEAF) {
				if (operation == SR_OP_CREATED || operation == SR_OP_MODIFIED) {
					error = srpu_uci_option_set(uci_path, node_value, transform_sysrepo_data_cb);
					if (error) {
						SRP_LOG_ERR("srpu_uci_option_set error (%d): %s", error, srpu_error_description_get(error));
						goto out;
					}
				} else if (operation == SR_OP_DELETED) {
					error = srpu_uci_option_remove(uci_path);
					if (error) {
						SRP_LOG_ERR("srpu_uci_option_remove error (%d): %s", error, srpu_error_description_get(error));
						goto out;
					}
				}
			} else if (node->schema->nodetype == LYS_LEAFLIST) {
				if (operation == SR_OP_CREATED || operation == SR_OP_MODIFIED) {
					if (prev_value) {
						error = srpu_uci_list_remove(uci_path, prev_value);
						if (error) {
							SRP_LOG_ERR("srpu_uci_list_remove error (%d): %s", error, srpu_error_description_get(error));
							goto out;
						}
					}

					error = srpu_uci_list_set(uci_path, node_value, transform_sysrepo_data_cb);
					if (error) {
						SRP_LOG_ERR("srpu_uci_list_set error (%d): %s", error, srpu_error_description_get(error));
						goto out;
					}
				} else if (operation == SR_OP_DELETED) {
					error = srpu_uci_list_remove(uci_path, node_value);
					if (error) {
						SRP_LOG_ERR("srpu_uci_list_remove error (%d): %s", error, srpu_error_description_get(error));
						goto out;
					}
				}
			}

			free(uci_path);
			uci_path = NULL;
			free(node_xpath);
			node_xpath = NULL;
		}
	}

out:
	free(node_xpath);
	free(uci_path);
	sr_free_change_iter(dhcp_server_change_iter);

	return error ? SR_ERR_CALLBACK_FAILED : SR_ERR_OK;
}

#ifndef PLUGIN
#include <signal.h>
#include <unistd.h>

volatile int exit_application = 0;

static void sigint_handler(__attribute__((unused)) int signum);

int main()
{
	int error = SR_ERR_OK;
	sr_conn_ctx_t *connection = NULL;
	sr_session_ctx_t *session = NULL;
	void *private_data = NULL;

	sr_log_stderr(SR_LL_DBG);

	/* connect to sysrepo */
	error = sr_connect(SR_CONN_DEFAULT, &connection);
	if (error) {
		SRP_LOG_ERR("sr_connect error (%d): %s", error, sr_strerror(error));
		goto out;
	}

	error = sr_session_start(connection, SR_DS_RUNNING, &session);
	if (error) {
		SRP_LOG_ERR("sr_session_start error (%d): %s", error, sr_strerror(error));
		goto out;
	}

	error = dhcp_plugin_init_cb(session, &private_data);
	if (error) {
		SRP_LOG_ERRMSG("dhcp_plugin_init_cb error");
		goto out;
	}

	/* loop until ctrl-c is pressed / SIGINT is received */
	signal(SIGINT, sigint_handler);
	signal(SIGPIPE, SIG_IGN);
	while (!exit_application) {
		sleep(1); /* or do some more useful work... */
	}

out:
	dhcp_plugin_cleanup_cb(session, private_data);
	sr_disconnect(connection);

	return error ? -1 : 0;
}

static void sigint_handler(__attribute__((unused)) int signum)
{
	SRP_LOG_INFMSG("Sigint called, exiting...");
	exit_application = 1;
}

#endif
