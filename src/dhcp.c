#include <inttypes.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <uci.h>
#include <sysrepo.h>
#include <sysrepo/xpath.h>

#include "srpu.h"

#define ARRAY_SIZE(X) (sizeof((X)) / sizeof((X)[0]))

#define DHCP_YANG_MODEL "terastream-dhcp"
#define DHCP_UCI_CONFIG "dhcp"

int dhcp_plugin_init_cb(sr_session_ctx_t *session, void **private_data);
void dhcp_plugin_cleanup_cb(sr_session_ctx_t *session, void *private_data);

static int dhcp_module_change_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, sr_event_t event, uint32_t request_id, void *private_data);

static char *dhcp_path_key_set(const char *path, const char *key);
static int dhcp_uci_data_set(const char *uci_path, const char *value, const sr_change_oper_t oparation, parse_uci_set_cb parse_uci_set);

struct {
	const char *xpath;
	const char *uci_path;
	parse_uci_set_cb parse_uci_set;
} sysrepo_uci_template_map[] = {
	{"/terastream-dhcp:dhcp-servers/dhcp-server[name='%s']/name", "dhcp.%s", parse_uci_section_set_cb},
	{"/terastream-dhcp:dhcp-servers/dhcp-server[name='%s']/enable", "dhcp.%s.ignore", parse_uci_negated_boolean_set_cb},
	{"/terastream-dhcp:dhcp-servers/dhcp-server[name='%s']/interface", "dhcp.%s.interface", parse_uci_string_set_cb},
	{"/terastream-dhcp:dhcp-servers/dhcp-server[name='%s']/start", "dhcp.%s.start", parse_uci_string_set_cb},
	{"/terastream-dhcp:dhcp-servers/dhcp-server[name='%s']/stop", "dhcp.%s.limit", parse_uci_limit_set_cb},
	{"/terastream-dhcp:dhcp-servers/dhcp-server[name='%s']/leasetime", "dhcp.%s.leasetime", parse_uci_leasetime_set_cb},
	{"/terastream-dhcp:dhcp-servers/dhcp-server[name='%s']/dhcpv6", "dhcp.%s.dhcpv6", parse_uci_string_set_cb},
	{"/terastream-dhcp:dhcp-servers/dhcp-server[name='%s']/ra", "dhcp.%s.ra", parse_uci_string_set_cb},
	{"/terastream-dhcp:dhcp-servers/dhcp-server[name='%s']/ra_management", "dhcp.%s.ra_management", parse_uci_string_set_cb},
	{"/terastream-dhcp:dhcp-servers/dhcp-server[name='%s']/sntp", "dhcp.%s.sntp", parse_uci_string_set_cb},
	{"/terastream-dhcp:dhcp-servers/dhcp-server[name='%s']/dhcp_option", "dhcp.%s.dhcp_option", parse_uci_list_set_cb},
	{"/terastream-dhcp:dhcp-servers/dhcp-server[name='%s']/dynamicdhcp", "dhcp.%s.dynamicdhcp", parse_uci_boolean_set_cb},
	{"/terastream-dhcp:dhcp-servers/dhcp-server[name='%s']/force", "dhcp.%s.force", parse_uci_boolean_set_cb},
	{"/terastream-dhcp:dhcp-servers/dhcp-server[name='%s']/ndp", "dhcp.%s.ndp", parse_uci_string_set_cb},
	{"/terastream-dhcp:dhcp-servers/dhcp-server[name='%s']/master", "dhcp.%s.master", parse_uci_boolean_set_cb},
	{"/terastream-dhcp:dhcp-servers/dhcp-server[name='%s']/networkid", "dhcp.%s.networkid", parse_uci_string_set_cb},
};

int dhcp_plugin_init_cb(sr_session_ctx_t *session, void **private_data)
{
	int error = 0;
	sr_conn_ctx_t *connection = NULL;
	sr_session_ctx_t *startup_session = NULL;
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

	// TODO: synchronize DS and system

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
	sr_xpath_ctx_t sr_xpath_ctx = {0};
	char *xpath_node_name = NULL;
	char *xpath_node_key_name = NULL;
	char *xpath_node_key_value = NULL;
	char *table_xpath = NULL;
	char *table_uci_path = NULL;

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
			if (node->schema->nodetype != LYS_LEAF && node->schema->nodetype != LYS_LEAFLIST) {
				continue;
			}

			node_xpath = lyd_path(node);
			node_value = ((struct lyd_node_leaf_list *) node)->value_str;

			xpath_node_name = sr_xpath_next_node(node_xpath, &sr_xpath_ctx);
			if (xpath_node_name) {
				do {
					xpath_node_key_name = sr_xpath_next_key_name(NULL, &sr_xpath_ctx);
					if (xpath_node_key_name) {
						xpath_node_key_value = strdup(sr_xpath_next_key_value(NULL, &sr_xpath_ctx));
						break;
					}
				} while (sr_xpath_next_node(NULL, &sr_xpath_ctx));
			}

			sr_xpath_recover(&sr_xpath_ctx);

			for (size_t i = 0; i < ARRAY_SIZE(sysrepo_uci_template_map); i++) {
				table_xpath = dhcp_path_key_set(sysrepo_uci_template_map[i].xpath, xpath_node_key_value);
				table_uci_path = dhcp_path_key_set(sysrepo_uci_template_map[i].uci_path, xpath_node_key_value);
				if (strcmp(node_xpath, table_xpath) == 0) {
					dhcp_uci_data_set(table_uci_path, node_value, operation, sysrepo_uci_template_map[i].parse_uci_set);
				}

				free(table_xpath);
				table_xpath = NULL;

				free(table_uci_path);
				table_uci_path = NULL;
			}

			free(node_xpath);
			node_xpath = NULL;
		}
	}

out:
	free(node_xpath);
	free(xpath_node_key_value);
	free(table_xpath);
	free(table_uci_path);
	sr_free_change_iter(dhcp_server_change_iter);

	return error ? SR_ERR_CALLBACK_FAILED : SR_ERR_OK;
}

static char *dhcp_path_key_set(const char *path, const char *key)
{
	char *value = NULL;
	size_t length = 0;

	if (path == NULL) {
		goto out;
	}

	if (key == NULL) { /* if the xpath does not contain list elements, copy string */
		value = strdup(path);
		goto out;
	}

	length = strlen(key) + strlen(path) + 1;

	value = malloc(sizeof(char) * length);
	if (value == NULL) {
		SRP_LOG_ERRMSG("malloc error");
		goto out;
	}

	snprintf(value, length, path, key);

out:
	return value;
}

static int dhcp_uci_data_set(const char *uci_path, const char *value, const sr_change_oper_t oparation, parse_uci_set_cb parse_uci_set)
{
	SRP_LOG_INFMSG("not implemented");
	return 0;
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
