#include <inttypes.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <uci.h>
#include <sysrepo.h>

#include "parse.h"

#define DHCP_YANG_MODEL "terastream-dhcp"
#define DHCP_UCI_CONFIG "dhcp"

int dhcp_plugin_init_cb(sr_session_ctx_t *session, void **private_data);
void dhcp_plugin_cleanup_cb(sr_session_ctx_t *session, void *private_data);

static int dhcp_module_change_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, sr_event_t event, uint32_t request_id, void *private_data);

typedef struct {
	struct uci_context *uci_context;
	sr_session_ctx_t *startup_session;
} private_ctx_t;

struct {
	const char *xpath;
	const char *ucipath;
	enum uci_type uci_type;
} sysrepo_uci_template_map[] = {
	{"/terastream-dhcp:dhcp-servers/dhcp-server[name='%s']/name", "dhcp.%s", UCI_TYPE_SECTION},
	{"/terastream-dhcp:dhcp-servers/dhcp-server[name='%s']/enable", "dhcp.%s.ignore", UCI_TYPE_OPTION},
	{"/terastream-dhcp:dhcp-servers/dhcp-server[name='%s']/interface", "dhcp.%s.interface", UCI_TYPE_SECTION},
	{"/terastream-dhcp:dhcp-servers/dhcp-server[name='%s']/start", "dhcp.%s.start", UCI_TYPE_SECTION},
	{"/terastream-dhcp:dhcp-servers/dhcp-server[name='%s']/stop", "dhcp.%s.limit", UCI_TYPE_SECTION},
	{"/terastream-dhcp:dhcp-servers/dhcp-server[name='%s']/leasetime", "dhcp.%s.leasetime", UCI_TYPE_SECTION},
	{"/terastream-dhcp:dhcp-servers/dhcp-server[name='%s']/dhcpv6", "dhcp.%s.dhcpv6", UCI_TYPE_SECTION},
	{"/terastream-dhcp:dhcp-servers/dhcp-server[name='%s']/ra", "dhcp.%s.ra", UCI_TYPE_SECTION},
	{"/terastream-dhcp:dhcp-servers/dhcp-server[name='%s']/ra_management", "dhcp.%s.ra_management", UCI_TYPE_SECTION},
	{"/terastream-dhcp:dhcp-servers/dhcp-server[name='%s']/sntp", "dhcp.%s.sntp", UCI_TYPE_SECTION},
	{"/terastream-dhcp:dhcp-servers/dhcp-server[name='%s']/dhcp_option", "dhcp.%s.dhcp_option", UCI_TYPE_SECTION},
	{"/terastream-dhcp:dhcp-servers/dhcp-server[name='%s']/dynamicdhcp", "dhcp.%s.dynamicdhcp", UCI_TYPE_SECTION},
	{"/terastream-dhcp:dhcp-servers/dhcp-server[name='%s']/force", "dhcp.%s.force", UCI_TYPE_SECTION},
	{"/terastream-dhcp:dhcp-servers/dhcp-server[name='%s']/ndp", "dhcp.%s.ndp", UCI_TYPE_SECTION},
	{"/terastream-dhcp:dhcp-servers/dhcp-server[name='%s']/master", "dhcp.%s.master", UCI_TYPE_SECTION},
	{"/terastream-dhcp:dhcp-servers/dhcp-server[name='%s']/networkid", "dhcp.%s.networkid", UCI_TYPE_SECTION},
};

int dhcp_plugin_init_cb(sr_session_ctx_t *session, void **private_data)
{
	int error = 0;
	private_ctx_t *private_ctx = NULL;
	sr_conn_ctx_t *connection = NULL;
	sr_subscription_ctx_t *subscrption = NULL;

	*private_data = NULL;

	private_ctx = malloc(sizeof(private_ctx_t));
	if (private_ctx == NULL) {
		SRP_LOG_ERRMSG("malloc error");
		goto error_out;
	}

	private_ctx->startup_session = NULL;

	*private_data = private_ctx;

	SRP_LOG_INFMSG("start session to startup datastore");

	connection = sr_session_get_connection(session);
	error = sr_session_start(connection, SR_DS_STARTUP, &private_ctx->startup_session);
	if (error) {
		SRP_LOG_ERR("sr_session_start error (%d): %s", error, sr_strerror(error));
		goto error_out;
	}

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
	private_ctx_t *private_ctx = (private_ctx_t *) private_data;
	system("rm /dev/shm/sr_main");

	if (private_ctx) {
		sr_session_stop(private_ctx->startup_session);
	}

	free(private_ctx);

	SRP_LOG_INFMSG("plugin cleanup finished");
}

static int dhcp_module_change_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, sr_event_t event, uint32_t request_id, void *private_data)
{
	int error = 0;
	private_ctx_t *private_ctx = (private_ctx_t *) private_data;
	sr_change_iter_t *dhcp_server_change_iter = NULL;
	sr_change_oper_t operation = SR_OP_CREATED;
	const struct lyd_node *node = NULL;
	const char *prev_value = NULL;
	const char *prev_list = NULL;
	bool prev_default = false;
	char *node_xpath = NULL;

	SRP_LOG_INF("module_name: %s, xpath: %s, request_id: %" PRIu32, module_name, xpath, request_id);

	switch (event) {
		case SR_EV_CHANGE:
			error = sr_get_changes_iter(session, xpath, &dhcp_server_change_iter);
			if (error) {
				SRP_LOG_ERR("sr_get_changes_iter error (%d): %s", error, sr_strerror(error));
				goto error_out;
			}

			while (sr_get_change_tree_next(session, dhcp_server_change_iter, &operation, &node, &prev_value, &prev_list, &prev_default) == SR_ERR_OK) {
				node_xpath = lyd_path(node);
				SRP_LOG_INF("operation: %d", operation);
				SRP_LOG_INF("lyd_node xpath: %s", node_xpath);
				SRP_LOG_INF("previous value: %s", prev_value);
				SRP_LOG_INF("previous list: %s", prev_list);
				SRP_LOG_INF("previous default value: %d", prev_default);

				// TODO: use a global table that maps xpath to uci_path_and uci_type
				// TODO: depending on the uci type call specific uci call
				// TODO: set value for uci call depending on the operation, lyd_node, prev_*
				// TODO: call the selected uci call

				// different uci calls:
				// 		create uci section -> uci_path, value = NULL, uci_context? uci_package?
				//		set/create uci option -> uci_path, value = NULL
				//		delete uci section/option -> uci_path, value = NULL
				//

				switch (operation) {
					case SR_OP_CREATED:
						break;
					case SR_OP_MODIFIED:
						break;
					case SR_OP_DELETED:
						break;
					case SR_OP_MOVED:
						SRP_LOG_INFMSG("not implemented");
						break;
					default:
						SRP_LOG_ERRMSG("unknow operation");
						goto error_out;
				}

				free(node_xpath);
				node_xpath = NULL;
			}
			break;

		case SR_EV_DONE:
			error = sr_copy_config(private_ctx->startup_session, DHCP_YANG_MODEL, SR_DS_RUNNING, 0, 0);
			if (error) {
				SRP_LOG_ERR("sr_copy_config error (%d): %s", error, sr_strerror(error));
				goto error_out;
			}
			break;

		case SR_EV_ABORT:
			SRP_LOG_ERR("aborting changes made to %s", xpath);
			break;

		case SR_EV_UPDATE:
			// fall-through
		case SR_EV_ENABLED:
			// fall-through
		case SR_EV_RPC:
			SRP_LOG_INFMSG("unsuported event");
			break;

		default: /* SR_EV_UPDATE, SR_EV_ENABLED, SR_EV_RPC */
			SRP_LOG_ERRMSG("unknown event");
			goto error_out;
	}

	goto out;

error_out:

out:
	free(node_xpath);
	sr_free_change_iter(dhcp_server_change_iter);

	return SR_ERR_OK;
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
