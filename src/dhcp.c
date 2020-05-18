#include <sys/stat.h>
#include <sys/wait.h>
#include <uci.h>
#include <unistd.h>

#include <json-c/json.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubus.h>
#include <libyang/libyang.h>
#include <sysrepo.h>
#include <uci.h>

#include "parse.h"

#define DHCP_YANG_MODEL "terastream-dhcp"
#define DHCP_UCI_CONFIG "dhcp"

int dhcp_plugin_init_cb(sr_session_ctx_t *session, void **private_data);
void dhcp_plugin_cleanup_cb(sr_session_ctx_t *session, void *private_data);

typedef struct {
	struct uci_context *uci_context;
	// TODO: look at how to work with UCI
	sr_session_ctx_t *startup_session;
} private_ctx_t;

int dhcp_plugin_init_cb(sr_session_ctx_t *session, void **private_data)
{
	int error = 0;
	private_ctx_t *private_ctx = NULL;
	sr_subscription_ctx_t *subscrption = NULL;

	*private_data = NULL;

	// TODO: create and initialize private_ctx_t
	private_ctx = malloc(sizeof(private_ctx_t));
	if (private_ctx == NULL) {
		SRP_LOG_ERRMSG("malloc error");
		goto error_out;
	}

	// TODO: look at how to work with UCI

	SRP_LOG_INFMSG("start session to startup datastore");

	// TODO: initialize session on the same connection as the currnet session

	// TODO: synchronize DS and system

	SRP_LOG_INFMSG("subscribing to module change");

	// TODO: subuscribe to module change

	SRP_LOG_INFMSG("subscribing to get items");

	// TODO: subscribe to get items

	*private_data = private_ctx;

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
	system("rm /dev/shm/sr_main"); // TODO: check with Michal

	if (private_ctx) {
		// TODO: free and free private_ctx
	}

	free(private_ctx);
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
