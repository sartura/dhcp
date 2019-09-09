#include <sys/stat.h>
#include <sys/wait.h>
#include <uci.h>
#include <unistd.h>

#include <json-c/json.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubus.h>
#include <libyang/libyang.h>
#include <sr_uci.h>
#include <sysrepo.h>
#include <sysrepo/values.h>

#include "parse.h"
#include "version.h"

/* name of the uci config file. */
static const char *config_file_dhcp = "dhcp";
static const char *yang_model = "terastream-dhcp";

sr_uci_mapping_t table_sr_uci[] = {
    {sr_section_cb, uci_section_cb, "dhcp.%s",
     "/terastream-dhcp:dhcp-servers/dhcp-server[name='%s']"},
    {sr_boolean_reverse_cb, uci_boolean_reverse_cb, "dhcp.%s.ignore",
     "/terastream-dhcp:dhcp-servers/dhcp-server[name='%s']/enable"},
    {sr_option_cb, uci_option_cb, "dhcp.%s.interface",
     "/terastream-dhcp:dhcp-servers/dhcp-server[name='%s']/interface"},
    {sr_option_cb, uci_option_cb, "dhcp.%s.start",
     "/terastream-dhcp:dhcp-servers/dhcp-server[name='%s']/start"},
    {sr_stop_cb, uci_stop_cb, "dhcp.%s.limit",
     "/terastream-dhcp:dhcp-servers/dhcp-server[name='%s']/stop"},
    {sr_leasetime_cb, uci_leasetime_cb, "dhcp.%s.leasetime",
     "/terastream-dhcp:dhcp-servers/dhcp-server[name='%s']/leasetime"},
    {sr_option_cb, uci_option_cb, "dhcp.%s.dhcpv6",
     "/terastream-dhcp:dhcp-servers/dhcp-server[name='%s']/dhcpv6"},
    {sr_option_cb, uci_option_cb, "dhcp.%s.ra",
     "/terastream-dhcp:dhcp-servers/dhcp-server[name='%s']/ra"},
    {sr_option_cb, uci_option_cb, "dhcp.%s.ra_management",
     "/terastream-dhcp:dhcp-servers/dhcp-server[name='%s']/ra_management"},
    {sr_option_cb, uci_option_cb, "dhcp.%s.sntp",
     "/terastream-dhcp:dhcp-servers/dhcp-server[name='%s']/sntp"},
    {sr_list_cb, uci_list_cb, "dhcp.%s.dhcp_option",
     "/terastream-dhcp:dhcp-servers/dhcp-server[name='%s']/dhcp_option"},
    {sr_boolean_cb, uci_boolean_cb, "dhcp.%s.dynamicdhcp",
     "/terastream-dhcp:dhcp-servers/dhcp-server[name='%s']/dynamicdhcp"},
    {sr_boolean_cb, uci_boolean_cb, "dhcp.%s.force",
     "/terastream-dhcp:dhcp-servers/dhcp-server[name='%s']/force"},
    {sr_option_cb, uci_option_cb, "dhcp.%s.ndp",
     "/terastream-dhcp:dhcp-servers/dhcp-server[name='%s']/ndp"},
    {sr_boolean_cb, uci_boolean_cb, "dhcp.%s.master",
     "/terastream-dhcp:dhcp-servers/dhcp-server[name='%s']/master"},
    {sr_option_cb, uci_option_cb, "dhcp.%s.networkid",
     "/terastream-dhcp:dhcp-servers/dhcp-server[name='%s']/networkid"},

    {sr_list_cb, uci_list_cb, "dhcp.@domain[0].name",
     "/terastream-dhcp:domains/domain"},

    {sr_section_cb, uci_section_cb, "network.%s",
     "/terastream-dhcp:dhcp-clients/dhcp-client[name='%s']"},
    {sr_option_cb, uci_dhcpv6_option_cb, "network.%s.proto",
     "/terastream-dhcp:dhcp-clients/dhcp-client[name='%s']/proto"},
    {sr_boolean_cb, uci_dhcpv6_boolean_cb, "network.%s.accept_ra",
     "/terastream-dhcp:dhcp-clients/dhcp-client[name='%s']/accept_ra"},
    {sr_option_cb, uci_dhcpv6_option_cb, "network.%s.request_pd",
     "/terastream-dhcp:dhcp-clients/dhcp-client[name='%s']/request_pd"},
    {sr_option_cb, uci_dhcpv6_option_cb, "network.%s.request_na",
     "/terastream-dhcp:dhcp-clients/dhcp-client[name='%s']/request_na"},
    {sr_option_cb, uci_dhcpv6_option_cb, "network.%s.aftr_v4_local",
     "/terastream-dhcp:dhcp-clients/dhcp-client[name='%s']/aftr_v4_local"},
    {sr_option_cb, uci_dhcpv6_option_cb, "network.%s.aftr_v4_remote",
     "/terastream-dhcp:dhcp-clients/dhcp-client[name='%s']/aftr_v4_remote"},
    {sr_option_cb, uci_dhcpv6_option_cb, "network.%s.reqopts",
     "/terastream-dhcp:dhcp-clients/dhcp-client[name='%s']/reqopts"},
};

static int dhcp_v4_state_data_cb(sr_session_ctx_t *session,
                                 const char *module_name, const char *path,
                                 const char *request_xpath, uint32_t request_id,
                                 struct lyd_node **parent, void *private_data) {
  int rc = SR_ERR_OK;
  sr_ctx_t *ctx = private_data;
  sr_val_t *values = NULL;
  size_t values_cnt;
  char *value_string = NULL;
  const struct ly_ctx *ly_ctx = NULL;

  rc = fill_dhcp_v4_data(ctx, (char *)path, &values, &values_cnt);
  if (SR_ERR_OK != rc) {
    DBG("failed to load state data: %s", sr_strerror(rc));
    rc = SR_ERR_OK;
  }
  CHECK_RET(rc, error, "failed to load state data: %s", sr_strerror(rc));

  if (*parent == NULL) {
    ly_ctx = sr_get_context(sr_session_get_connection(session));
    CHECK_NULL_MSG(ly_ctx, &rc, error,
                   "sr_get_context error: libyang context is NULL");
    *parent = lyd_new_path(NULL, ly_ctx, request_xpath, NULL, 0, 0);
  }

  for (size_t i = 0; i < values_cnt; i++) {
    value_string = sr_val_to_str(&values[i]);
    lyd_new_path(*parent, NULL, values[i].xpath, value_string, 0, 0);
    free(value_string);
    value_string = NULL;
  }

error:
  if (values != NULL) {
    sr_free_values(values, values_cnt);
    values = NULL;
    values_cnt = 0;
  }
  return rc;
}

static int dhcp_v6_state_data_cb(sr_session_ctx_t *session,
                                 const char *module_name, const char *path,
                                 const char *request_xpath, uint32_t request_id,
                                 struct lyd_node **parent, void *private_data) {
  int rc = SR_ERR_OK;
  sr_ctx_t *ctx = private_data;
  sr_val_t *values = NULL;
  size_t values_cnt;
  char *value_string = NULL;
  const struct ly_ctx *ly_ctx = NULL;

  rc = fill_dhcp_v6_data(ctx, (char *)path, &values, &values_cnt);
  if (SR_ERR_OK != rc) {
    DBG("failed to load state data: %s", sr_strerror(rc));
    rc = SR_ERR_OK;
  }
  CHECK_RET(rc, error, "failed to load state data: %s", sr_strerror(rc));

  if (*parent == NULL) {
    ly_ctx = sr_get_context(sr_session_get_connection(session));
    CHECK_NULL_MSG(ly_ctx, &rc, error,
                   "sr_get_context error: libyang context is NULL");
    *parent = lyd_new_path(NULL, ly_ctx, request_xpath, NULL, 0, 0);
  }

  for (size_t i = 0; i < values_cnt; i++) {
    value_string = sr_val_to_str(&values[i]);
    lyd_new_path(*parent, NULL, values[i].xpath, value_string, 0, 0);
    free(value_string);
    value_string = NULL;
  }

error:
  if (values != NULL) {
    sr_free_values(values, values_cnt);
    values = NULL;
    values_cnt = 0;
  }
  return rc;
}

static int parse_change(sr_session_ctx_t *session, const char *module_name,
                        sr_ctx_t *ctx, sr_event_t event) {
  sr_change_iter_t *it = NULL;
  int rc = SR_ERR_OK;
  sr_change_oper_t oper;
  sr_val_t *old_value = NULL;
  sr_val_t *new_value = NULL;
  char xpath[100] = {
      0,
  };

  snprintf(xpath, 100, "/%s:*//.", module_name);

  rc = sr_get_changes_iter(session, xpath, &it);
  if (SR_ERR_OK != rc) {
    printf("Get changes iter failed for xpath %s", xpath);
    goto error;
  }

  while (SR_ERR_OK ==
         sr_get_change_next(session, it, &oper, &old_value, &new_value)) {

    rc = sysrepo_to_uci(ctx, oper, old_value, new_value, event);
    sr_free_val(old_value);
    sr_free_val(new_value);
    CHECK_RET(rc, error, "failed to add operation: %s", sr_strerror(rc));
  }
  commit_uci_file("dhcp");
  commit_uci_file("network");

error:
  if (NULL != it) {
    sr_free_change_iter(it);
  }
  return rc;
}

static int module_change_cb(sr_session_ctx_t *session, const char *module_name,
                            const char *xpath, sr_event_t event,
                            uint32_t request_id, void *private_data) {
  int rc = SR_ERR_OK;
  sr_ctx_t *ctx = private_data;

  ctx->sess = session;

  if (SR_EV_DONE == event) {
    /* copy running datastore to startup */

    rc = sr_copy_config(ctx->startup_sess, module_name, SR_DS_RUNNING,
                        SR_DS_STARTUP);
    if (SR_ERR_OK != rc) {
      WRN_MSG("Failed to copy running datastore to startup");
      /* TODO handle this error */
      return rc;
    }
    return SR_ERR_OK;
  }

  rc = parse_change(session, module_name, ctx, event);
  CHECK_RET(rc, error, "failed to apply sysrepo changes to snabb: %s",
            sr_strerror(rc));

error:
  return rc;
}

int sr_plugin_init_cb(sr_session_ctx_t *session, void **private_ctx) {
  int rc = SR_ERR_OK;

  INF_MSG("sr_plugin_init_cb called for dhcp plugin");

  sr_ctx_t *ctx = calloc(1, sizeof(*ctx));
  ctx->sub = NULL;
  ctx->sess = session;
  ctx->startup_conn = NULL;
  ctx->startup_sess = NULL;
  ctx->yang_model = yang_model;
  ctx->config_file = config_file_dhcp;
  *private_ctx = ctx;
  ctx->map = table_sr_uci;
  ctx->map_size = sizeof(table_sr_uci) / sizeof(table_sr_uci[0]);

  /* Allocate UCI context for uci files. */
  ctx->uctx = uci_alloc_context();
  if (NULL == ctx->uctx) {
    rc = SR_ERR_NOMEM;
  }
  CHECK_RET(rc, error, "Can't allocate uci context: %s", sr_strerror(rc));

  /* load the startup datastore */
  INF_MSG("load sysrepo startup datastore");
  rc = load_startup_datastore(ctx);
  CHECK_RET(rc, error, "failed to load startup datastore: %s", sr_strerror(rc));

  /* sync sysrepo datastore and uci configuration file */
  INF_MSG("sync sysrepo datastore and uci configuration file");
  rc = sync_datastores(ctx);
  CHECK_RET(rc, error,
            "failed to sync sysrepo datastore and uci configuration file: %s",
            sr_strerror(rc));

  rc = sr_copy_config(ctx->startup_sess, yang_model, SR_DS_STARTUP,
                      SR_DS_RUNNING);
  if (SR_ERR_OK != rc) {
    WRN_MSG("Failed to copy running datastore to startup");
    /* TODO handle this error */
    return rc;
  }

  rc =
      sr_module_change_subscribe(ctx->sess, yang_model, NULL, module_change_cb,
                                 *private_ctx, 0, SR_SUBSCR_DEFAULT, &ctx->sub);
  CHECK_RET(rc, error, "initialization error: %s", sr_strerror(rc));

  rc = sr_oper_get_items_subscribe(
      ctx->sess, yang_model, "/terastream-dhcp:dhcp-v4-leases",
      dhcp_v4_state_data_cb, ctx, SR_SUBSCR_CTX_REUSE, &ctx->sub);
  CHECK_RET(rc, error, "failed sr_oper_get_items_subscribe: %s",
            sr_strerror(rc));

  rc = sr_oper_get_items_subscribe(
      ctx->sess, yang_model, "/terastream-dhcp:dhcp-v6-leases",
      dhcp_v6_state_data_cb, ctx, SR_SUBSCR_CTX_REUSE, &ctx->sub);
  CHECK_RET(rc, error, "failed sr_oper_get_items_subscribe: %s",
            sr_strerror(rc));

  INF_MSG("Plugin initialized successfully");

  return SR_ERR_OK;

error:
  ERR("Plugin initialization failed: %s", sr_strerror(rc));
  if (NULL != ctx->sub) {
    sr_unsubscribe(ctx->sub);
    ctx->sub = NULL;
  }
  return rc;
}

void sr_plugin_cleanup_cb(sr_session_ctx_t *session, void *private_ctx) {
  INF("Plugin cleanup called, private_ctx is %s available.",
      private_ctx ? "" : "not");
  if (!private_ctx) {
    return;
  }

  sr_uci_free_context((sr_ctx_t *)private_ctx);
}

#ifndef PLUGIN
#include <signal.h>
#include <unistd.h>

volatile int exit_application = 0;

static void sigint_handler(__attribute__((unused)) int signum) {
  INF_MSG("Sigint called, exiting...");
  exit_application = 1;
}

int main() {
  sr_conn_ctx_t *connection = NULL;
  sr_session_ctx_t *session = NULL;
  void *private_ctx = NULL;
  int rc = SR_ERR_OK;

  ENABLE_LOGGING(SR_LL_DBG);

  /* connect to sysrepo */
  rc = sr_connect(SR_CONN_DEFAULT, &connection);
  CHECK_RET(rc, cleanup, "Error by sr_connect: %s", sr_strerror(rc));

  /* start session */
  rc = sr_session_start(connection, SR_DS_RUNNING, &session);
  CHECK_RET(rc, cleanup, "Error by sr_session_start: %s", sr_strerror(rc));

  rc = sr_plugin_init_cb(session, &private_ctx);
  CHECK_RET(rc, cleanup, "Error by sr_plugin_init_cb: %s", sr_strerror(rc));

  /* loop until ctrl-c is pressed / SIGINT is received */
  signal(SIGINT, sigint_handler);
  signal(SIGPIPE, SIG_IGN);
  while (!exit_application) {
    sleep(1); /* or do some more useful work... */
  }

cleanup:
  sr_plugin_cleanup_cb(session, private_ctx);
  if (NULL != session) {
    sr_session_stop(session);
  }
  if (NULL != connection) {
    sr_disconnect(connection);
  }
}
#endif
