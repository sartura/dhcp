#include <sys/wait.h>
#include <sys/stat.h>
#include <unistd.h>
#include <uci.h>
#include <sysrepo.h>
#include <sysrepo/plugins.h>
#include <sysrepo/xpath.h>
#include <sysrepo/values.h>
#include <ctype.h>

#include <libubus.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <json-c/json.h>

#include "common.h"
#include "parse.h"
#include "uci.h"

typedef int (*sr_callback)(ctx_t *, sr_change_oper_t, char *, char *, char *, sr_val_t *);

int sysrepo_option_callback(ctx_t *ctx, sr_change_oper_t op, char *xpath, char *ucipath, char *key, sr_val_t *val)
{
    int rc = SR_ERR_OK;

    /* add/change leafs */
    if (SR_OP_CREATED == op || SR_OP_MODIFIED == op) {
        char *mem = NULL;
        mem = sr_val_to_str(val);
        CHECK_NULL(mem, &rc, error, "sr_print_val %s", sr_strerror(rc));
        rc = set_uci_item(ctx->uctx, ucipath, mem);
        if (mem) {
            free(mem);
        }
        UCI_CHECK_RET(rc, uci_error, "set_uci_item %x", rc);
    } else if (SR_OP_DELETED == op) {
        rc = uci_del(ctx, ucipath);
        UCI_CHECK_RET(rc, uci_error, "uci_del %d", rc);
    }

error:
    return rc;
uci_error:
    return SR_ERR_INTERNAL;
}

int sysrepo_boolean_callback(ctx_t *ctx, sr_change_oper_t op, char *xpath, char *ucipath, char *key, sr_val_t *val)
{
    int rc = SR_ERR_OK;

    /* add/change leafs */
    if (SR_OP_CREATED == op || SR_OP_MODIFIED == op) {
        if (val->data.bool_val) {
            rc = set_uci_item(ctx->uctx, ucipath, "1");
        } else {
            rc = set_uci_item(ctx->uctx, ucipath, "0");
        }
        UCI_CHECK_RET(rc, uci_error, "set_uci_item %x", rc);
    } else if (SR_OP_DELETED == op) {
        rc = uci_del(ctx, ucipath);
        UCI_CHECK_RET(rc, uci_error, "uci_del %d", rc);
    }

    if (val->data.bool_val) {
        /* voice_client init.d script will delete the password when the leaf is set
         * to disabled, so after it's enabled the password needs to be written, if
         * it exists, to UCI again */
        sr_val_t *value = NULL;
        char password_xpath[XPATH_MAX_LEN] = {0};
        char password_ucipath[XPATH_MAX_LEN] = {0};

        snprintf(password_xpath, XPATH_MAX_LEN, "/terastream-sip:sip/sip-account[account='%s']/password", key);
        snprintf(password_ucipath, XPATH_MAX_LEN, "voice_client.%s.secret", key);

        rc = sr_get_item(ctx->sess, password_xpath, &value);
        if (SR_ERR_NOT_FOUND == rc) {
            return SR_ERR_OK;
        } else if (SR_ERR_OK != rc) {
            return rc;
        }
        rc = set_uci_item(ctx->uctx, password_ucipath, value->data.string_val);
        sr_free_val(value);
        UCI_CHECK_RET(rc, uci_error, "set_uci_item %x", rc);
    }

    return rc;
uci_error:
    return SR_ERR_INTERNAL;
}

int sysrepo_section_callback(ctx_t *ctx, sr_change_oper_t op, char *xpath, char *ucipath, char *key, sr_val_t *val)
{
    int rc = SR_ERR_OK;

    /* for now there is only one */
    char *element = "sip_service_provider";

    /* add/change leafs */
    if (SR_OP_CREATED == op || SR_OP_MODIFIED == op) {
        // TODO check
        if (NULL != strstr(xpath, "dhcp-server")) {
            sprintf(ucipath, "%s.%s=%s", ctx->config_file_dhcp, key, element);
        } else {
            sprintf(ucipath, "%s.%s=%s", ctx->config_file_network, key, element);
        }
        rc = set_uci_section(ctx, ucipath);
        UCI_CHECK_RET(rc, uci_error, "set_uci_item %x", rc);
    } else if (SR_OP_DELETED == op) {
        rc = uci_del(ctx, ucipath);
        UCI_CHECK_RET(rc, uci_error, "uci_del %d", rc);
    }

    return rc;
uci_error:
    return SR_ERR_INTERNAL;
}

int sysrepo_list_callback(ctx_t *ctx, sr_change_oper_t op, char *orig_xpath, char *orig_ucipath, char *key, sr_val_t *val)
{
    int rc = SR_ERR_OK;
    size_t count = 0;
    bool enabled = true;
    sr_val_t *values = NULL;
    struct uci_ptr ptr = {};
    char set_path[XPATH_MAX_LEN] = {0};
    char ucipath[] = "voice_client.direct_dial.direct_dial";
    char xpath[] = "/terastream-sip:sip/digitmap/dials";

    /* check if digitmap is enabled */
    rc = sr_get_item(ctx->sess, "/terastream-sip:sip/digitmap/enabled", &values);
    CHECK_RET(rc, cleanup, "failed sr_get_item: %s", sr_strerror(rc));
    enabled = values->data.bool_val;
    sr_free_val(values);
    values = NULL;
    if (false == enabled) {
        return rc;
    }

    rc = uci_lookup_ptr(ctx->uctx, &ptr, (char *) ucipath, true);
    UCI_CHECK_RET(rc, uci_error, "uci_lookup_ptr %d, path %s", rc, ucipath);
    if (NULL != ptr.o) {
        /* remove the UCI list first */
        rc = uci_delete(ctx->uctx, &ptr);
        UCI_CHECK_RET(rc, uci_error, "uci_delete %d, path %s", rc, ucipath);
    }

    /* get all list instances */
    rc = sr_get_items(ctx->sess, xpath, &values, &count);
    CHECK_RET(rc, cleanup, "failed sr_get_items: %s", sr_strerror(rc));

    for (size_t i = 0; i < count; i++) {
        sprintf(set_path, "%s%s%s", orig_ucipath, "=", values[i].data.string_val);

        rc = uci_lookup_ptr(ctx->uctx, &ptr, set_path, true);
        UCI_CHECK_RET(rc, uci_error, "lookup_pointer %d %s", rc, set_path);

        rc = uci_add_list(ctx->uctx, &ptr);
        UCI_CHECK_RET(rc, uci_error, "uci_set %d %s", rc, set_path);

        rc = uci_save(ctx->uctx, ptr.p);
        UCI_CHECK_RET(rc, uci_error, "uci_save %d %s", rc, set_path);

        rc = uci_commit(ctx->uctx, &(ptr.p), false);
        UCI_CHECK_RET(rc, uci_error, "uci_commit %d %s", rc, set_path);
    }

cleanup:
    if (NULL != values && 0 != count) {
        sr_free_values(values, count);
    }
    return rc;
uci_error:
    if (NULL != values && 0 != count) {
        sr_free_values(values, count);
    }
    return SR_ERR_INTERNAL;
}

int sysrepo_list_callback_enable(ctx_t *ctx, sr_change_oper_t op, char *xpath, char *orig_ucipath, char *key, sr_val_t *val)
{
    int rc = SR_ERR_OK;
    struct uci_ptr ptr = {};
    char ucipath[] = "voice_client.direct_dial.direct_dial";

    if (SR_OP_CREATED == op || SR_OP_MODIFIED == op) {
        if (false == val->data.bool_val) {
            rc = uci_lookup_ptr(ctx->uctx, &ptr, (char *) ucipath, true);
            UCI_CHECK_RET(rc, uci_error, "uci_lookup_ptr %d, path %s", rc, ucipath);
            if (NULL != ptr.o) {
                /* remove the UCI list first */
                rc = uci_delete(ctx->uctx, &ptr);
                UCI_CHECK_RET(rc, uci_error, "uci_delete %d, path %s", rc, ucipath);

                rc = uci_save(ctx->uctx, ptr.p);
                UCI_CHECK_RET(rc, uci_error, "uci_save %d %s", rc, ucipath);

                rc = uci_commit(ctx->uctx, &(ptr.p), false);
                UCI_CHECK_RET(rc, uci_error, "uci_commit %d %s", rc, ucipath);
            }
        } else {
            return sysrepo_list_callback(ctx, op, xpath, "voice_client.direct_dial.direct_dial", key, val);
        }
    } else if (SR_OP_DELETED == op) {
        // TODO
    }

    return rc;
uci_error:
    return SR_ERR_INTERNAL;
}

/* Configuration part of the plugin. */
typedef struct sr_uci_mapping {
    sr_callback callback;
    bool boolean;
    char *ucipath;
    char *xpath;
} sr_uci_link;

bool string_eq(char *first, char *second)
{
    if (0 == strcmp(first, second)) {
        if (strlen(first) == strlen(second)) {
            return true;
        }
    }
    return false;
}

static sr_uci_link table_sr_uci[] = {
    {sysrepo_section_callback, false, "dhcp.%s", "/terastream-dhcp:dhcp-servers/dhcp-server[name='%s']"},
    {sysrepo_boolean_callback, true, "dhcp.%s.ignore", "/terastream-dhcp:dhcp-servers/dhcp-server[name='%s']/ignore"},
    {sysrepo_option_callback, false, "dhcp.%s.interface", "/terastream-dhcp:dhcp-servers/dhcp-server[name='%s']/interface"},
    {sysrepo_option_callback, false, "dhcp.%s.start", "/terastream-dhcp:dhcp-servers/dhcp-server[name='%s']/start"},
    {sysrepo_option_callback, false, "dhcp.%s.limit", "/terastream-dhcp:dhcp-servers/dhcp-server[name='%s']/limit"},
    {sysrepo_option_callback, false, "dhcp.%s.leasetime", "/terastream-dhcp:dhcp-servers/dhcp-server[name='%s']/leasetime"},
    {sysrepo_option_callback, false, "dhcp.%s.dhcpv6", "/terastream-dhcp:dhcp-servers/dhcp-server[name='%s']/dhcpv6"},
    {sysrepo_option_callback, false, "dhcp.%s.ra", "/terastream-dhcp:dhcp-servers/dhcp-server[name='%s']/ra"},
    {sysrepo_option_callback, false, "dhcp.%s.ra_management", "/terastream-dhcp:dhcp-servers/dhcp-server[name='%s']/ra_management"},
    {sysrepo_option_callback, false, "dhcp.%s.sntp", "/terastream-dhcp:dhcp-servers/dhcp-server[name='%s']/sntp"},
    {sysrepo_list_callback, false, "dhcp.%s.dhcp_option", "/terastream-dhcp:dhcp-servers/dhcp-server[name='%s']/dhcp_option"},

    {sysrepo_section_callback, false, "network.%s", "/terastream-dhcp:dhcp-clients/dhcp-client[name='%s']"},
    {sysrepo_option_callback, false, "network.%s.proto", "/terastream-dhcp:dhcp-clients/dhcp-client[name='%s']/proto"},
    {sysrepo_option_callback, false, "network.%s.accept_ra", "/terastream-dhcp:dhcp-clients/dhcp-client[name='%s']/accept_ra"},
    {sysrepo_option_callback, false, "network.%s.request_pd", "/terastream-dhcp:dhcp-clients/dhcp-client[name='%s']/request_pd"},
    {sysrepo_option_callback, false, "network.%s.request_na", "/terastream-dhcp:dhcp-clients/dhcp-client[name='%s']/request_na"},
    {sysrepo_option_callback, false, "network.%s.aftr_v4_local", "/terastream-dhcp:dhcp-clients/dhcp-client[name='%s']/aftr_v4_local"},
    {sysrepo_option_callback, false, "network.%s.aftr_v4_remote", "/terastream-dhcp:dhcp-clients/dhcp-client[name='%s']/aftr_v4_remote"},
    {sysrepo_option_callback, false, "network.%s.reqopts", "/terastream-dhcp:dhcp-clients/dhcp-client[name='%s']/reqopts"},
};

/* parse UCI list dhcp_option in dhcp */
static int parse_uci_config_list(ctx_t *ctx, char *key)
{
    int rc = SR_ERR_OK;
    struct uci_option *o;
    struct uci_element *el;
    struct uci_ptr ptr = {};
    char ucipath[XPATH_MAX_LEN] = {0};
    char xpath[XPATH_MAX_LEN] = {0};

    snprintf(ucipath, XPATH_MAX_LEN, "dhcp.%s.dhcp_option", key);
    snprintf(xpath, XPATH_MAX_LEN, "/terastream-dhcp:dhcp-servers/dhcp-server[name='%s']/dhcp_option", key);

    rc = uci_lookup_ptr(ctx->uctx, &ptr, (char *) ucipath, true);
    UCI_CHECK_RET(rc, uci_error, "uci_lookup_ptr %d, path %s", rc, ucipath);

    if (NULL == ptr.o) {
        goto uci_error;
    }

    uci_foreach_element(&ptr.o->v.list, el)
    {
        o = uci_to_option(el);
        if (NULL == o && NULL == o->e.name) {
            goto uci_error;
        }
        rc = sr_set_item_str(ctx->startup_sess, xpath, o->e.name, SR_EDIT_DEFAULT);
        CHECK_RET(rc, cleanup, "failed sr_set_item_str: %s", sr_strerror(rc));
    }

cleanup:
    return rc;
uci_error:
    return SR_ERR_INTERNAL;
}

static int parse_uci_config(ctx_t *ctx, char *key, char *match)
{
    char xpath[XPATH_MAX_LEN] = {0};
    char ucipath[XPATH_MAX_LEN] = {0};
    char *uci_val = calloc(1, 100);
    int rc = SR_ERR_OK;

    const int n_mappings = ARR_SIZE(table_sr_uci);
    for (int i = 0; i < n_mappings; i++) {
        snprintf(xpath, XPATH_MAX_LEN, table_sr_uci[i].xpath, key);
        snprintf(ucipath, XPATH_MAX_LEN, table_sr_uci[i].ucipath, key);
        if (NULL == strstr(xpath, match)) {
            continue;
        }
        rc = get_uci_item(ctx->uctx, ucipath, &uci_val);
        if (UCI_OK == rc) {
            UCI_CHECK_RET(rc, cleanup, "get_uci_item %d", rc);
            INF("%s : %s", xpath, uci_val);
            if (sysrepo_list_callback == table_sr_uci[i].callback) {
                /* check if list value */
                rc = parse_uci_config_list(ctx, key);
            } else if (table_sr_uci[i].boolean) {
                /* check if boolean value */
                if (string_eq(uci_val, "1") || string_eq(uci_val, "true") || string_eq(uci_val, "on")) {
                    rc = sr_set_item_str(ctx->startup_sess, xpath, "true", SR_EDIT_DEFAULT);
                } else {
                    rc = sr_set_item_str(ctx->startup_sess, xpath, "false", SR_EDIT_DEFAULT);
                }
            } else {
                rc = sr_set_item_str(ctx->startup_sess, xpath, uci_val, SR_EDIT_DEFAULT);
            }
            CHECK_RET(rc, cleanup, "failed sr_set_item_str: %s", sr_strerror(rc));
        }
    }

    rc = SR_ERR_OK;
cleanup:
    if (SR_ERR_NOT_FOUND == rc) {
        rc = SR_ERR_OK;
    }
    if (NULL != uci_val) {
        free(uci_val);
    }

    return rc;
}

char *get_key_value(char *orig_xpath)
{
    char *key = NULL, *node = NULL;
    sr_xpath_ctx_t state = {0, 0, 0, 0};

    node = sr_xpath_next_node(orig_xpath, &state);
    if (NULL == node) {
        goto error;
    }
    while (true) {
        key = sr_xpath_next_key_name(NULL, &state);
        if (NULL != key) {
            key = strdup(sr_xpath_next_key_value(NULL, &state));
            break;
        }
        node = sr_xpath_next_node(NULL, &state);
        if (NULL == node) {
            break;
        }
    }

error:
    sr_xpath_recover(&state);
    return key;
}

int sysrepo_to_uci(ctx_t *ctx, sr_change_oper_t op, sr_val_t *old_val, sr_val_t *new_val, sr_notif_event_t event)
{
    char xpath[XPATH_MAX_LEN] = {0};
    char ucipath[XPATH_MAX_LEN] = {0};
    char *orig_xpath = NULL;
    char *key = NULL;
    int rc = SR_ERR_OK;

    if (SR_OP_CREATED == op || SR_OP_MODIFIED == op) {
        orig_xpath = new_val->xpath;
    } else if (SR_OP_DELETED == op) {
        orig_xpath = old_val->xpath;
    } else {
        return rc;
    }

    key = get_key_value(orig_xpath);

    /* add/change leafs */
    const int n_mappings = ARR_SIZE(table_sr_uci);
    for (int i = 0; i < n_mappings; i++) {
        snprintf(xpath, XPATH_MAX_LEN, table_sr_uci[i].xpath, key);
        snprintf(ucipath, XPATH_MAX_LEN, table_sr_uci[i].ucipath, key);
        if (string_eq(xpath, orig_xpath)) {
            rc = table_sr_uci[i].callback(ctx, op, xpath, ucipath, key, new_val);
            CHECK_RET(rc, error, "failed sysrepo operation %s", sr_strerror(rc));
        }
    }

error:
    if (NULL != key) {
        free(key);
    }
    return rc;
}

static int init_sysrepo_data(ctx_t *ctx)
{
    struct uci_element *e;
    struct uci_section *s;
    int rc;

    rc = uci_load(ctx->uctx, ctx->config_file_dhcp, &ctx->package);
    if (rc != UCI_OK) {
        fprintf(stderr, "No configuration (package): %s\n", ctx->config_file_dhcp);
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

    uci_foreach_element(&ctx->package->sections, e)
    {
        s = uci_to_section(e);
        if (string_eq(s->type, "dhcp")) {
            rc = parse_uci_config(ctx, s->e.name, "dhcp-server");
            CHECK_RET(rc, cleanup, "failed to add sysrepo data: %s", sr_strerror(rc));
        }
    }

    rc = uci_load(ctx->uctx, ctx->config_file_network, &ctx->package);
    if (rc != UCI_OK) {
        fprintf(stderr, "No configuration (package): %s\n", ctx->config_file_network);
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

    uci_foreach_element(&ctx->package->sections, e)
    {
        s = uci_to_section(e);
        if (string_eq(s->type, "interface")) {
            /* parse only interfaces with
             * option proto 'dhcpv6' */
            char ucipath[MAX_UCI_PATH] = {0};
            snprintf(ucipath, XPATH_MAX_LEN, "network.%s.proto", s->e.name);
            char *uci_val = calloc(1, MAX_UCI_PATH);
            rc = get_uci_item(ctx->uctx, ucipath, &uci_val);
            INF_MSG("test");
            if (SR_ERR_OK == rc && 0 == strcmp(uci_val, "dhcpv6")) {
                rc = parse_uci_config(ctx, s->e.name, "dhcp-client");
                CHECK_RET(rc, cleanup, "failed to add sysrepo data: %s", sr_strerror(rc));
            }
            free(uci_val);
        }
    }

    /* commit the changes to startup datastore */
    rc = sr_commit(ctx->startup_sess);
    CHECK_RET(rc, cleanup, "failed sr_commit: %s", sr_strerror(rc));

    return SR_ERR_OK;

cleanup:
    if (ctx->uctx) {
        uci_free_context(ctx->uctx);
        ctx->uctx = NULL;
    }
    return rc;
}

int sync_datastores(ctx_t *ctx)
{
    char startup_file[XPATH_MAX_LEN] = {0};
    int rc = SR_ERR_OK;
    struct stat st;

    /* check if the startup datastore is empty
     * by checking the content of the file */
    snprintf(startup_file, XPATH_MAX_LEN, "/etc/sysrepo/data/%s.startup", ctx->yang_model);

    if (stat(startup_file, &st) != 0) {
        ERR("Could not open sysrepo file %s", startup_file);
        return SR_ERR_INTERNAL;
    }

    if (0 == st.st_size) {
        /* parse uci config */
        rc = init_sysrepo_data(ctx);
        INF_MSG("copy uci data to sysrepo");
        CHECK_RET(rc, error, "failed to apply uci data to sysrepo: %s", sr_strerror(rc));
    } else {
        /* copy the sysrepo startup datastore to uci */
        INF_MSG("copy sysrepo data to uci");
        CHECK_RET(rc, error, "failed to apply sysrepo startup data to snabb: %s", sr_strerror(rc));
    }

error:
    return rc;
}

int load_startup_datastore(ctx_t *ctx)
{
    sr_conn_ctx_t *connection = NULL;
    sr_session_ctx_t *session = NULL;
    int rc = SR_ERR_OK;

    /* connect to sysrepo */
    rc = sr_connect(ctx->yang_model, SR_CONN_DEFAULT, &connection);
    CHECK_RET(rc, cleanup, "Error by sr_connect: %s", sr_strerror(rc));

    /* start session */
    rc = sr_session_start(connection, SR_DS_STARTUP, SR_SESS_CONFIG_ONLY, &session);
    CHECK_RET(rc, cleanup, "Error by sr_session_start: %s", sr_strerror(rc));

    ctx->startup_sess = session;
    ctx->startup_conn = connection;

    return rc;
cleanup:
    if (NULL != session) {
        sr_session_stop(session);
    }
    if (NULL != connection) {
        sr_disconnect(connection);
    }

    return rc;
}

void dhcp_v6_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
    char xpath[XPATH_MAX_LEN] = {0};
    ubus_ctx_t *ubus_ctx = req->priv;
    struct json_object *r = NULL, *o = NULL;
    char *json_result = NULL;
    int counter = 0;
    int rc = SR_ERR_OK;
    sr_val_t *sr_val = NULL;

    if (msg) {
        json_result = blobmsg_format_json(msg, true);
        r = json_tokener_parse(json_result);
    } else {
        goto cleanup;
    }

    json_object_object_get_ex(r, "device", &o);
    CHECK_NULL_MSG(o, &rc, cleanup, "could not get json object device");

    json_object_object_foreach(o, tmp_interface_key, tmp_interface_val)
    {
        /* get list of interfaces */
        if (NULL != tmp_interface_key && NULL != tmp_interface_val) {
            /* get list of leases */
            json_object_object_foreach(tmp_interface_val, tmp_device_key, tmp_device_val)
            {
                if (NULL != tmp_device_key && NULL != tmp_device_val) {
                    /* get list of IPv6 addresses */
                    int device_len = json_object_array_length(tmp_device_val);
                    int device_element;
                    for (device_element = 0; device_element < device_len; device_element++) {
                        struct json_object *l = NULL, *i = NULL;
                        l = json_object_array_get_idx(tmp_device_val, device_element);
                        counter = counter + 4;
                        json_object_object_get_ex(l, "ipv6", &i);
                        CHECK_NULL_MSG(i, &rc, cleanup, "could not get json object ipv6");
                        counter = counter + json_object_array_length(i);
                    }
                }
            }
        }
    }

    rc = sr_new_values(counter * 3, &sr_val);
    CHECK_RET(rc, cleanup, "failed sr_new_values: %s", sr_strerror(rc));

    counter = 0;
    json_object_object_foreach(o, interface_key, interface_val)
    {
        /* get list of interfaces */
        if (NULL != interface_key && NULL != interface_val) {
            /* get list of leases */
            json_object_object_foreach(interface_val, device_key, device_val)
            {
                if (NULL != device_key && NULL != device_val) {
                    /* get list of IPv6 addresses */
                    int device_len = json_object_array_length(device_val);
                    int device_element;
                    for (device_element = 0; device_element < device_len; device_element++) {
                        struct json_object *val = NULL, *v = NULL, *jobj_duid = NULL, *jobj_iaid = NULL;
                        long number = 0;
                        char *string_number = NULL;
                        val = json_object_array_get_idx(device_val, device_element);

                        json_object_object_get_ex(val, "duid", &jobj_duid);
                        CHECK_NULL_MSG(jobj_duid, &rc, cleanup, "could not get json object duid");
                        const char *duid = json_object_get_string(jobj_duid);
                        json_object_object_get_ex(val, "iaid", &jobj_iaid);
                        CHECK_NULL_MSG(jobj_iaid, &rc, cleanup, "could not get json object iaid");
                        const char *iaid = json_object_get_string(jobj_iaid);

                        json_object_object_get_ex(val, "hostname", &v);
                        CHECK_NULL_MSG(v, &rc, cleanup, "could not get json object hostname");
                        snprintf(xpath, XPATH_MAX_LEN, "/terastream-dhcp:dhcp-v6-leases/dhcp-v6-lease[duid='%s'][iaid='%s']/hostname", duid, iaid);
                        rc = sr_val_set_xpath(&sr_val[counter], xpath);
                        CHECK_RET(rc, cleanup, "failed sr_val_set_xpath: %s", sr_strerror(rc));
                        rc = sr_val_set_str_data(&sr_val[counter], SR_STRING_T, (char *) json_object_get_string(v));
                        CHECK_RET(rc, cleanup, "failed sr_val_set_str_data: %s", sr_strerror(rc));
                        counter++;

                        json_object_object_get_ex(val, "assigned", &v);
                        CHECK_NULL_MSG(v, &rc, cleanup, "could not get json object assigned");
                        string_number = (char *) json_object_get_string(v);
                        number = strtol(string_number, &string_number, 10);
                        snprintf(xpath, XPATH_MAX_LEN, "/terastream-dhcp:dhcp-v6-leases/dhcp-v6-lease[duid='%s'][iaid='%s']/assigned", duid, iaid);
                        rc = sr_val_set_xpath(&sr_val[counter], xpath);
                        CHECK_RET(rc, cleanup, "failed sr_val_set_xpath: %s", sr_strerror(rc));
                        (&sr_val[counter])->data.uint32_val = number;
                        (&sr_val[counter])->type = SR_UINT32_T;
                        counter++;

                        json_object_object_get_ex(val, "length", &v);
                        CHECK_NULL_MSG(v, &rc, cleanup, "could not get json object length");
                        string_number = (char *) json_object_get_string(v);
                        number = strtol(string_number, &string_number, 10);
                        snprintf(xpath, XPATH_MAX_LEN, "/terastream-dhcp:dhcp-v6-leases/dhcp-v6-lease[duid='%s'][iaid='%s']/length", duid, iaid);
                        rc = sr_val_set_xpath(&sr_val[counter], xpath);
                        CHECK_RET(rc, cleanup, "failed sr_val_set_xpath: %s", sr_strerror(rc));
                        (&sr_val[counter])->data.uint8_val = number;
                        (&sr_val[counter])->type = SR_UINT8_T;
                        counter++;

                        json_object_object_get_ex(val, "valid", &v);
                        CHECK_NULL_MSG(v, &rc, cleanup, "could not get json object valid");
                        string_number = (char *) json_object_get_string(v);
                        number = strtol(string_number, &string_number, 10);
                        snprintf(xpath, XPATH_MAX_LEN, "/terastream-dhcp:dhcp-v6-leases/dhcp-v6-lease[duid='%s'][iaid='%s']/valid", duid, iaid);
                        rc = sr_val_set_xpath(&sr_val[counter], xpath);
                        CHECK_RET(rc, cleanup, "failed sr_val_set_xpath: %s", sr_strerror(rc));
                        (&sr_val[counter])->data.int32_val = number;
                        (&sr_val[counter])->type = SR_INT32_T;
                        counter++;

                        json_object_object_get_ex(val, "ipv6", &v);
                        CHECK_NULL_MSG(v, &rc, cleanup, "could not get json object ipv6");
                        int ip_len = json_object_array_length(v);
                        int ip_element;
                        for (ip_element = 0; ip_element < ip_len; ip_element++) {
                            struct json_object *ip = json_object_array_get_idx(v, ip_element);
                            snprintf(xpath, XPATH_MAX_LEN, "/terastream-dhcp:dhcp-v6-leases/dhcp-v6-lease[duid='%s'][iaid='%s']/ipv6", duid, iaid);
                            rc = sr_val_set_xpath(&sr_val[counter], xpath);
                            CHECK_RET(rc, cleanup, "failed sr_val_set_xpath: %s", sr_strerror(rc));
                            rc = sr_val_set_str_data(&sr_val[counter], SR_STRING_T, (char *) json_object_get_string(ip));
                            CHECK_RET(rc, cleanup, "failed sr_val_set_str_data: %s", sr_strerror(rc));
                            counter++;
                        }
                    }
                }
            }
        }
    }

cleanup:
    if (SR_ERR_OK != rc) {
        sr_free_values(sr_val, counter);
        sr_val = NULL;
        counter = 0;
    }
    if (NULL != r) {
        json_object_put(r);
    }
    if (NULL != json_result) {
        free(json_result);
    }
    *ubus_ctx->values_cnt = counter;
    *ubus_ctx->values = sr_val;

    return;
}

int fill_dhcp_v6_data(ctx_t *ctx, char *xpath, sr_val_t **values, size_t *values_cnt)
{
    int rc = SR_ERR_OK;
    uint32_t id = 0;
    struct blob_buf buf = {0};
    ubus_ctx_t ubus_ctx = {0, 0, 0};
    int u_rc = UBUS_STATUS_OK;

    struct ubus_context *u_ctx = ubus_connect(NULL);
    if (u_ctx == NULL) {
        ERR_MSG("Could not connect to ubus");
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

    blob_buf_init(&buf, 0);
    u_rc = ubus_lookup_id(u_ctx, "dhcp", &id);
    if (UBUS_STATUS_OK != u_rc) {
        ERR("ubus [%d]: no object asterisk\n", u_rc);
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

    ubus_ctx.ctx = ctx;
    ubus_ctx.values = values;
    ubus_ctx.values_cnt = values_cnt;
    u_rc = ubus_invoke(u_ctx, id, "ipv6leases", buf.head, dhcp_v6_cb, &ubus_ctx, 0);
    if (UBUS_STATUS_OK != u_rc) {
        ERR("ubus [%d]: no object asterisk\n", u_rc);
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

cleanup:
    if (NULL != u_ctx) {
        ubus_free(u_ctx);
        blob_buf_free(&buf);
    }
    return rc;
}

void dhcp_v4_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
    char xpath[XPATH_MAX_LEN] = {0};
    ubus_ctx_t *ubus_ctx = req->priv;
    struct json_object *r = NULL, *v = NULL;
    char *json_result = NULL;
    int counter = 0;
    int rc = SR_ERR_OK;
    sr_val_t *sr_val = NULL;

    if (msg) {
        json_result = blobmsg_format_json(msg, true);
        r = json_tokener_parse(json_result);
    } else {
        goto cleanup;
    }

    /* get array size */
    json_object_object_foreach(r, key_tmp, val_tmp)
    {
        if (NULL != key_tmp && NULL != val_tmp) {
            counter++;
        }
    }

    counter = counter * 6;

    rc = sr_new_values(counter * 3, &sr_val);
    CHECK_RET(rc, cleanup, "failed sr_new_values: %s", sr_strerror(rc));

    counter = 0;
    json_object_object_foreach(r, key, val)
    {
        json_object_object_get_ex(val, "leasetime", &v);
        CHECK_NULL_MSG(v, &rc, cleanup, "could not get json object leasetime");
        snprintf(xpath, XPATH_MAX_LEN, "/terastream-dhcp:dhcp-v4-leases/dhcp-v4-lease[name='%s']/leasetime", key);
        rc = sr_val_set_xpath(&sr_val[counter], xpath);
        CHECK_RET(rc, cleanup, "failed sr_val_set_xpath: %s", sr_strerror(rc));
        rc = sr_val_set_str_data(&sr_val[counter], SR_STRING_T, (char *) json_object_get_string(v));
        CHECK_RET(rc, cleanup, "failed sr_val_set_str_data: %s", sr_strerror(rc));
        counter++;

        json_object_object_get_ex(val, "hostname", &v);
        CHECK_NULL_MSG(v, &rc, cleanup, "could not get json object hostname");
        snprintf(xpath, XPATH_MAX_LEN, "/terastream-dhcp:dhcp-v4-leases/dhcp-v4-lease[name='%s']/hostname", key);
        rc = sr_val_set_xpath(&sr_val[counter], xpath);
        CHECK_RET(rc, cleanup, "failed sr_val_set_xpath: %s", sr_strerror(rc));
        rc = sr_val_set_str_data(&sr_val[counter], SR_STRING_T, (char *) json_object_get_string(v));
        CHECK_RET(rc, cleanup, "failed sr_val_set_str_data: %s", sr_strerror(rc));
        counter++;

        json_object_object_get_ex(val, "ipaddr", &v);
        CHECK_NULL_MSG(v, &rc, cleanup, "could not get json object ipaddr");
        snprintf(xpath, XPATH_MAX_LEN, "/terastream-dhcp:dhcp-v4-leases/dhcp-v4-lease[name='%s']/ipaddr", key);
        rc = sr_val_set_xpath(&sr_val[counter], xpath);
        CHECK_RET(rc, cleanup, "failed sr_val_set_xpath: %s", sr_strerror(rc));
        rc = sr_val_set_str_data(&sr_val[counter], SR_STRING_T, (char *) json_object_get_string(v));
        CHECK_RET(rc, cleanup, "failed sr_val_set_str_data: %s", sr_strerror(rc));
        counter++;

        json_object_object_get_ex(val, "macaddr", &v);
        CHECK_NULL_MSG(v, &rc, cleanup, "could not get json object macaddr");
        snprintf(xpath, XPATH_MAX_LEN, "/terastream-dhcp:dhcp-v4-leases/dhcp-v4-lease[name='%s']/macaddr", key);
        rc = sr_val_set_xpath(&sr_val[counter], xpath);
        CHECK_RET(rc, cleanup, "failed sr_val_set_xpath: %s", sr_strerror(rc));
        rc = sr_val_set_str_data(&sr_val[counter], SR_STRING_T, (char *) json_object_get_string(v));
        CHECK_RET(rc, cleanup, "failed sr_val_set_str_data: %s", sr_strerror(rc));
        counter++;

        json_object_object_get_ex(val, "device", &v);
        CHECK_NULL_MSG(v, &rc, cleanup, "could not get json object device");
        snprintf(xpath, XPATH_MAX_LEN, "/terastream-dhcp:dhcp-v4-leases/dhcp-v4-lease[name='%s']/device", key);
        rc = sr_val_set_xpath(&sr_val[counter], xpath);
        CHECK_RET(rc, cleanup, "failed sr_val_set_xpath: %s", sr_strerror(rc));
        rc = sr_val_set_str_data(&sr_val[counter], SR_STRING_T, (char *) json_object_get_string(v));
        CHECK_RET(rc, cleanup, "failed sr_val_set_str_data: %s", sr_strerror(rc));
        counter++;

        json_object_object_get_ex(val, "connected", &v);
        CHECK_NULL_MSG(v, &rc, cleanup, "could not get json object connected");
        snprintf(xpath, XPATH_MAX_LEN, "/terastream-dhcp:dhcp-v4-leases/dhcp-v4-lease[name='%s']/connected", key);
        rc = sr_val_set_xpath(&sr_val[counter], xpath);
        CHECK_RET(rc, cleanup, "failed sr_val_set_xpath: %s", sr_strerror(rc));
        (&sr_val[counter])->data.bool_val = json_object_get_boolean(v);
        (&sr_val[counter])->type = SR_BOOL_T;
        counter++;
    }

cleanup:
    if (SR_ERR_OK != rc) {
        sr_free_values(sr_val, counter);
        sr_val = NULL;
        counter = 0;
    }
    if (NULL != r) {
        json_object_put(r);
    }
    if (NULL != json_result) {
        free(json_result);
    }
    *ubus_ctx->values_cnt = counter;
    *ubus_ctx->values = sr_val;
    return;
}

int fill_dhcp_v4_data(ctx_t *ctx, char *xpath, sr_val_t **values, size_t *values_cnt)
{
    int rc = SR_ERR_OK;
    uint32_t id = 0;
    struct blob_buf buf = {0};
    ubus_ctx_t ubus_ctx = {0, 0, 0};
    int u_rc = UBUS_STATUS_OK;

    struct ubus_context *u_ctx = ubus_connect(NULL);
    if (u_ctx == NULL) {
        ERR_MSG("Could not connect to ubus");
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

    blob_buf_init(&buf, 0);
    u_rc = ubus_lookup_id(u_ctx, "router.network", &id);
    if (UBUS_STATUS_OK != u_rc) {
        ERR("ubus [%d]: no object asterisk\n", u_rc);
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

    ubus_ctx.ctx = ctx;
    ubus_ctx.values = values;
    ubus_ctx.values_cnt = values_cnt;
    u_rc = ubus_invoke(u_ctx, id, "leases", buf.head, dhcp_v4_cb, &ubus_ctx, 0);
    if (UBUS_STATUS_OK != u_rc) {
        ERR("ubus [%d]: no object asterisk\n", u_rc);
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

cleanup:
    if (NULL != u_ctx) {
        ubus_free(u_ctx);
        blob_buf_free(&buf);
    }
    return rc;
}
