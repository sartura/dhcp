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
#include <sr_uci.h>

#include "parse.h"

static double parse_leasetime(char *val) {
    char *endptr = NULL;
    double time = strcmp(val, "infinite") ? strtod(val, &endptr) : UINT32_MAX;

    if (time && endptr && endptr[0]) {
        if (endptr[0] == 's') {
            time *= 1;
        } else if (endptr[0] == 'm') {
            time *= 60;
        } else if (endptr[0] == 'h') {
            time *= 3600;
        } else if (endptr[0] == 'd') {
            time *= 24 * 3600;
        } else if (endptr[0] == 'w') {
            time *= 7 * 24 * 3600;
        } else {
            goto cleanup;
        }
    }

    if (time < 60) {
        time = 60;
    }

    return time;

cleanup:
    return -1;
}

/* transform leasetime from seconds to <number>s */
int sr_leasetime_cb(sr_ctx_t *ctx, sr_change_oper_t op, sr_val_t *old_val, sr_val_t *new_val, char *xpath, char *ucipath) {
    int rc = SR_ERR_OK;

    /* add/change leafs */
    if (SR_OP_CREATED == op || SR_OP_MODIFIED == op) {
        char *mem = sr_val_to_str(new_val);
        CHECK_NULL(mem, &rc, cleanup, "sr_print_val %s", sr_strerror(rc));
        int len = strlen(mem) + 2;
        char *leasetime = malloc(sizeof(char) * len);
        CHECK_NULL_MSG(leasetime, &rc, cleanup, "malloc failed");
        snprintf(leasetime, len, "%ss", mem);
        rc = set_uci_item(ctx->uctx, ucipath, leasetime);
        free(leasetime);
        free(mem);
        CHECK_RET(rc, cleanup, "set_uci_item %x", rc);
    } else if (SR_OP_DELETED == op) {
        rc = uci_del(ctx, ucipath);
        CHECK_RET(rc, cleanup, "uci_del %d", rc);
    }

cleanup:
    return rc;
}

/* transform leasetime 12h to seconds */
int uci_leasetime_cb(sr_ctx_t *ctx, char *xpath, char *ucipath, sr_edit_flag_t flag, void *data) {
    int rc = SR_ERR_OK;
    char *uci_val = NULL;

    rc = get_uci_item(ctx->uctx, ucipath, &uci_val);
    if (UCI_OK == rc) {
        char leasetime[12];
        snprintf(leasetime, 12, "%.0lf", parse_leasetime(uci_val));
        rc = sr_set_item_str(ctx->startup_sess, xpath, leasetime, flag);
        free(uci_val);
        CHECK_RET(rc, cleanup, "failed sr_set_item_str: %s", sr_strerror(rc));
    }

cleanup:
    return rc;
}

/* transform sysrepo leaf stop to uci option limit, limit = stop - start + 1 */
int sr_stop_cb(sr_ctx_t *ctx, sr_change_oper_t op, sr_val_t *old_val, sr_val_t *new_val, char *xpath, char *ucipath) {
    int rc = SR_ERR_OK;
    sr_val_t *value = NULL;
    char *limit_xpath = NULL;
    char *key = NULL;

    /* add/change leafs */
    if (SR_OP_CREATED == op || SR_OP_MODIFIED == op) {
        /* get start uci option and convert it to string */
        key = get_key_value(xpath);
        CHECK_NULL(key, &rc, cleanup, "could not extract key from %s", xpath);

        limit_xpath = new_path_key("/terastream-dhcp:dhcp-servers/dhcp-server[name='%s']/start", key);
        CHECK_NULL_MSG(limit_xpath, &rc, cleanup, "failed to generate path");

        rc = sr_get_item(ctx->sess, limit_xpath, &value);
        CHECK_RET(rc, cleanup, "failed sr_get_item %s", sr_strerror(rc));
        unsigned long limit = new_val->data.uint32_val - value->data.uint32_val + 1;
        char limit_string[12];
        snprintf(limit_string, 12, "%lu", limit);

        rc = set_uci_item(ctx->uctx, ucipath, limit_string);
        CHECK_RET(rc, cleanup, "set_uci_item %x", rc);
    } else if (SR_OP_DELETED == op) {
        rc = uci_del(ctx, ucipath);
        CHECK_RET(rc, cleanup, "uci_del %d", rc);
    }

cleanup:
    del_path_key(&limit_xpath);
    if (NULL != value) {
        sr_free_val(value);
    }
    if (NULL != key) {
        free(key);
    }
    return rc;
}

/* transform uci option limit to stop leaf, stop = start + limit - 1*/
int uci_stop_cb(sr_ctx_t *ctx, char *xpath, char *ucipath, sr_edit_flag_t flag, void *data) {
    int rc = SR_ERR_OK;
    int uci_ret = UCI_OK;
    char *key = NULL;
    char *uci_val = NULL;
    char *start_val = NULL;
    char *start_ucipath = NULL;

    /* get start uci option and convert it to string */
    key = get_key_value(xpath);
    CHECK_NULL(key, &rc, cleanup, "could not extract key from %s", xpath);

    start_ucipath = new_path_key("dhcp.%s.start", key);
    CHECK_NULL_MSG(start_ucipath, &rc, cleanup, "failed to generate path");

    char *endptr = NULL;
    unsigned long start;
    uci_ret = get_uci_item(ctx->uctx, start_ucipath, &start_val);
    if (UCI_ERR_NOTFOUND == uci_ret) {
        start = 100;
    } else if (UCI_OK == uci_ret) {
        UCI_CHECK_RET(uci_ret, &rc, cleanup, "get_uci_item %d %s", uci_ret, start_ucipath);
        start = strtoul(start_val, &endptr, 10);
        if (*endptr || start > UINT8_MAX) {
            rc = SR_ERR_INTERNAL;
            goto cleanup;
        }
    } else {
        goto cleanup;
    }

    /* get limit uci option and convert it to string */
    uci_ret = get_uci_item(ctx->uctx, ucipath, &uci_val);
    if (UCI_OK != uci_ret) {
        goto cleanup;
    }
    UCI_CHECK_RET(uci_ret, &rc, cleanup, "get_uci_item %d %s", uci_ret, ucipath);

    unsigned long limit = strtoul(uci_val, &endptr, 10);
    if (*endptr || limit > UINT8_MAX) {
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

    unsigned long stop = start + limit - 1;
    char stop_string[12];
    snprintf(stop_string, 12, "%lu", stop);

    rc = sr_set_item_str(ctx->startup_sess, xpath, stop_string, flag);
    CHECK_RET(rc, cleanup, "failed sr_set_item_str: %s", sr_strerror(rc));

cleanup:
    del_path_key(&start_ucipath);
    if (NULL != key) {
        free(key);
    }
    if (NULL != start_val) {
        free(start_val);
    }
    if (NULL != uci_val) {
        free(uci_val);
    }
    return rc;
}

/* parse only interfaces with option proto 'dhcpv6' */
int uci_dhcpv6_option_cb(sr_ctx_t *ctx, char *xpath, char *ucipath, sr_edit_flag_t flag, void *data) {
    int rc = SR_ERR_OK;
    char *uci_val = NULL, *if_ucipath = NULL;
    bool check_passed = false;
    char *key = NULL;

    /* get start uci option and convert it to string */
    key = get_key_value(xpath);
    CHECK_NULL(key, &rc, cleanup, "could not extract key from %s", xpath);

    int len = strlen(key) + 18;
    if_ucipath = malloc(sizeof(char) * len);
    CHECK_NULL_MSG(if_ucipath, &rc, cleanup, "malloc failed");
    snprintf(if_ucipath, len, "network.%s.proto", key);

    rc = get_uci_item(ctx->uctx, if_ucipath, &uci_val);
    if (SR_ERR_OK == rc && 0 == strcmp(uci_val, "dhcpv6")) {
        check_passed= true;
    }

cleanup:
    if (NULL != key) {
        free(key);
    }
    if (NULL != uci_val) {
        free(uci_val);
    }
    if (NULL != if_ucipath) {
        free(if_ucipath);
    }
    return true == check_passed ? uci_option_cb(ctx, xpath, ucipath, flag, data) : SR_ERR_OK;
}

/* parse only interfaces with option proto 'dhcpv6' */
int uci_dhcpv6_boolean_cb(sr_ctx_t *ctx, char *xpath, char *ucipath, sr_edit_flag_t flag, void *data) {
    int rc = SR_ERR_OK;
    char *uci_val = NULL, *if_ucipath = NULL;
    bool check_passed = false;
    char *key = NULL;

    /* get start uci option and convert it to string */
    key = get_key_value(xpath);
    CHECK_NULL(key, &rc, cleanup, "could not extract key from %s", xpath);

    int len = strlen(key) + 18;
    if_ucipath = malloc(sizeof(char) * len);
    CHECK_NULL_MSG(if_ucipath, &rc, cleanup, "malloc failed");
    snprintf(if_ucipath, len, "network.%s.proto", key);

    rc = get_uci_item(ctx->uctx, if_ucipath, &uci_val);
    if (SR_ERR_OK == rc && 0 == strcmp(uci_val, "dhcpv6")) {
        check_passed= true;
    }

cleanup:
    if (NULL != key) {
        free(key);
    }
    if (NULL != uci_val) {
        free(uci_val);
    }
    if (NULL != if_ucipath) {
        free(if_ucipath);
    }
    return true == check_passed ? uci_boolean_cb(ctx, xpath, ucipath, flag, data) : SR_ERR_OK;
}

/* trnasform uci list to sysrepo leaf */
int sr_list_option_cb(sr_ctx_t *ctx, sr_change_oper_t op, sr_val_t *old_val, sr_val_t *new_val, char *xpath, char *ucipath) {
    int rc = SR_ERR_OK;
    int uci_ret = UCI_OK;
    struct uci_ptr ptr = {};
    char *set_path = NULL;


    if (SR_OP_DELETED == op || SR_OP_MODIFIED == op) {
        int len = strlen(ucipath) + strlen(old_val->data.string_val) + 2;
        set_path = malloc(sizeof(char) * len);
        CHECK_NULL_MSG(set_path, &rc, cleanup, "malloc failed");
        sprintf(set_path, "%s%s%s", ucipath, "=", old_val->data.string_val);

        uci_ret = uci_lookup_ptr(ctx->uctx, &ptr, set_path, true);
        UCI_CHECK_RET(uci_ret, &rc, cleanup, "lookup_pointer %d %s", uci_ret, set_path);

        uci_ret = uci_del_list(ctx->uctx, &ptr);
        UCI_CHECK_RET(uci_ret, &rc, cleanup, "uci_set %d %s", uci_ret, set_path);

        uci_ret = uci_save(ctx->uctx, ptr.p);
        UCI_CHECK_RET(uci_ret, &rc, cleanup, "uci_save %d %s", uci_ret, set_path);

        uci_ret = uci_commit(ctx->uctx, &(ptr.p), false);
        UCI_CHECK_RET(uci_ret, &rc, cleanup, "uci_commit %d %s", uci_ret, set_path);
    }

    if (SR_OP_CREATED == op || SR_OP_MODIFIED == op) {
        int len = strlen(ucipath) + strlen(new_val->data.string_val) + 2;
        set_path = malloc(sizeof(char) * len);
        CHECK_NULL_MSG(set_path, &rc, cleanup, "malloc failed");
        sprintf(set_path, "%s%s%s", ucipath, "=", new_val->data.string_val);

        rc = uci_lookup_ptr(ctx->uctx, &ptr, set_path, true);
        UCI_CHECK_RET(uci_ret, &rc, cleanup, "lookup_pointer %d %s", uci_ret, set_path);

        rc = uci_add_list(ctx->uctx, &ptr);
        UCI_CHECK_RET(uci_ret, &rc, cleanup, "uci_set %d %s", uci_ret, set_path);

        rc = uci_save(ctx->uctx, ptr.p);
        UCI_CHECK_RET(uci_ret, &rc, cleanup, "uci_save %d %s", uci_ret, set_path);

        rc = uci_commit(ctx->uctx, &(ptr.p), false);
        UCI_CHECK_RET(uci_ret, &rc, cleanup, "uci_commit %d %s", uci_ret, set_path);
    }

cleanup:
    if (NULL != set_path) {
        free(set_path);
    }
    return rc;
}


int sync_datastores(sr_ctx_t *ctx)
{
    char *startup_file = NULL;
    int rc = SR_ERR_OK;
    struct stat st;

    /* check if the startup datastore is empty
     * by checking the content of the file */
    int len = strlen(ctx->yang_model) + 28;
    startup_file = malloc(sizeof(char) * len);
    CHECK_NULL_MSG(startup_file, &rc, cleanup, "malloc failed");

    snprintf(startup_file, len, "/etc/sysrepo/data/%s.startup", ctx->yang_model);

    if (stat(startup_file, &st) != 0) {
        ERR("Could not open sysrepo file %s", startup_file);
        return SR_ERR_INTERNAL;
    }

    if (0 == st.st_size) {
        /* parse uci config */
        INF_MSG("copy uci data to sysrepo");
        const char *network[] = {"interface",0};
        rc = sr_uci_init_data(ctx, "network", network);
        CHECK_RET(rc, cleanup, "failed to apply uci data to sysrepo: %s", sr_strerror(rc));
        const char *dhcp[] = {"dhcp", "domain",0};
        rc = sr_uci_init_data(ctx, "dhcp", dhcp);
        CHECK_RET(rc, cleanup, "failed to apply uci data to sysrepo: %s", sr_strerror(rc));
    } else {
        /* copy the sysrepo startup datastore to uci */
        INF_MSG("copy sysrepo data to uci");
        CHECK_RET(rc, cleanup, "failed to apply sysrepo startup data to snabb: %s", sr_strerror(rc));
    }

cleanup:
    if (NULL != startup_file) {
        free(startup_file);
    }
    return rc;
}

void dhcp_v6_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
    char *xpath = NULL;
    sr_values_t *sr_values = req->priv;
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

                        int len = strlen(duid) + strlen(iaid) + 76;
                        xpath = malloc(sizeof(char) * len);
                        CHECK_NULL_MSG(xpath, &rc, cleanup, "malloc failed");

                        json_object_object_get_ex(val, "hostname", &v);
                        CHECK_NULL_MSG(v, &rc, cleanup, "could not get json object hostname");
                        snprintf(xpath, len, "/terastream-dhcp:dhcp-v6-leases/dhcp-v6-lease[duid='%s'][iaid='%s']/hostname", duid, iaid);
                        rc = sr_val_set_xpath(&sr_val[counter], xpath);
                        CHECK_RET(rc, cleanup, "failed sr_val_set_xpath: %s", sr_strerror(rc));
                        rc = sr_val_set_str_data(&sr_val[counter], SR_STRING_T, (char *) json_object_get_string(v));
                        CHECK_RET(rc, cleanup, "failed sr_val_set_str_data: %s", sr_strerror(rc));
                        counter++;

                        json_object_object_get_ex(val, "assigned", &v);
                        CHECK_NULL_MSG(v, &rc, cleanup, "could not get json object assigned");
                        string_number = (char *) json_object_get_string(v);
                        number = strtol(string_number, &string_number, 10);
                        snprintf(xpath, len, "/terastream-dhcp:dhcp-v6-leases/dhcp-v6-lease[duid='%s'][iaid='%s']/assigned", duid, iaid);
                        rc = sr_val_set_xpath(&sr_val[counter], xpath);
                        CHECK_RET(rc, cleanup, "failed sr_val_set_xpath: %s", sr_strerror(rc));
                        (&sr_val[counter])->data.uint32_val = number;
                        (&sr_val[counter])->type = SR_UINT32_T;
                        counter++;

                        json_object_object_get_ex(val, "length", &v);
                        CHECK_NULL_MSG(v, &rc, cleanup, "could not get json object length");
                        string_number = (char *) json_object_get_string(v);
                        number = strtol(string_number, &string_number, 10);
                        snprintf(xpath, len, "/terastream-dhcp:dhcp-v6-leases/dhcp-v6-lease[duid='%s'][iaid='%s']/length", duid, iaid);
                        rc = sr_val_set_xpath(&sr_val[counter], xpath);
                        CHECK_RET(rc, cleanup, "failed sr_val_set_xpath: %s", sr_strerror(rc));
                        (&sr_val[counter])->data.uint8_val = number;
                        (&sr_val[counter])->type = SR_UINT8_T;
                        counter++;

                        json_object_object_get_ex(val, "valid", &v);
                        CHECK_NULL_MSG(v, &rc, cleanup, "could not get json object valid");
                        string_number = (char *) json_object_get_string(v);
                        number = strtol(string_number, &string_number, 10);
                        snprintf(xpath, len, "/terastream-dhcp:dhcp-v6-leases/dhcp-v6-lease[duid='%s'][iaid='%s']/valid", duid, iaid);
                        rc = sr_val_set_xpath(&sr_val[counter], xpath);
                        CHECK_RET(rc, cleanup, "failed sr_val_set_xpath: %s", sr_strerror(rc));
                        (&sr_val[counter])->data.uint32_val = number;
                        (&sr_val[counter])->type = SR_UINT32_T;
                        counter++;

                        json_object_object_get_ex(val, "ipv6", &v);
                        CHECK_NULL_MSG(v, &rc, cleanup, "could not get json object ipv6");
                        int ip_len = json_object_array_length(v);
                        int ip_element;
                        for (ip_element = 0; ip_element < ip_len; ip_element++) {
                            struct json_object *ip = json_object_array_get_idx(v, ip_element);
                            snprintf(xpath, len, "/terastream-dhcp:dhcp-v6-leases/dhcp-v6-lease[duid='%s'][iaid='%s']/ipv6", duid, iaid);
                            rc = sr_val_set_xpath(&sr_val[counter], xpath);
                            CHECK_RET(rc, cleanup, "failed sr_val_set_xpath: %s", sr_strerror(rc));
                            rc = sr_val_set_str_data(&sr_val[counter], SR_STRING_T, (char *) json_object_get_string(ip));
                            CHECK_RET(rc, cleanup, "failed sr_val_set_str_data: %s", sr_strerror(rc));
                            counter++;
                        }
                        if (NULL != xpath) {
                            free(xpath);
                            xpath = NULL;
                        }
                    }
                }
            }
        }
    }

cleanup:
    if (NULL != xpath) {
        free(xpath);
    }
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
    *sr_values->values_cnt = counter;
    *sr_values->values = sr_val;

    return;
}

int fill_dhcp_v6_data(sr_ctx_t *ctx, char *xpath, sr_val_t **values, size_t *values_cnt)
{
    int rc = SR_ERR_OK;
    uint32_t id = 0;
    struct blob_buf buf = {0};
    sr_values_t sr_values = {0, 0, 0};
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

    sr_values.ctx = ctx;
    sr_values.values = values;
    sr_values.values_cnt = values_cnt;
    u_rc = ubus_invoke(u_ctx, id, "ipv6leases", buf.head, dhcp_v6_cb, &sr_values, 0);
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
    char *xpath = NULL;
    sr_values_t *sr_values = req->priv;
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
        long number = 0;
        char *string_number = NULL;

        int len = strlen(key) + 66;
        xpath = malloc(sizeof(char) * len);
        CHECK_NULL_MSG(xpath, &rc, cleanup, "malloc failed");

        json_object_object_get_ex(val, "leasetime", &v);
        CHECK_NULL_MSG(v, &rc, cleanup, "could not get json object leasetime");
        string_number = (char *) json_object_get_string(v);
        number = strtol(string_number, &string_number, 10);
        snprintf(xpath, len, "/terastream-dhcp:dhcp-v4-leases/dhcp-v4-lease[name='%s']/leasetime", key);
        rc = sr_val_set_xpath(&sr_val[counter], xpath);
        CHECK_RET(rc, cleanup, "failed sr_val_set_xpath: %s", sr_strerror(rc));
        (&sr_val[counter])->data.uint32_val = number;
        (&sr_val[counter])->type = SR_UINT32_T;
        counter++;

        json_object_object_get_ex(val, "hostname", &v);
        CHECK_NULL_MSG(v, &rc, cleanup, "could not get json object hostname");
        snprintf(xpath, len, "/terastream-dhcp:dhcp-v4-leases/dhcp-v4-lease[name='%s']/hostname", key);
        rc = sr_val_set_xpath(&sr_val[counter], xpath);
        CHECK_RET(rc, cleanup, "failed sr_val_set_xpath: %s", sr_strerror(rc));
        rc = sr_val_set_str_data(&sr_val[counter], SR_STRING_T, (char *) json_object_get_string(v));
        CHECK_RET(rc, cleanup, "failed sr_val_set_str_data: %s", sr_strerror(rc));
        counter++;

        json_object_object_get_ex(val, "ipaddr", &v);
        CHECK_NULL_MSG(v, &rc, cleanup, "could not get json object ipaddr");
        snprintf(xpath, len, "/terastream-dhcp:dhcp-v4-leases/dhcp-v4-lease[name='%s']/ipaddr", key);
        rc = sr_val_set_xpath(&sr_val[counter], xpath);
        CHECK_RET(rc, cleanup, "failed sr_val_set_xpath: %s", sr_strerror(rc));
        rc = sr_val_set_str_data(&sr_val[counter], SR_STRING_T, (char *) json_object_get_string(v));
        CHECK_RET(rc, cleanup, "failed sr_val_set_str_data: %s", sr_strerror(rc));
        counter++;

        json_object_object_get_ex(val, "macaddr", &v);
        CHECK_NULL_MSG(v, &rc, cleanup, "could not get json object macaddr");
        snprintf(xpath, len, "/terastream-dhcp:dhcp-v4-leases/dhcp-v4-lease[name='%s']/macaddr", key);
        rc = sr_val_set_xpath(&sr_val[counter], xpath);
        CHECK_RET(rc, cleanup, "failed sr_val_set_xpath: %s", sr_strerror(rc));
        rc = sr_val_set_str_data(&sr_val[counter], SR_STRING_T, (char *) json_object_get_string(v));
        CHECK_RET(rc, cleanup, "failed sr_val_set_str_data: %s", sr_strerror(rc));
        counter++;

        json_object_object_get_ex(val, "device", &v);
        CHECK_NULL_MSG(v, &rc, cleanup, "could not get json object device");
        snprintf(xpath, len, "/terastream-dhcp:dhcp-v4-leases/dhcp-v4-lease[name='%s']/device", key);
        rc = sr_val_set_xpath(&sr_val[counter], xpath);
        CHECK_RET(rc, cleanup, "failed sr_val_set_xpath: %s", sr_strerror(rc));
        rc = sr_val_set_str_data(&sr_val[counter], SR_STRING_T, (char *) json_object_get_string(v));
        CHECK_RET(rc, cleanup, "failed sr_val_set_str_data: %s", sr_strerror(rc));
        counter++;

        json_object_object_get_ex(val, "connected", &v);
        CHECK_NULL_MSG(v, &rc, cleanup, "could not get json object connected");
        snprintf(xpath, len, "/terastream-dhcp:dhcp-v4-leases/dhcp-v4-lease[name='%s']/connected", key);
        rc = sr_val_set_xpath(&sr_val[counter], xpath);
        CHECK_RET(rc, cleanup, "failed sr_val_set_xpath: %s", sr_strerror(rc));
        (&sr_val[counter])->data.bool_val = json_object_get_boolean(v);
        (&sr_val[counter])->type = SR_BOOL_T;
        counter++;

        if (NULL != xpath) {
            free(xpath);
            xpath = NULL;
        }
    }

cleanup:
    if (NULL != xpath) {
        free(xpath);
    }
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
    *sr_values->values_cnt = counter;
    *sr_values->values = sr_val;
    return;
}

int fill_dhcp_v4_data(sr_ctx_t *ctx, char *xpath, sr_val_t **values, size_t *values_cnt)
{
    int rc = SR_ERR_OK;
    uint32_t id = 0;
    struct blob_buf buf = {0};
    sr_values_t sr_values = {0, 0, 0};
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

    sr_values.ctx = ctx;
    sr_values.values = values;
    sr_values.values_cnt = values_cnt;
    u_rc = ubus_invoke(u_ctx, id, "leases", buf.head, dhcp_v4_cb, &sr_values, 0);
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
