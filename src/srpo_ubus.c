#include <libubus.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>

#include "utils/memory.h"

#include "srpo_ubus.h"

typedef struct {
	srpo_ubus_transform_data_cb transform_data_cb;
	srpo_ubus_result_values_t *values;
} srpo_ubus_invoke_wrapper_t;

static void ubus_data_cb(struct ubus_request *req, int type, struct blob_attr *msg);

srpo_ubus_error_e srpo_ubus_data_get(srpo_ubus_result_values_t *values, srpo_ubus_transform_template_t *transform)
{
	srpo_ubus_error_e error = SRPO_UBUS_ERR_OK;
	struct ubus_context *ubus_ctx = NULL;
	struct blob_buf buf = {0};
	int ubus_error = UBUS_STATUS_OK;
	uint32_t id = 0;
	srpo_ubus_invoke_wrapper_t *ubus_wrapper = &((srpo_ubus_invoke_wrapper_t) {.transform_data_cb = transform->transform_data_cb, .values = values});
	
	ubus_ctx = ubus_connect(NULL);
	if (ubus_ctx == NULL) {
		error = SRPO_UBUS_ERR_INTERNAL;
		goto cleanup;
	}

	blob_buf_init(&buf, 0);
	ubus_error = ubus_lookup_id(ubus_ctx, transform->lookup_path, &id);
	if (ubus_error != UBUS_STATUS_OK) {
		error = SRPO_UBUS_ERR_INTERNAL;
		goto cleanup;
	}

	ubus_error = ubus_invoke(ubus_ctx, id, transform->method, buf.head, ubus_data_cb, ubus_wrapper, 0);
	if (ubus_error != UBUS_STATUS_OK) {
		error = SRPO_UBUS_ERR_INTERNAL;
		goto cleanup;
	}

cleanup:
	if (ubus_ctx != NULL) {
		ubus_free(ubus_ctx);
		blob_buf_free(&buf);
	}
	return error;
}

const char *srpo_ubus_error_description_get(srpo_ubus_error_e error)
{
	return "ok";
}

static void ubus_data_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	char *json_result = NULL;
	srpo_ubus_invoke_wrapper_t *private_data = req->priv;

	if (msg == NULL) {
		return;
	}

	json_result = blobmsg_format_json(msg, true);
	private_data->transform_data_cb(json_result, private_data->values);

	return;
}

srpo_ubus_error_e srpo_ubus_result_values_add(srpo_ubus_result_values_t *values, const char *value, const char *xpath_template, const char *xpath_value)
{
	srpo_ubus_error_e error = SRPO_UBUS_ERR_OK;
	size_t xpath_len = 0;

	values->values = xrealloc(values->values, sizeof(srpo_ubus_result_value_t) * (values->num_values + 1));
	//TODO check for buffer overflow
	values->values[values->num_values].value = xstrdup(value);
	//TODO check for buffer overflow
	xpath_len = strlen(xpath_template) + strlen(xpath_value);
	values->values[values->num_values].xpath = xmalloc(xpath_len + 1);
	snprintf(values->values[values->num_values].xpath, xpath_len, xpath_template, xpath_value);

	values->num_values++;

	return error;
}

void srpo_ubus_init_result_values(srpo_ubus_result_values_t **values)
{
	*values = xmalloc(sizeof(srpo_ubus_result_values_t));
	(*values)->num_values = 0;
	(*values)->values = NULL;
}

void srpo_ubus_free_result_values(srpo_ubus_result_values_t *values)
{
        for(size_t i = 0; i < values->num_values; i++) {
                FREE_SAFE(values->values[i].xpath);
                FREE_SAFE(values->values[i].value);
        }

        FREE_SAFE(values->values);
        FREE_SAFE(values);
}
