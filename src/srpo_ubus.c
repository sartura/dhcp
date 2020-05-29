#include <libubus.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>

#include "srpo_ubus.h"

typedef struct {
	srpo_ubus_transform_data_cb transform_data_cb;
	srpo_ubus_result_values_t **values;
} srpo_ubus_invoke_wrapper_t;

static void ubus_data_cb(struct ubus_request *req, int type, struct blob_attr *msg);

srpo_ubus_error_e srpo_ubus_data_get(srpo_ubus_result_values_t **values, size_t *num_values, srpo_ubus_transform_template_t *transform, void *private_data)
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
