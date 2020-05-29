#include "srpo_ubus.h"

srpo_ubus_error_e srpo_ubus_data_get(srpo_ubus_result_values_t **values, size_t *num_values, srpo_ubus_transform_template_t *transform, void *private_data)
{
	return SRPO_UBUS_ERR_OK;
}

const char *srpo_ubus_error_description_get(srpo_ubus_error_e error)
{
	return "ok";
}
