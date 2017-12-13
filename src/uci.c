#include <uci.h>
#include <sysrepo.h>

#include "dhcp.h"
#include "common.h"
#include "uci.h"

int uci_del(ctx_t *ctx, const char *uci)
{
	int rc = UCI_OK;
	struct uci_ptr ptr = {};

	uci_lookup_ptr(ctx->uctx, &ptr, (char *) uci, true);
	UCI_CHECK_RET(rc, error, "uci_lookup_ptr %d, path %s", rc, uci);

	uci_delete(ctx->uctx, &ptr);
	UCI_CHECK_RET(rc, error, "uci_set %d, path %s", rc, uci);

	uci_save(ctx->uctx, ptr.p);
	UCI_CHECK_RET(rc, error, "UCI save error %d, path %s", rc, uci);

	uci_commit(ctx->uctx, &ptr.p, 1);
	UCI_CHECK_RET(rc, error, "UCI commit error %d, path %s", rc, uci);

error:
	return rc;
}

int set_uci_section(ctx_t *ctx, char *uci)
{
	int rc = UCI_OK;
	struct uci_ptr ptr = {0};

	uci_lookup_ptr(ctx->uctx, &ptr, (char *) uci, true);
	UCI_CHECK_RET(rc, error, "uci_lookup_ptr %d, path %s", rc, uci);

	uci_set(ctx->uctx, &ptr);
	UCI_CHECK_RET(rc, error, "uci_set %d, path %s", rc, uci);

	uci_save(ctx->uctx, ptr.p);
	UCI_CHECK_RET(rc, error, "UCI save error %d, path %s", rc, uci);

	uci_commit(ctx->uctx, &ptr.p, 1);
	UCI_CHECK_RET(rc, error, "UCI commit error %d, path %s", rc, uci);

error:
	return rc;
}

int get_uci_item(struct uci_context *uctx, char *ucipath, char **value)
{
	int rc = UCI_OK;
	char path[MAX_UCI_PATH];
	struct uci_ptr ptr;

	sprintf(path, "%s", ucipath);

	rc = uci_lookup_ptr(uctx, &ptr, path, true);
	UCI_CHECK_RET(rc, exit, "lookup_pointer %d %s", rc, path);

	if (NULL == ptr.o) {
		INF("Uci item %s not found", ucipath);
		return UCI_ERR_NOTFOUND;
	}

	strcpy(*value, ptr.o->v.string);

exit:
	return rc;
}

int set_uci_item(struct uci_context *uctx, char *ucipath, char *value)
{
	int rc = UCI_OK;
	struct uci_ptr ptr;
	char *set_path = calloc(1, MAX_UCI_PATH);

	sprintf(set_path, "%s%s%s", ucipath, "=", value);

	rc = uci_lookup_ptr(uctx, &ptr, set_path, true);
	UCI_CHECK_RET(rc, exit, "lookup_pointer %d %s", rc, set_path);

	rc = uci_set(uctx, &ptr);
	UCI_CHECK_RET(rc, exit, "uci_set %d %s", rc, set_path);

	rc = uci_save(uctx, ptr.p);
	UCI_CHECK_RET(rc, exit, "uci_save %d %s", rc, set_path);

	rc = uci_commit(uctx, &(ptr.p), false);
	UCI_CHECK_RET(rc, exit, "uci_commit %d %s", rc, set_path);

exit:
	free(set_path);

	return rc;
}
