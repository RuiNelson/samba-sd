/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Event-driven, count-only session observations for Click SMB. */
#include "includes.h"
#include "messages.h"
#include "session.h"
#include "serverid.h"
#include "lib/util/server_id_db.h"
#include "status_watch.h"

struct users_watch {
	struct messaging_context *msg;
	struct tevent_immediate *refresh;
	bool pending, done, failed, have_count;
	size_t last_count;
};

struct users_snapshot {
	const char **names;
	size_t count, capacity;
};

static int collect_user(const char *key, struct sessionid *session, void *data)
{
	struct users_snapshot *snapshot = data;
	const char **names;

	if (session->uid == (uid_t)-1 || session->username[0] == '\0' ||
	    !process_exists(session->pid)) {
		return 0;
	}
	if (snapshot->count == snapshot->capacity) {
		size_t capacity = MAX(64, snapshot->capacity * 2);
		names = talloc_realloc(snapshot, snapshot->names,
				       const char *, capacity);
		if (names == NULL) {
			return -1;
		}
		snapshot->names = names;
		snapshot->capacity = capacity;
	}
	snapshot->names[snapshot->count] = talloc_strdup(snapshot->names,
						       session->username);
	if (snapshot->names[snapshot->count] == NULL) {
		return -1;
	}
	snapshot->count++;
	return 0;
}

static int compare_names(const void *a, const void *b)
{
	return strcmp(*(const char * const *)a, *(const char * const *)b);
}

static void refresh_users(struct tevent_context *ev,
			  struct tevent_immediate *im, void *data)
{
	struct users_watch *watch = data;
	struct users_snapshot *snapshot = talloc_zero(watch, struct users_snapshot);
	NTSTATUS status;
	size_t count = 0, i;

	watch->pending = false;
	if (snapshot == NULL) {
		watch->done = watch->failed = true;
		return;
	}
	status = sessionid_traverse_read(collect_user, snapshot);
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr, "Cannot observe SMB sessions: %s\n", nt_errstr(status));
		watch->done = watch->failed = true;
		TALLOC_FREE(snapshot);
		return;
	}
	if (snapshot->count > 0) {
		qsort(snapshot->names, snapshot->count, sizeof(*snapshot->names),
		      compare_names);
	}
	for (i = 0; i < snapshot->count; i++) {
		if (i == 0 || strcmp(snapshot->names[i - 1], snapshot->names[i]) != 0) {
			count++;
		}
	}
	if (!watch->have_count || count != watch->last_count) {
		if (printf("{\"count\":%zu,\"error\":null}\n", count) < 0 ||
		    fflush(stdout) != 0) {
			watch->done = watch->failed = true;
		}
		watch->last_count = count;
		watch->have_count = true;
	}
	TALLOC_FREE(snapshot);
}

static void users_changed(struct messaging_context *msg, void *data,
			  uint32_t type, struct server_id source, DATA_BLOB *payload)
{
	struct users_watch *watch = data;
	if (!watch->pending) {
		watch->pending = true;
		tevent_schedule_immediate(watch->refresh,
			messaging_tevent_context(msg), refresh_users, watch);
	}
}

static void input_ready(struct tevent_context *ev, struct tevent_fd *fde,
			uint16_t flags, void *data)
{
	struct users_watch *watch = data;
	char buffer[64];
	ssize_t count = read(STDIN_FILENO, buffer, sizeof(buffer));
	if (count == 0 || (count < 0 && errno != EINTR && errno != EAGAIN)) {
		watch->done = true;
	}
}

int status_watch_users(struct messaging_context *msg_ctx)
{
	struct tevent_context *ev = messaging_tevent_context(msg_ctx);
	struct server_id_db *names = messaging_names_db(msg_ctx);
	struct users_watch *watch = talloc_zero(msg_ctx, struct users_watch);
	NTSTATUS status;
	int result = 1;

	if (watch == NULL) {
		return 1;
	}
	watch->msg = msg_ctx;
	watch->refresh = tevent_create_immediate(watch);
	if (watch->refresh == NULL ||
	    tevent_add_fd(ev, watch, STDIN_FILENO, TEVENT_FD_READ,
			  input_ready, watch) == NULL) {
		goto done;
	}
	status = messaging_register(msg_ctx, watch, MSG_SMBXSRV_SESSION_CHANGED,
				    users_changed);
	if (!NT_STATUS_IS_OK(status) ||
	    server_id_db_add(names, SMBSTATUS_USERS_WATCH_NAME) != 0) {
		goto done;
	}
	/* Subscribe before reading, so a concurrent logon cannot be missed. */
	refresh_users(ev, NULL, watch);
	while (!watch->done) {
		if (tevent_loop_once(ev) != 0) {
			watch->failed = true;
			break;
		}
	}
	result = watch->failed ? 1 : 0;
done:
	server_id_db_remove(names, SMBSTATUS_USERS_WATCH_NAME);
	messaging_deregister(msg_ctx, MSG_SMBXSRV_SESSION_CHANGED, watch);
	TALLOC_FREE(watch);
	return result;
}
