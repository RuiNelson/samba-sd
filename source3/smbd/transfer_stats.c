/* SPDX-License-Identifier: GPL-3.0-or-later */
/* File payload totals for one smbd lifetime, independent of its observers. */
#include "includes.h"
#include "messages.h"
#include "lib/util/server_id_db.h"
#include "lib/util/server_id.h"
#include "smbd/transfer_stats.h"

struct transfer_totals {
	uint64_t uploaded, downloaded;
	unsigned notification_pending;
};

static struct transfer_totals *totals;
static struct server_id parent_id;
static struct tevent_timer *flush_timer;

static void transfer_snapshot(uint8_t buffer[16])
{
	SBVAL(buffer, 0, __atomic_load_n(&totals->uploaded, __ATOMIC_SEQ_CST));
	SBVAL(buffer, 8, __atomic_load_n(&totals->downloaded, __ATOMIC_SEQ_CST));
}

void smbd_transfer_flush(struct messaging_context *msg)
{
	uint8_t buffer[16];
	TALLOC_CTX *frame = talloc_stackframe();
	struct server_id *subscribers = NULL;
	unsigned count = 0, i;

	if (totals == NULL) {
		TALLOC_FREE(frame);
		return;
	}
	TALLOC_FREE(flush_timer);
	/* Clear before reading: a concurrent increment either appears in this
	 * snapshot or queues another notification. Counters never depend on IPC. */
	__atomic_store_n(&totals->notification_pending, 0, __ATOMIC_SEQ_CST);
	transfer_snapshot(buffer);
	if (server_id_db_lookup(messaging_names_db(msg), SMBSTATUS_USERS_WATCH_NAME,
				frame, &count, &subscribers) == 0) {
		for (i = 0; i < count; i++) {
			messaging_send_buf(msg, subscribers[i], MSG_SMBXSRV_TRANSFER_STATS,
					   buffer, sizeof(buffer));
		}
	}
	TALLOC_FREE(frame);
}

static void flush_ready(struct tevent_context *ev, struct tevent_timer *te,
			struct timeval now, void *data)
{
	smbd_transfer_flush(data);
}

static void transfer_changed(struct messaging_context *msg, void *data,
			     uint32_t type, struct server_id source,
			     DATA_BLOB *payload)
{
	struct server_id self = messaging_server_id(msg);
	if (!server_id_equal(&parent_id, &self)) {
		return;
	}
	if (flush_timer == NULL) {
		/* A single timer is armed only by activity, never rearmed while idle. */
		flush_timer = tevent_add_timer(messaging_tevent_context(msg), msg,
				timeval_current_ofs(0, 250000), flush_ready, msg);
		if (flush_timer == NULL) {
			smbd_transfer_flush(msg);
		}
	}
}

static void transfer_requested(struct messaging_context *msg, void *data,
			       uint32_t type, struct server_id source,
			       DATA_BLOB *payload)
{
	struct server_id self = messaging_server_id(msg);
	uint8_t buffer[16];
	if (!server_id_equal(&parent_id, &self) || payload->length != 0) {
		return;
	}
	transfer_snapshot(buffer);
	messaging_send_buf(msg, source, MSG_SMBXSRV_TRANSFER_STATS,
			   buffer, sizeof(buffer));
}

bool smbd_transfer_stats_init(struct messaging_context *msg)
{
	NTSTATUS status;
	/* These counters must remain atomic between processes even after a
	 * worker is killed. Never use a process-local emulation lock. */
	if (!__atomic_always_lock_free(sizeof(uint64_t), 0) ||
	    !__atomic_always_lock_free(sizeof(unsigned), 0)) {
		return false;
	}
	totals = anonymous_shared_allocate(sizeof(*totals));
	if (totals == NULL) {
		return false;
	}
	ZERO_STRUCTP(totals);
	parent_id = messaging_server_id(msg);
	status = messaging_register(msg, NULL, MSG_SMBXSRV_TRANSFER_CHANGED,
				    transfer_changed);
	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}
	status = messaging_register(msg, NULL, MSG_SMBXSRV_TRANSFER_STATS,
				    transfer_requested);
	return NT_STATUS_IS_OK(status) &&
		server_id_db_add(messaging_names_db(msg), SMBD_TRANSFER_STATS_NAME) == 0;
}

void smbd_transfer_record(struct messaging_context *msg,
			  uint64_t uploaded, uint64_t downloaded)
{
	NTSTATUS status;
	if (totals == NULL || (uploaded == 0 && downloaded == 0)) {
		return;
	}
	__atomic_fetch_add(&totals->uploaded, uploaded, __ATOMIC_SEQ_CST);
	__atomic_fetch_add(&totals->downloaded, downloaded, __ATOMIC_SEQ_CST);
	if (__atomic_exchange_n(&totals->notification_pending, 1, __ATOMIC_SEQ_CST)) {
		return;
	}
	status = messaging_send_buf(msg, parent_id, MSG_SMBXSRV_TRANSFER_CHANGED,
				    NULL, 0);
	if (!NT_STATUS_IS_OK(status)) {
		__atomic_store_n(&totals->notification_pending, 0, __ATOMIC_SEQ_CST);
		DBG_WARNING("Cannot announce transfer totals: %s\n", nt_errstr(status));
	}
}
