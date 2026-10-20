/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef SMBSTATUS_WATCH_H
#define SMBSTATUS_WATCH_H

struct messaging_context;
int status_watch_users(struct messaging_context *msg_ctx, bool transfers);

#endif
