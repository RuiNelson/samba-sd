/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef SMBD_TRANSFER_STATS_H
#define SMBD_TRANSFER_STATS_H

struct messaging_context;
bool smbd_transfer_stats_init(struct messaging_context *msg);
void smbd_transfer_record(struct messaging_context *msg,
			  uint64_t uploaded, uint64_t downloaded);
void smbd_transfer_flush(struct messaging_context *msg);

#endif
