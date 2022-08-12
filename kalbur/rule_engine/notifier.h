#ifndef NOTIFIER_H
#define NOTIFIER_H

#include <sys/un.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <unistd.h>
#include "lua_ms_tags.h"
#include "err.h"
#include "message.h"

struct alert_data {
	uint64_t alert_type;
};

struct hashlookup_data {
	uint64_t file_id;
};

struct action_struct {
	uint64_t event_id;
	uint64_t action_tags;
	struct alert_data alert;
	struct hashlookup_data hashlookup;
};

int process_tags(struct message_state *ms);
int send_action_message(struct action_struct *action);

#endif // NOTIFIER_H
