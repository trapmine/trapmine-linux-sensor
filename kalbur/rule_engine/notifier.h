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

int process_tags(struct message_state *ms);

#endif // NOTIFIER_H
