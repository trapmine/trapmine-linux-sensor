#ifndef LISTENER_H
#define LISTENER_H

#include <sys/un.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <unistd.h>
#include "err.h"
#include "rule_manager.h"
#include "kalbur/loader.h"
#include "kalbur/network_isolation.h"

struct config_struct {
	uint64_t reload_rules;
};

void *listen_config(void *arg);
void *listen_network_isolation_config(void *arg);
int init_listener(const char *socket_path, int *sfd);

#endif // LISTENER_H
