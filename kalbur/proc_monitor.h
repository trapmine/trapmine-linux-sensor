#ifndef PROC_MONITOR_H
#define PROC_MONITOR_H

#include "listener.h"


#define RULES_FILE "/opt/trapmine/rules/config.lua"

void handle_config(struct config_struct *config);


#endif // PROC_MONITOR_H