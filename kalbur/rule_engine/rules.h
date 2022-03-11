#ifndef RULES_H
#define RULES_H

#include <sqlite3.h>
#include <sys/types.h>
#include <stdint.h>
#include <hash.h>

#define ALERT_TYPE_INDX 0
#define EVENT_ID_INDX 1

int evaluate_rule(sqlite3_context *context, hashtable_t *ht,
		  sqlite3_value **argv);

#endif // RULES_H
