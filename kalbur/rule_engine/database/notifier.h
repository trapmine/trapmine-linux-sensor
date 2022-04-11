#ifndef NOTIFIER_H
#define NOTIFIER_H

#include <hash.h>
#include <sqlite3.h>

int init_notifier(sqlite3 *db, hashtable_t *ht);

#endif // NOTIFIER_H
