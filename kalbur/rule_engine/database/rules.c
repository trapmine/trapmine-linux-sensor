#include <err.h>
#include <rules.h>

static int zero_rule(sqlite3 *db, hashtable_t *ht, int event_id)
{
	return CODE_FAILED;
}

#define RULES_NR 1
int (*rules[RULES_NR])(sqlite3 *, hashtable_t *,
		       sqlite3_value **) = { zero_rule };

int evaluate_rule(sqlite3_context *context, hashtable_t *ht,
		  sqlite3_value **argv)
{
	sqlite3 *db;
	int alert_type;
	int err;

	db = sqlite3_context_db_handle(context);
	if (db == NULL)
		return CODE_FAILED;

	alert_type = sqlite3_value_int(argv[ALERT_TYPE_INDX]);

	if (alert_type >= RULES_NR)
		return CODE_FAILED;

	if (rules[alert_type] == NULL)
		return CODE_FAILED;

	err = rules[alert_type](db, ht, argv);

	return err;
}
