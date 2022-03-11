#include "notifier.h"
#include "rules.h"
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdint.h>
#include <err.h>
#include <errno.h>
#include <hash.h>
#include <string.h>
#include <stdio.h>

#define ALERT_SOCK_PATH "/opt/trapmine/alertsock"

struct alert_struct {
	int64_t event_id;
	int64_t alert_type;
};

static void generate_alert(sqlite3_context *context, int argc,
			   sqlite3_value **argv)
{
	struct sockaddr_un addr;
	struct alert_struct alert = { 0 };
	int sfd, err;
	hashtable_t *ht;

	ht = sqlite3_user_data(context);
	if (ht == NULL) {
		fprintf(stderr, "generate_alert: hashtable pointer is null\n");
		return;
	}

	err = evaluate_rule(context, ht, argv);
	if (err == CODE_FAILED) {
		return;
	}

	sfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sfd == -1) {
		fprintf(stderr, "generate_alert: socket syscall failed\n");
		return;
	}

	memset(&addr, 0, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, ALERT_SOCK_PATH, sizeof(addr.sun_path) - 1);

	if (connect(sfd, (struct sockaddr *)&addr,
		    sizeof(struct sockaddr_un)) == -1) {
		fprintf(stderr,
			"generate_alert: failed to connect to domain socket %s\n",
			ALERT_SOCK_PATH);
		goto out;
	}

	alert.event_id = sqlite3_value_int64(argv[EVENT_ID_INDX]);
	alert.alert_type = sqlite3_value_int64(argv[ALERT_TYPE_INDX]);

	if (write(sfd, &alert, sizeof(struct alert_struct)) !=
	    sizeof(struct alert_struct)) {
		fprintf(stderr,
			"generate_alert: write failed or partial write to unix domain socket %s\n",
			ALERT_SOCK_PATH);
	}
out:
	close(sfd);
	return;
}

int init_notifier(sqlite3 *db, hashtable_t *ht)
{
	int err;

	err = sqlite3_create_function(db, "detect_and_notify", -1, SQLITE_UTF8,
				      ht, generate_alert, 0, 0);

	if (err != SQLITE_OK)
		return CODE_FAILED;

	return CODE_SUCCESS;
}
