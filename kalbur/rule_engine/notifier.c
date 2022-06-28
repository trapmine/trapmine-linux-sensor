#include "notifier.h"

#define ACTION_SOCK_PATH "/opt/trapmine/actionsock"

int process_tags(struct message_state *ms)
{
	int err = CODE_SUCCESS;

	if (ms->tags[TAG_ALERT_INDX]) {
		err = generate_alert((uint64_t)ms->event_id,
				     ms->tags[TAG_ALERT_INDX]);
	}

	return err;
}

int generate_alert(uint64_t event_id, uint64_t alert_type)
{
	struct sockaddr_un addr;
	struct action_struct action = { 0 };
	int sfd;
	int err;

	sfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sfd == -1) {
		fprintf(stderr, "generate_alert: socket syscall failed\n");
		err = CODE_FAILED;
		goto ret;
	}

	memset(&addr, 0, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, ACTION_SOCK_PATH, sizeof(addr.sun_path) - 1);

	if (connect(sfd, (struct sockaddr *)&addr,
		    (socklen_t)sizeof(struct sockaddr_un)) == -1) {
		fprintf(stderr,
			"generate_alert: failed to connect to domain socket %s\n",
			ACTION_SOCK_PATH);
		err = CODE_FAILED;
		goto out;
	}

	action.event_id = event_id;
	action.action_type = ALERT_ACTION;
	action.data.alert.alert_type = alert_type;

	if (write(sfd, &action, sizeof(struct action_struct)) !=
	    sizeof(struct action_struct)) {
		fprintf(stderr,
			"generate_alert: write failed or partial write to unix domain "
			"socket %s\n",
			ACTION_SOCK_PATH);
		err = CODE_FAILED;
		goto out;
	}

	err = CODE_SUCCESS;
out:
	close(sfd);
ret:
	return err;
}
