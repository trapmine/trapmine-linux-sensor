#include "notifier.h"

#define ACTION_SOCK_PATH "/opt/trapmine/actionsock"

int process_tags(struct message_state *ms)
{
	struct action_struct action = { 0 };
	int err = CODE_SUCCESS;
	bool send_message = false;
	action.event_id = (uint64_t)ms->event_id;

	if (ms->tags[TAG_ALERT_INDX]) {
		action.action_tags |= 1UL << TAG_ALERT_INDX;
		action.alert.alert_type = ms->tags[TAG_ALERT_INDX];
		send_message = true;
	}

	if (ms->tags[TAG_KILL_PROCESS_INDX]) {
		action.action_tags |= 1UL << TAG_KILL_PROCESS_INDX;
		send_message = true;
	}

	if (send_message) {
		err = send_action_message(&action);
	}

	return err;
}

// closes the fd on error.
int init_socket(const char *socket_path, int *sfd)
{
	struct sockaddr_un addr;
	int err;

	// create unix socket
	*sfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (*sfd == -1) {
		fprintf(stderr, "kill_process: socket syscall failed\n");
		err = CODE_FAILED;
		goto ret;
	}

	memset(&addr, 0, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

	// connect to socket.
	if (connect(*sfd, (struct sockaddr *)&addr,
		    (socklen_t)sizeof(struct sockaddr_un)) == -1) {
		fprintf(stderr,
			"kill_process: failed to connect to domain socket %s\n",
			socket_path);
		err = CODE_FAILED;
		goto out;
	} else {
		return CODE_SUCCESS;
	}

out:
	close(*sfd);

ret:
	return err;
}

int send_action_message(struct action_struct *action)
{
	int sfd;
	int err;

	// create and connect to socket
	err = init_socket(ACTION_SOCK_PATH, &sfd);
	if (err == CODE_FAILED) {
		goto ret;
	}

	// write to socket.
	if (write(sfd, action, sizeof(struct action_struct)) !=
	    sizeof(struct action_struct)) {
		fprintf(stderr,
			"send_action_message: write failed or partial write to unix domain "
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
