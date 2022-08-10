#include "notifier.h"

#define ACTION_SOCK_PATH "/opt/trapmine/actionsock"

int process_tags(struct message_state *ms)
{
	int err = CODE_SUCCESS;

	if (ms->tags[TAG_ALERT_INDX]) {
		err = generate_alert((uint64_t)ms->event_id,
				     ms->tags[TAG_ALERT_INDX]);
		if (err != CODE_SUCCESS) {
			return err;
		}
	}
	if (ms->tags[TAG_KILL_PROCESS_INDX]) {
		printf("process_tags: killing process %d", ms->event_id);
		err = kill_process((uint64_t)ms->event_id);
		if (err != CODE_SUCCESS) {
			return err;
		}
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

int kill_process(uint64_t event_id)
{
	struct action_struct action = { 0 };
	int sfd;
	int err;

	// create and connect to socket
	err = init_socket(ACTION_SOCK_PATH, &sfd);
	if (err == CODE_FAILED) {
		goto ret;
	}

	// populate action struct.
	action.event_id = event_id;
	action.action_type = KILL_PROCESS_ACTION;

	// write to socket.
	if (write(sfd, &action, sizeof(struct action_struct)) !=
	    sizeof(struct action_struct)) {
		fprintf(stderr,
			"kill_process: write failed or partial write to unix domain "
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

int generate_alert(uint64_t event_id, uint64_t alert_type)
{
	struct action_struct action = { 0 };
	int sfd;
	int err;

	// create and connect to socket
	err = init_socket(ACTION_SOCK_PATH, &sfd);
	if (err == CODE_FAILED) {
		goto ret;
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
