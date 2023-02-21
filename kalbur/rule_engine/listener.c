#include "listener.h"
#include "proc_monitor.h"

#define CONFIG_SOCK_PATH "/opt/trapmine/configsock"
#define BACKLOG 1

// closes the fd on error.
int init_listener(const char *socket_path, int *sfd)
{
	struct sockaddr_un addr;
	int err;

	// create unix socket
	*sfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (*sfd == -1) {
		fprintf(stderr, "init_listener: socket syscall failed\n");
		err = CODE_FAILED;
		goto ret;
	}

	memset(&addr, 0, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

    unlink(socket_path);

	// bind to socket
    err = bind(*sfd, (const struct sockaddr *) &addr, (socklen_t) sizeof(struct sockaddr_un));
    if (err == -1) {
		fprintf(stderr, "init_listener: bind syscall failed\n");
		err = CODE_FAILED;
        goto out;
    }

    err = listen(*sfd, BACKLOG);
    if (err == -1) {
		fprintf(stderr, "init_listener: listen syscall failed\n");
		err = CODE_FAILED;
        goto out;
    }

    return CODE_SUCCESS;

out:
	close(*sfd);

ret:
	return err;
}

void *listen_config(void *arg)
{
    int err;
    int sfd;
    int cfd;
    ssize_t bytesRead;
    struct config_struct config;


    err = init_listener(CONFIG_SOCK_PATH, &sfd);
    if (err != CODE_SUCCESS) {
        fprintf(stderr, "listen_config: init_socket failed\n");
        goto ret;
    }

    for(;;) {
        cfd = accept(sfd, NULL, NULL);
        if (cfd == -1) {
            fprintf(stderr, "listen_config: accept syscall failed\n");
            goto ret;
        }

        memset(&config, 0, sizeof(struct config_struct));

        while ((bytesRead = read(cfd, (void *) &config, sizeof(struct config_struct))) > 0) {
        }

        if (bytesRead == -1) {
            fprintf(stderr, "listen_config: read syscall failed\n");
            goto try_close;
        }

        handle_config(&config);

        close(cfd);
    }

try_close:
    if (cfd > 0) {
        close(cfd);
    }
ret:
    return NULL;
}