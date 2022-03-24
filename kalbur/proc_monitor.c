/*
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright 2021-2022 TRAPMINE, Inc.
 *
 * This file contains code for starting the sensor, which includes
 * loading the eBPF code, starting the consumer threads, and initializing
 * the sqlite3 database file for the rule_engine.
 * It then registers a function to poll the perf_event buffer for incoming
 * events from the kernel
 */

#define _GNU_SOURCE
#include <sys/resource.h>
#include <stdio.h>
#include <unistd.h>
#include <consumer.h>
#include <err.h>
#include <database.h>
#include <execinfo.h>
#include <signal.h>
#include <sys/prctl.h>
#include <errno.h>
#include <message.h>
#include <loader.h>
#include <message_ls.h>
#include <safe_hash.h>

#define GARBAGE_COLLECT 5000
#define GARBAGE_COLLECT_LIMIT (GARBAGE_COLLECT * 3)

static struct thread_msg **threads;
size_t thread_num = 0;

static void backtrace_handler(int sig)
{
	void *trace[30];
	int size;

	size = backtrace(trace, 30);

	fprintf(stderr, "Error: signal: %d\n", sig);
	backtrace_symbols_fd(trace, size, STDERR_FILENO);

	exit(1);
}

/* Send wakeup signal to each sleeping thread
 * We wakeup each thread, because under high workloads
 * the system generates multiple event before a thread has 
 * fully consumed one message. Therefore all thread loop over the 
 * entire message list, consuming all the messages it can. */
static void broadcast_complete(void)
{
	size_t i;
	int err;

	for (i = 0; i < thread_num; ++i) {
		if (pthread_mutex_trylock(&(threads[i]->mtx)) == 0) {
			if (!threads[i]->ready) {
				threads[i]->ready = true;

				err = pthread_mutex_unlock(&(threads[i]->mtx));
				ASSERT(err == 0,
				       "broadcast_complete: pthread_mutex_unlock(threads[i]->mtx) != 0");

				err = pthread_cond_signal(
					&(threads[i]->wakeup));
				ASSERT(err == 0,
				       "broadcast_complete: pthread_cond_signal(threads[i]->wakeup != 0");
			} else {
				err = pthread_mutex_unlock(&threads[i]->mtx);
				ASSERT(err == 0,
				       "broadcast_complete: pthread_mutex_unlock(thread[i]->mtx) != 0");
			}
		}
	}
}

static int attempt_lock_threads(void)
{
	size_t i, j;
	int err;
	for (i = 0; i < thread_num; ++i) {
		if (pthread_mutex_trylock(&threads[i]->mtx) != 0) {
			goto release;
		}
	}

	return 0;

release:
	for (j = 0; j < i; ++j) {
		err = pthread_mutex_unlock(&threads[j]->mtx);
		ASSERT(err == 0,
		       "attempt_acquire_lock: pthread_mutex_unlock != 0");
	}
	return -EBUSY;
}

static int force_lock_threads(void)
{
	size_t i;
	int err;
	for (i = 0; i < thread_num; ++i) {
		err = pthread_mutex_lock(&threads[i]->mtx);
		ASSERT(err == 0, "force_lock_threads: pthread_mutex_lock != 0");
	}

	return 0;
}

static void unlock_threads(void)
{
	size_t i;
	int err;
	for (i = 0; i < thread_num; ++i) {
		err = pthread_mutex_unlock(&(threads[i]->mtx));
		ASSERT(err == 0, "unlock_threads: pthread_mutex_unlock != 0");
	}
}

static inline unsigned long max(unsigned long s1, unsigned long s2)
{
	return s1 > s2 ? s1 : s2;
}

// data from perf_buffer has 4 bytes of padding at the end.
// we have to account for that in our calculations.
#define PADDING 4
static int validate_max_size(unsigned int size, enum Data_T dt)
{
	if (dt == Primary_Data) {
		if (size > max(sizeof(proc_activity_t) + PADDING,
			       sizeof(proc_info_t) + PADDING))
			goto fail;
	}
	if (dt == String_Data) {
		if (size > (PER_CPU_STR_BUFFSIZE + PADDING))
			goto fail;
	}
	if (dt == Mmap_Data) {
		if (size > (MMAP_BUFFSIZE + PADDING))
			goto fail;
	}

	return CODE_SUCCESS;

fail:
	return CODE_FAILED;
}

static void mark_ms_as_garbage(struct message_state *ms)
{
	ASSERT(ms != NULL, "mark_ms_as_garbage: ms == NULL");
	ms->saved = 1;
}

static void consume_kernel_events(void *ctx, int cpu, void *data,
				  unsigned int size)
{
	struct probe_event_header eh_local = { 0 };
	struct message_state *ms;
	struct msg_list *head;
	int err;

	head = (struct msg_list *)ctx;
	ASSERT(head != NULL, "consume_kernel_events: head == NULL");

	// make sure data is more than the event header size.
	if (size < sizeof(struct probe_event_header))
		goto out;

	// validate that the event header data is correct
	memcpy(&eh_local, data, sizeof(struct probe_event_header));
	if (!is_legal_event(&eh_local))
		goto out;

	// make sure maximum size is within expected bounds
	if (validate_max_size(size, eh_local.data_type) == CODE_FAILED)
		goto out;

	ms = get_message(head, &eh_local, cpu);
	if (ms == NULL)
		goto out;

	if (construct_message_state(ms, &eh_local, data, size) == CODE_FAILED)
		goto error;

	if (head->elements > GARBAGE_COLLECT) {
		// acquire lock on msg_list, if all threads are sleeping
		err = attempt_lock_threads();
		if (err == 0) {
			garbage_collect(head, "pause collect");
			unlock_threads();
		}

		if (head->elements > GARBAGE_COLLECT_LIMIT) {
			err = force_lock_threads();
			if (err == 0) {
				garbage_collect(head, "force collect");
				printf("Garbage collected\n");
				unlock_threads();
			}
		}
	}

	if (ms->pred(ms)) {
		ms->complete = 1;
		broadcast_complete();
	}

out:
	return;

error:
	mark_ms_as_garbage(ms);
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	fprintf(stderr, "Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

static void delete_all_threads(void)
{
	size_t i;

	for (i = 0; i < thread_num; i++) {
		pthread_mutex_destroy(&(threads[i]->mtx));
		pthread_cond_destroy(&(threads[i]->wakeup));
		free(threads[i]);
	}

	free(threads);
}

static void shutdown_threads(void)
{
	size_t i;
	int err;

	// lock all threads to shutdown
	force_lock_threads();
	for (i = 0; i < thread_num; i++) {
		threads[i]->die = true;
	}

	// Wake up all blocked threads so
	// they can shutdown
	broadcast_complete();

	for (i = 0; i < thread_num; i++) {
		err = pthread_join(threads[i]->thread_id, NULL);
		if (err != 0) {
			perror("handle_exit");
		}
	}

	return;
}

static safetable_t *initialize_safetable(void)
{
	return init_safetable();
}

static void initialize_thread_ls(struct msg_list *head, safetable_t *table)
{
	size_t i;
	int err;

	threads = calloc(thread_num, sizeof(struct thread_msg *));

	for (i = 0; i < thread_num; i++) {
		threads[i] = calloc(1UL, sizeof(struct thread_msg));
		if (threads[i] == NULL) {
			fprintf(stderr,
				"initialize_thread_ls: Calloc failed\n");
			exit(1);
		}

		threads[i]->safe_hashtable = table;
		threads[i]->ready = false;
		threads[i]->die = false;
		threads[i]->head = head;
		err = pthread_cond_init(&(threads[i]->wakeup), NULL);
		ASSERT(err == 0,
		       "initialize_thread_ls: pthread_cond_init != 0");
		err = pthread_mutex_init(&(threads[i]->mtx), NULL);
		ASSERT(err == 0,
		       "initialize_thread_ls: pthread_cond_init != 0");
	}
}

static void init_threads(void)
{
	size_t i;
	int err;

	for (i = 0; i < thread_num; ++i) {
		err = pthread_create(&(threads[i]->thread_id), NULL, &consumer,
				     threads[i]);
		if (err != 0) {
			fprintf(stderr, "Failed to create pthread\n");
			exit(1);
		}
	}
}

int main(int argc, char **argv)
{
	struct proc_monitor_bpf *skel = NULL;
	struct msg_list *head = NULL;
	struct rlimit limit = { 0 };
	safetable_t *table;
	int err;

	/* Kill this process if parent dies */
	err = prctl(PR_SET_PDEATHSIG, SIGKILL);
	if (err != 0)
		goto out;

	/* Enable core dumping */
	limit.rlim_cur = RLIM_INFINITY;
	limit.rlim_max = RLIM_INFINITY;

	err = setrlimit(RLIMIT_CORE, &limit);
	if (err != 0) {
		fprintf(stderr, "Failed to setrlimit: %d\n", errno);
	}

	/* Turn off buffering */
	setvbuf(stdout, NULL, _IONBF, 0UL);
	setvbuf(stderr, NULL, _IONBF, 0UL);

	/* setup signal handlers */
	signal(SIGSEGV, backtrace_handler);

	/* Load and attach bpf programs */
	skel = load();
	if (skel == NULL)
		goto out;

	/* Initialize database */
	err = initialize_database(DB_NAME);
	if (err != CODE_SUCCESS) {
		fprintf(stderr, "Failed to initialize database file\n");
		goto out;
	}

	/* Initialize number of cpu */
	long num = sysconf(_SC_NPROCESSORS_CONF);
	if (num < 0) {
		fprintf(stderr, "Failed to get number of cpus: %ld\n", num);
	}
	thread_num = (size_t)(num / 2) + 1;

	/* perform initializations */
	head = initialize_msg_list();
	if (head == NULL)
		goto out;

	// initialize safetable
	table = initialize_safetable();
	initialize_thread_ls(head, table);

	init_threads();

	err = poll_buff(bpf_map__fd(skel->maps.streamer), consume_kernel_events,
			handle_lost_events, (void *)head);

out:
	if (head != NULL)
		free(head);

	shutdown_threads();
	if (head != NULL)
		head = delete_message_list(head);

	delete_all_threads();

	return err < 0 ? 1 : 0;
}
