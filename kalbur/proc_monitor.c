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
#include <stdbool.h>
#include <lua_engine.h>
#include <proc_monitor.h>

#define GARBAGE_COLLECT 5000

pthread_t listener;
static struct thread_msg **threads;
size_t thread_num;

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

	// forcefully garbage collect message
	transition_ms_progress(ms, MS_GC, CODE_SUCCESS);
}

static void try_garbage_collect(struct msg_list *head, safetable_t *counter)
{
	int err;
	// acquire lock on msg_list, if all threads are sleeping
	err = attempt_lock_threads();
	if (err == 0) {
#ifdef __DEBUG__
		printf("try_garbage_collect: precollect: head->elements: %d\n",
		       head->elements);
#endif
		garbage_collect(head, counter);
		printf("try_garbage_collect: postcollect: head->elements: %d\n",
		       head->elements);
		head->wait_for_gc = false;
		unlock_threads();
	} else {
		head->wait_for_gc = true;
	}
}

struct callback_ctx {
	struct msg_list *head;
	safetable_t *counter;
};

static void consume_kernel_events(void *ctx, int cpu, void *data,
				  unsigned int size)
{
	struct probe_event_header eh_local = { 0 };
	struct message_state *ms;
	struct callback_ctx *context;
	safetable_t *counter;
	struct msg_list *head;

	context = (struct callback_ctx *)ctx;
	head = context->head;
	ASSERT(head != NULL, "consume_kernel_events: head == NULL");
	counter = context->counter;
	ASSERT(counter != NULL, "consume_kernel_events: counter == NULL");

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
		try_garbage_collect(head, counter);
	}

	// Make sure this is done regardless of whether broadcast_complete()
	// is called or not. If we don't try this everytime we may miss this
	// state transition for some messages.
	transition_ms_progress(ms, MS_COMPLETE, ms->pred(ms));

	// if a message was completed, incremented the process event counter
	if (IS_MS_COMPLETE(ms))
		count_event(ms, counter, true);

	// If we are not waiting for a garbage collect operation, broadcast
	// message to wake up sleeping threads
	if (!(head->wait_for_gc)) {
		if (IS_MS_COMPLETE(ms)) {
			broadcast_complete();
		}
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
		free(threads[i]->rule_engine);
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

	err = pthread_join(listener, NULL);
	if (err != 0) {
		perror("handle_exit");
	}

	return;
}

static safetable_t *initialize_safetable(void)
{
	return init_safetable();
}

static int initialize_thread_ls(struct msg_list *head,
				struct rules_manager *manager)
{
	struct lua_engine *e;
	size_t i;
	int err;

	threads = calloc(thread_num, sizeof(struct thread_msg *));

	for (i = 0; i < thread_num; i++) {
		e = initialize_new_lua_engine(manager);
		if (e == NULL)
			return CODE_FAILED;

		threads[i] = calloc(1UL, sizeof(struct thread_msg));
		if (threads[i] == NULL) {
			fprintf(stderr,
				"initialize_thread_ls: Calloc failed\n");
			exit(1);
		}

		threads[i]->rule_engine = e;
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

	return CODE_SUCCESS;
}

static int startup_workers(void)
{
	size_t i;
	int err;

	for (i = 0; i < thread_num; ++i) {
		err = pthread_create(&(threads[i]->thread_id), NULL, &consumer,
				     threads[i]);
		if (err != 0) {
			fprintf(stderr,
				"startup_workers: Failed to create pthread: %d\n",
				err);
			return CODE_FAILED;
		}
	}

	return CODE_SUCCESS;
}

static struct callback_ctx *initialize_callback_ctx(struct msg_list *head,
						    safetable_t *counter)
{
	struct callback_ctx *ctx = calloc(1UL, sizeof(struct callback_ctx));
	if (ctx == NULL) {
		return NULL;
	}

	ctx->head = head;
	ctx->counter = counter;

	return ctx;
}

void handle_config(struct config_struct *config)
{
    struct rules_manager *manager;
    struct rules_manager *old_manager;
	struct lua_engine *engine;
	struct lua_engine *old_engine;

	// handle the config received
	if (config->reload_rules) {
		manager = init_rules_manager(RULES_FILE);
		force_lock_threads();

		old_manager = threads[0]->rule_engine->manager;
		for(size_t i = 0; i < thread_num; i++) {
			threads[i]->rule_engine->manager = manager;
		}

		free_rules_manager(old_manager);

		unlock_threads();
	}
}

int main(int argc, char **argv)
{
	struct proc_monitor_bpf *skel = NULL;
	struct msg_list *head = NULL;
	struct rlimit limit = { 0 };
	safetable_t *counter;
	struct callback_ctx *ctx = NULL;
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
	/* initialize message list */
	head = initialize_msg_list();
	if (head == NULL)
		goto out;

	/* Initialize event counter */
	counter = initialize_safetable();
	if (counter == NULL) {
		fprintf(stderr,
			"Failed to initialize hashtable for counting process events\n");
		goto del_head;
	}

	/* Initialize perf buffer callback context */
	ctx = initialize_callback_ctx(head, counter);
	if (ctx == NULL)
		goto del_head;

	/* Initialize number of threads */
	long num = sysconf(_SC_NPROCESSORS_CONF);
	if (num < 0) {
		fprintf(stderr, "Failed to get number of cpus: %ld\n", num);
	}
	thread_num = (size_t)(num / 2) + 1;

	err = pthread_create(&listener, NULL, listen_config, NULL);
	if (err != 0) {
		goto del_head;
	}

	struct rules_manager *manager = init_rules_manager(RULES_FILE);
	if (manager == NULL)
		goto del_head;

	/* Initialize threads */
	err = initialize_thread_ls(head, manager);
	if (err != CODE_SUCCESS)
		goto del_head;

	err = startup_workers();
	if (err != CODE_SUCCESS)
		goto del_threads;

	err = poll_buff(bpf_map__fd(skel->maps.streamer), consume_kernel_events,
			handle_lost_events, (void *)ctx);

del_threads:
	shutdown_threads();
	delete_all_threads();

del_head:
	if (head != NULL)
		head = delete_message_list(head);

	if (ctx != NULL)
		free(ctx);

out:
	return err < 0 ? 1 : 0;
}
