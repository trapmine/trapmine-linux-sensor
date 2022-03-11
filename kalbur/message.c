/*
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright 2021-2022 TRAPMINE, Inc.
 *
 * All incoming events from the kernel are placed in a generic struct, which is
 * then placed in a message list for consumption by worker threads.
 * This file provides all the code necessary for allocating, initializing, and
 * linking of these events.
 */

#include <message_preds.h>
#include <message.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <err.h>

static void *allocate_message_data(void **copy_target, void *data, size_t size)
{
	if (copy_target == NULL)
		return NULL;

	if (data == NULL)
		return NULL;

	if (size <= 0)
		return NULL;

	/* This check can be regarded as a program invariant.
         * However, this get violated because under high load,
         * perf returns duplicated events. This check is present to 
         * handle that case */
	if (*copy_target != NULL) {
		return *copy_target;
	}

	*copy_target = calloc(1UL, size);
	if (*copy_target == NULL)
		return NULL;

	memcpy(*copy_target, data, size);

	return *copy_target;
}

/* Allocate message_state struct and set the appropriate complete predicate
 * based on the syscall number */
static struct message_state *allocate_message_struct(int syscall, int cpu)
{
	struct message_state *ms;
	ms = calloc(1UL, sizeof(struct message_state));
	if (ms == NULL)
		return NULL;

	if (pthread_mutex_init(&(ms->message_state_lock), NULL) != 0)
		goto error;

	if (syscall == SYS_EXECVE)
		ms->pred = is_execve_complete;
	else if (syscall == SYS_MMAP)
		ms->pred = is_mmap_complete;
	else if (IS_FORK_OR_FRIENDS(syscall))
		ms->pred = is_fork_and_friends_complete;
	else if (syscall == SYS_CONNECT)
		ms->pred = is_tcp_connect_complete;
	else if (syscall == SYS_ACCEPT)
		ms->pred = is_tcp_accept_complete;
	else if (syscall == SYS_SOCKET)
		ms->pred = is_socket_create_complete;
	else if (syscall == SYS_PTRACE)
		ms->pred = is_ptrace_complete;
	else if (syscall == SYS_FINIT_MODULE)
		ms->pred = is_module_load_complete;
	else if (syscall == DUMP_MMAP_DATA) // Dump data
		ms->pred = is_mem_dump_complete;
	else if (syscall == LPE_COMMIT_CREDS)
		ms->pred = is_lpe_commit_creds_complete;
	else if (syscall == MODPROBE_OVERWRITE)
		ms->pred = is_modprobe_overwrite_complete;
	else { // This case should never happen thus the strange assert
		ASSERT(1 == 0, "allocate_message_struct: unexpected syscall");
		goto error;
	}

	ms->cpu = cpu;
	return ms;

error:
	free(ms);
	return NULL;
}

int construct_message_state(struct message_state *ms,
			    struct probe_event_header *eh_local, void *data,
			    unsigned int size)
{
	struct dump_header *dh;
	size_t copy_sz;
	void **mmap_regions;
	void *target;

	/* Calculate copy size based on the data type */
	if (eh_local->data_type == Primary_Data) {
		SYSCALL_PRIMARY_STRUCT_SZ(copy_sz, eh_local->syscall_nr);

		if (!allocate_message_data(&(ms->primary_data), data, copy_sz))
			goto error;

#ifdef __DEBUG__
		/* DEBUG */
		if ((eh_local->syscall_nr == SYS_EXECVE) &&
		    (MESSAGE_MMAP(ms) != NULL)) {
			// First make sure that mmap is correct for this event. Might cause improper allocations
			struct probe_event_header *eh_mmap = MESSAGE_MMAP(ms);
			ASSERT(EVENT_HEADER_EQ(eh_mmap, eh_local) == 1,
			       "Primary: eh_mmap != eh_local");

			struct process_info *p = ms->primary_data;
			size_t cnt = (MESSAGE_MMAP_SZ(ms) -
				      sizeof(struct probe_event_header)) /
				     sizeof(struct proc_mmap);

			if (cnt != p->mmap_cnt)
				printf("[%lu] pid: %lu, eh_size: %lu, proc_mmap_sz: %lu, map_size: %u, cnt: %lu, p->mmap_cnt: %u\n",
				       eh_local->event_time,
				       eh_local->tgid_pid >> 32,
				       sizeof(struct probe_event_header),
				       sizeof(struct proc_mmap),
				       MESSAGE_MMAP_SZ(ms), cnt, p->mmap_cnt);

			ASSERT(cnt == p->mmap_cnt,
			       "construct_message_state: p->mmap_cnt != cnt");
		}
		/* */
#endif
	} else if (eh_local->data_type == String_Data) {
		if (!allocate_message_data(&(MESSAGE_STRING(ms)), data,
					   (size_t)size))
			goto error;

		MESSAGE_STRING_SZ(ms) = size;
	} else if (eh_local->data_type == Mmap_Data) {
		if (!allocate_message_data(&(MESSAGE_MMAP(ms)), data,
					   (size_t)size))
			goto error;

		MESSAGE_MMAP_SZ(ms) = size;

#ifdef __DEBUG__
		/* DEBUG */
		if ((eh_local->syscall_nr == SYS_EXECVE) &&
		    (ms->primary_data != NULL)) {
			struct process_info *pinfo = ms->primary_data;

			// First make sure that mmap is correct for this event. Might cause improper allocations
			struct probe_event_header *eh_prim = &pinfo->eh;
			ASSERT(EVENT_HEADER_EQ(eh_prim, eh_local) == 1,
			       "Primary: eh_mmap != eh_local");

			size_t cnt =
				(size - sizeof(struct probe_event_header)) /
				sizeof(struct proc_mmap);

			if (cnt != pinfo->mmap_cnt)
				printf("size: %u, cnt: %lu, p->mmap_cnt: %u\n",
				       size, cnt, pinfo->mmap_cnt);

			ASSERT(cnt == pinfo->mmap_cnt,
			       "construct_message_state: cnt != pinfo->mmap_cnt");
		}
		/* */
#endif

	} else if (eh_local->data_type == Dump_Data) {
		if (MESSAGE_STRING(ms) == NULL) {
			MESSAGE_STRING(ms) =
				calloc(MAX_MMAP_RECORDS, sizeof(void *));
			if (MESSAGE_STRING(ms) == NULL)
				goto error;
		}
		if (MESSAGE_STRING_SZ(ms) >= MAX_MMAP_RECORDS) {
			MESSAGE_STRING(ms) = realloc(MESSAGE_STRING(ms),
						     2 * MESSAGE_STRING_SZ(ms) *
							     sizeof(void *));
			goto error;
		}

		mmap_regions = MESSAGE_STRING(ms);
		mmap_regions[MESSAGE_STRING_SZ(ms)] =
			calloc(1UL, size * sizeof(uint8_t));

		target = mmap_regions[MESSAGE_STRING_SZ(ms)];
		if (target == NULL)
			goto error;

		memcpy(target, data, (size_t)size);

		dh = (struct dump_header *)target;
		dh->dump_sz = size;

		if (ms->primary_data == NULL) {
			ms->primary_data =
				calloc(1UL, sizeof(struct dump_header));
			if (ms->primary_data == NULL)
				goto error;
		}

		memcpy(ms->primary_data, target, sizeof(struct dump_header));

		MESSAGE_STRING_SZ(ms)++;
	}

	return CODE_SUCCESS;
error:
	return CODE_FAILED;
}

/* Insert new message into the beginning of the message list */
static void link_message(struct msg_list *head, struct message_state *ms)
{
	struct message_state *curr_first;

	ASSERT(head != NULL, "link_message: head == NULL");
	ASSERT(ms != NULL, "link_message: ms == NULL");

	if (head->first == NULL) {
		head->first = ms;
		head->last = ms;

		ms->next_msg = NULL;
		ms->prev_msg = (struct message_state *)head;
	} else {
		curr_first = head->first;

		/* Set the next and previous values of ms before linking into list
                 * Threads only traverse next message, so to avoid leaving list in 
                 * partial state we set the head->first, at the end. */
		ms->next_msg = curr_first;
		ms->prev_msg = (struct message_state *)head;
		curr_first->prev_msg = ms;
		head->first = ms;
	}

	head->elements += 1;
}

struct msg_list *initialize_msg_list(void)
{
	struct msg_list *head = calloc(1UL, sizeof(struct msg_list));
	return head;
}

static inline int validate_event_header(struct probe_event_header *eh)
{
	if ((eh->event_time == 0))
		return 0;

	if ((eh->tgid_pid == 0) || (PRESERVE_32_MSB(eh->tgid_pid) == 0) ||
	    (PRESERVE_32_LSB(eh->tgid_pid) == 0))
		return 0;

	return 1;
}

int is_legal_event(struct probe_event_header *eh)
{
	if (eh->data_type > Max_Valid_Data_T)
		goto error;

	if (!IS_EVENT_HANDLED(eh->syscall_nr))
		goto error;

	if (!validate_event_header(eh))
		goto error;

	return 1;
error:
	return 0;
}
/* get event header from one of the output events.
 * perf events buffer donot guarantee ordering, so 
 * it is legal for a message to have String data present,
 * before primary data */
static struct probe_event_header *get_event_header(struct message_state *ms)
{
	void *p;
	void *string;
	void *mmap;
	struct probe_event_header *eh = NULL;

	if (ms == NULL)
		goto out;

	p = ms->primary_data;
	if (p != NULL) {
		eh = (struct probe_event_header *)p;
		goto out;
	}

	string = MESSAGE_STRING(ms);
	if (string != NULL) {
		eh = (struct probe_event_header *)string;
		goto out;
	}

	mmap = MESSAGE_MMAP(ms);
	if (mmap != NULL)
		eh = (struct probe_event_header *)mmap;

out:
	if (eh == NULL)
		return NULL;

	if (!is_legal_event(eh))
		return NULL;

	return eh;
}

struct message_state *get_message(struct msg_list *head,
				  struct probe_event_header *eh_incoming,
				  int cpu)
{
	struct message_state *ms;
	struct probe_event_header *eh;
	struct message_state *prev_gc;
	ms = head->first;
	prev_gc = NULL;

	ASSERT(head != NULL, "get_message: head == NULL");
	ASSERT(eh_incoming != NULL, "get_message: eh_incoming == NULL");

	while (ms != NULL) {
		eh = get_event_header(ms);
		ASSERT(eh != NULL,
		       "get_message: (eh = get_even_header(ms)) == NULL");
		if (EVENT_HEADER_EQ(eh_incoming, eh)) {
			if (!ms->complete) { // to check for repeated wakeups
				ASSERT(ms->saved == 0,
				       "get_message: ms->saved == 1");
				ASSERT(ms->discard == 0,
				       "get_message: ms->discard == 1");
				return ms;
			} else // If ms->complete and event headers are equal, then ignore
				return NULL;
		}

		// Link saved messages together
		// so freeing later is simpler
		if (FREEABLE(ms)) {
			if (prev_gc == NULL)
				prev_gc = ms;
			else {
				prev_gc->next_gc = ms;
				prev_gc = ms;
			}
		}

		ms = ms->next_msg;
	}

	ASSERT(ms == NULL, "get_message: ms != NULL");
	ms = allocate_message_struct(eh_incoming->syscall_nr, cpu);
	if (ms != NULL)
		link_message(head, ms);

	return ms;
}

static void unlink_message(struct msg_list *head, struct message_state *ms)
{
	struct message_state *next;
	struct message_state *prev;
	int first = 0;

	ASSERT(head != NULL, "unlink_message: head == NULL");
	ASSERT(ms != NULL, "unlink_message: ms == NULL");

	if (head->first == NULL)
		return;

	next = ms->next_msg;
	prev = ms->prev_msg;

	// prev should never be NULL it is
	// either another message or the head
	ASSERT(prev != NULL, "unlink_message: prev == NULL");

	if ((void *)prev == (void *)head) {
		head->first = next;
		first = 1;
	} else
		prev->next_msg = next;

	if (ms == head->last) {
		if (first)
			head->last = NULL;
		else
			head->last = prev;
	}

	if (next != NULL)
		next->prev_msg = prev;

	ms->next_msg = NULL;
	ms->prev_msg = NULL;

	head->elements -= 1;
}

static struct message_state *free_message(struct message_state *ms)
{
	ASSERT(ms != NULL, "free_message: ms == NULL");

	// We should only be freeing from the free list
	// which in turn should only contain saved messages
	ASSERT(((ms->saved == 1) || (ms->discard == 1)) && (ms->complete == 1),
	       "free_message_contents: invalid value of ms->saved or ms->complete");

	if (ms->primary_data != NULL) {
		free(ms->primary_data);
		ms->primary_data = NULL;
	}

	if (MESSAGE_STRING(ms) != NULL) {
		free(MESSAGE_STRING(ms));
		MESSAGE_STRING(ms) = NULL;
	}

	if (MESSAGE_MMAP(ms) != NULL) {
		free(MESSAGE_MMAP(ms));
		MESSAGE_MMAP(ms) = NULL;
	}

	MESSAGE_STRING_SZ(ms) = 0;
	MESSAGE_MMAP_SZ(ms) = 0;

	// destroy mutex
	pthread_mutex_destroy(&(ms->message_state_lock));

	// misc
	ms->pred = NULL;
	ms->next_gc = NULL;

	free(ms);

	return NULL;
}

void delete_message(struct msg_list *head, struct message_state **state)
{
	unlink_message(head, *state);
	*state = free_message(*state);
}

/* Free all saved messages */
void garbage_collect(struct msg_list *head, char *caller)
{
	struct message_state *ms;
	struct message_state *tmp;

	ms = head->first;
	while (!TO_GC(ms))
		ms = ms->next_msg;

	if (ms == NULL)
		return;

	while (ms != NULL) {
		tmp = ms->next_gc;
		delete_message(head, &ms);

		ms = tmp;
	}
}

void *delete_message_list(struct msg_list *head)
{
	struct message_state *ms;
	struct message_state *tmp;

	ASSERT(head != NULL, "free_messages: head == NULL");

	ms = head->first;
	while (ms != NULL) {
		tmp = ms->next_msg;
		delete_message(head, &ms);
		ms = tmp;
	}

	free(head);

	return NULL;
}
