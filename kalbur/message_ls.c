/*
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright 2021-2022 TRAPMINE, Inc.
 *
 * All incoming events from the kernel are placed in a generic struct, which is
 * then placed in a message list for consumption by worker threads.
 * This file provides all the code necessary for managing the message_list.
 */

/*
The message list defined here is a linked list, linking incoming message_state structs
together.
The linked list defined here is not a generic linked list. It is written with the specific 
requirements and considerations of this project in mind.

There are two categories of threads which interact with this linked list. Each category has
different access rules, which are defined as follows.

1. main_thread
--------------
The first is the thread of the callback function for consuming incoming events from the kernel
via the perf buffer. This thread will be referred to as the main_thread henceforth.
The main_thread is responsible for
a) constructing the message_state struct representing the event, and placing it inside the 
linked list.
b) managing the deallocation of these structs, during a garbage collect operation.

During the garbage collect operation, the main_thread acquire locks on each worker_thread, and only
then begins traversing the list and deleting consumed messages.

On the other hand, during insertion, the main_thread does not acquire any locks. It insert the new
message in the beginning of the linked list. 

IMPORTANT: Look at link_message() function to see how it does that safely. 

The reason for not acquiring locks before insertion is because locking all threads
leads to high lock contention, causing our sensor to start dropping incoming events from the kernel.

2. worker threads
-----------------
The second category is the worker_threads. The point of these threads is to take messages from
the list and consume them. The messages are then marked as consumed, and thus are ready for garbage
collection.
The worker_threads do not modify the message list. They acquire a lock on specific messages when they 
begin consumption, and then release the lock when done. 
They traverse the linked list starting from the head and towards the end.
As long as the worker_threads are running the main_thread cannot begin garbage collection.
*/

#include <err.h>
#include <stdlib.h>
#include <message.h>
#include "message_ls.h"

struct msg_list *initialize_msg_list(void)
{
	struct msg_list *head = calloc(1UL, sizeof(struct msg_list));
	return head;
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

/* This function inserts a new message into the beginning of the message list.
 * Since the main_thread (see above) does not acquire any lock before linking
 * in a new message, this function has to be careful to never leave the linked
 * list in an invalid state.
 *
 * Lets say the following is the start state of the message list:
 * head -> B -> C -> D -> E
 * 'head' is the head and the alphabets are the message_state structs.
 * For a new incoming message, the main_thread constructs a new message_state
 * struct A, and calls link_message() to insert it into the message list.
 *
 * The insert must follow these step
 *
 * 1. A->next = B
 * 2. B->prev = A
 *
 * At this point, all traversing worker_threads will see the list as follows:
 * State:1 = head -> B -> C -> ...
 *
 * 3. head->first = A
 *
 * Now the list is State:2 = head -> A -> B -> ...
 *
 * The point here, is that all worker_threads must always see the list in either
 * State:1 or State:2
 * In order to guarantee this we must guarantee that operation 3. always happens
 * after 2. and 1.
 * 
 * As such we issue a memory fence before operation 3. in order to ensure that it
 * always takes place after the pointers of the new message (A) have been initialized
 * correctly */
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

		// memory barrier needed here because head->first must be set
		// after all other pointers have been set, as explained above.
		__sync_synchronize();
		head->first = ms;
	}

	head->elements += 1;
}

void remove_message_from_list(struct msg_list *head,
			      struct message_state **state)
{
	unlink_message(head, *state);
	delete_message(state);
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
		remove_message_from_list(head, &ms);

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
		remove_message_from_list(head, &ms);
		ms = tmp;
	}

	free(head);

	return NULL;
}
