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
