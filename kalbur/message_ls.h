#ifndef MESSAGE_LS_H
#define MESSAGE_LS_H
#include <events.h>
#include <stdbool.h>

struct msg_list *initialize_msg_list(void);
void *delete_message_list(struct msg_list *head);
struct message_state *get_message(struct msg_list *head,
				  struct probe_event_header *eh_incoming,
				  int cpu);
void garbage_collect(struct msg_list *head, char *caller);
void remove_message_from_list(struct msg_list *head,
			      struct message_state **state);
struct msg_list {
	struct message_state *first;
	struct message_state *last;
	int elements;
	bool wait_for_gc;
};

#endif // MESSAGE_LS_H

