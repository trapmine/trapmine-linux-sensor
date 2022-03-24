#ifndef ENGINE_H
#define ENGINE
#include <safe_hash.h>
#include <message.h>

void process_message(struct message_state *ms, safetable_t *table);

#endif // ENGINE_H
