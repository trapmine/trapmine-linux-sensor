#include "lua_event_info.h"

/**
 * @brief Frees lua_event_info
 * 
 * @param event_info 
 */
void delete_lua_event_info(struct lua_event_info *event_info)
{
	if (event_info == NULL) {
		return;
	}

	if (event_info->process_name != NULL) {
		free(event_info->process_name);
		event_info->process_name = NULL;
	}

	free(event_info);
	event_info = NULL;
}
