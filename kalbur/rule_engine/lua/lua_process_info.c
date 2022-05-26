#include "lua_process_info.h"

/**
 * @brief Frees lua_process_info
 * 
 * @param event_info 
 */
void delete_lua_process_info(struct lua_process_info *process_info)
{
	if (process_info == NULL) {
		return;
	}

	if (process_info->event_info != NULL) {
		delete_lua_event_info(process_info->event_info);
	}

	free(process_info);
	process_info = NULL;
}

/**
 * @brief Frees lua_process_info_array
 * 
 * @param event_info 
 */
void delete_lua_process_info_array(struct lua_process_info_array *arr)
{
	if (arr == NULL) {
		return;
	}

	if (arr->size > 0) {
		for (int i = 0; i < arr->size; i++) {
			delete_lua_process_info(arr->values[i]);
		}
	}

	arr->size = 0;
	free(arr->values);
	arr->values = NULL;

	free(arr);
	arr = NULL;
}
