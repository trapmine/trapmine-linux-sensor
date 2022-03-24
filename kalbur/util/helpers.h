#ifndef HELPERS_H
#define HELPERS_H
#include <stdint.h>
#include <events.h>
#include <message.h>

char *build_filename_from_event(char *file_path, uint32_t pathlen);
char *build_cmdline(char *args_data, uint32_t argv_off, uint32_t nargv);

#endif // HELPERS_H
