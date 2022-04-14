#ifndef HELPERS_H
#define HELPERS_H
#include <stdint.h>
#include <events.h>
#include <message.h>

char *build_filename_from_event(char *file_path, uint32_t pathlen);
char *build_cmdline(char *args_data, uint32_t argv_off, unsigned long nbytes);
char *build_env(char *env_data, uint32_t env_off, unsigned long nbytes);
char *socket_family_str(int family);
char *socket_type_str(int type);

#endif // HELPERS_H
