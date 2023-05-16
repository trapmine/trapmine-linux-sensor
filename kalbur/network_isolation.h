#ifndef NETWORK_ISOLATION_H
#define NETWORK_ISOLATION_H

#define NETWORK_ISOLATION_IDX 0
#define NETWORK_ISOLATION_ON 1
#define NETWORK_ISOLATION_OFF 0

#define NETWORK_ISOLATION_WHITELIST_IPS_MAX 10

struct network_isolation_config {
	uint32_t enable_network_isolation;
	uint32_t number_of_ips;
	uint32_t ips[NETWORK_ISOLATION_WHITELIST_IPS_MAX];
};
typedef struct network_isolation_config network_isolation_config_t;

#endif