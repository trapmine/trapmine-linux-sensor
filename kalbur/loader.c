/*
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright 2021-2022 TRAPMINE, Inc.
 *
 * This file provides the code loading the eBPF code into the kernel.
 */

#include <err.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <symsearch.h>
#include <sys/resource.h>
#include <linux/hw_breakpoint.h>
#include <net/if.h>
#include <sys/syscall.h>
#include <events.h>
#include <stdbool.h>
#include <loader.h>

#define KPROBE_TABLE 0
#define TRACEPOINT_TABLE 1
#define BPF_PROG_FDS 2
int progfds[BPF_PROG_FDS] = { 0 };


static int network_isolation_switch_fd = -1;
static int network_isolation_whitelist_ips_fd = -1;
static size_t tc_hooks_count = 0;
static size_t max_tc_hooks_count = 10;
static struct tc_hooks_set **tc_hooks_ptr = NULL;

struct ksym_name_id {
	char *name;
	int id;
};

const struct ksym_name_id symN[] = { { "socket_file_ops", SOCKET_FILE_OPS },
				     { "tcp_prot", TCP_PROT },
				     { "inet_stream_ops", INET_OPS },
				     { "tty_fops", TTY_FOPS },
				     { "pipefifo_fops", PIPE_FOPS } };

#define SYMS (sizeof(symN) / sizeof(symN[0]))

static void bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
		exit(1);
	}
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			   va_list args)
{
#ifdef __DEBUG__
	return vfprintf(stderr, format, args);
#endif
	return 0;
}

static void copy_bpf_tc_hook(struct bpf_tc_hook* dst, struct bpf_tc_hook* src) {
    dst->sz = src->sz;
    dst->ifindex = src->ifindex;
    dst->attach_point = src->attach_point;
    dst->parent = src->parent;
}

static void copy_bpf_tc_opts(struct bpf_tc_opts* dst, struct bpf_tc_opts* src) {
    dst->sz = src->sz;
    dst->prog_fd = src->prog_fd;
	dst->flags = src->flags;
	dst->prog_id = src->prog_id;
	dst->handle = src->handle;
	dst->priority = src->priority;
}

static inline int populuate_prog_array(struct bpf_program *prog, int key,
				       int table_type)
{
	int fd, err, table_fd;
	fd = bpf_program__fd(prog);
	table_fd = progfds[table_type];

	err = bpf_map_update_elem(table_fd, &key, &fd, (unsigned long long)BPF_ANY);

	return err;
}

// Check if the function is present in kallsyms, before attaching
// ToDo: Use hashtable
static bool check_kprobe_function(const char *section)
{
	char *name;

	// if not kprobe continue
	if (memcmp(section, "kprobe", 6UL))
		return true;

	name = strchr(section, '/');
	name++;

	if (ksym_get_addr(name)) {
		return true;
	}

	return false;
}

static inline int get_jump_table_indx(int id)
{
	return id % 1000;
}

static struct perf_event_attr init_perf_event_addr(int enabled,
						   unsigned long addr)
{
	struct perf_event_attr attr = {
		.type = PERF_TYPE_BREAKPOINT,
		.size = sizeof(attr),
		.sample_period = 1,
		.disabled = !enabled,
		.inherit = 1,
		.bp_addr = addr,
		.bp_type = HW_BREAKPOINT_W,
		.bp_len = HW_BREAKPOINT_LEN_1,
	};
	return attr;
}

static int attach_bpf_to_perf(struct bpf_program *bpf_prog)
{
	unsigned long addr;
	long i, cpus;
	int err, fd;
	struct perf_event_attr attr;
	struct bpf_link *link;

	addr = ksym_get_addr("modprobe_path");
	if (addr == 0) {
		return CODE_FAILED;
	}

	cpus = sysconf(_SC_NPROCESSORS_ONLN);
	attr = init_perf_event_addr(false, addr);
	for (i = 0; i < cpus; i++) {
#pragma GCC diagnostic push
#pragma GCC diagnostic warning "-Wconversion"
		fd = (int)syscall(TYPED_MACRO(__NR_perf_event_open, L), &attr,
				  -1, i, -1,
				  PERF_FLAG_FD_NO_GROUP | PERF_FLAG_FD_CLOEXEC);
#pragma GCC diagnostic pop

		if (fd < 0) {
			err = CODE_FAILED;
			goto out;
		}
		link = bpf_program__attach_perf_event(bpf_prog, fd);
		if (libbpf_get_error(link)) {
			return CODE_FAILED;
		}
	}

	err = CODE_SUCCESS;
out:
	return err;
}

int poll_buff(int streamer_fd, perf_buffer_sample_fn consumer,
	      perf_buffer_lost_fn err_fn, void *ctx)
{
	struct perf_buffer *pb = NULL;
	long libbpf_err;
	int err;

#define PERF_BUFFER_PAGES 64UL
	pb = perf_buffer__new(streamer_fd, PERF_BUFFER_PAGES, consumer, err_fn, ctx, NULL);
	libbpf_err = libbpf_get_error(pb);
	if (libbpf_err) {
		pb = NULL;
		fprintf(stderr, "failed to open perf buffer: %ld\n",
			libbpf_err);
		return CODE_FAILED;
	}

	/* if poll time is too slow it causes duplicate events to be reported
         * with the data of the duplicated event corrupted occasianally.
         * So far no such problem has been observed with poll time of 100.*/
	while ((err = perf_buffer__poll(pb, 100)) >= 0)
		;

	if (err)
		return CODE_FAILED;

	return CODE_SUCCESS;
}

void handle_network_isolation_config(struct network_isolation_config *config)
{
	int err;
	uint32_t idx;
	uint32_t value;
	uint32_t ip_indices[NETWORK_ISOLATION_WHITELIST_IPS_MAX];
	uint32_t ip_values[NETWORK_ISOLATION_WHITELIST_IPS_MAX];
	uint32_t number_of_ips = NETWORK_ISOLATION_WHITELIST_IPS_MAX;

	// delete old entries from network_isolation_whitelist_ips
	for(uint32_t i = 0; i < NETWORK_ISOLATION_WHITELIST_IPS_MAX; i++) {
		ip_indices[i] = i;
		ip_values[i] = 0;
	}
	DECLARE_LIBBPF_OPTS(bpf_map_batch_opts, delete_opts, .elem_flags = BPF_ANY);
	err = bpf_map_update_batch(network_isolation_whitelist_ips_fd, &ip_indices, &ip_values, &number_of_ips, &delete_opts);
	if (err != 0) {
		fprintf(stderr, "deleting old entries from network_isolation_whitelist_ips failed.: %d\n", err);
		goto ret;
	}

	for(uint32_t i = 0; i < config->number_of_ips; i++) {
		ip_indices[i] = i;
		ip_values[i] = config->ips[i];
	}
	DECLARE_LIBBPF_OPTS(bpf_map_batch_opts, add_opts, .elem_flags = BPF_ANY);
	err = bpf_map_update_batch(network_isolation_whitelist_ips_fd, &ip_indices, &ip_values, &number_of_ips, &delete_opts);
	if (err != 0) {
		fprintf(stderr, "adding new entries in network_isolation_whitelist_ips failed.: %d\n", err);
		goto ret;
	}

	idx = NETWORK_ISOLATION_IDX;
	value = NETWORK_ISOLATION_ON ? config->enable_network_isolation : NETWORK_ISOLATION_OFF;
	err = bpf_map_update_elem(network_isolation_switch_fd, &idx, &value, (unsigned long long)BPF_ANY);
	if (err != 0) {
		fprintf(stderr, "updating network_isolation_switch failed.\n");
		goto ret;
	}

ret:
	return;

}


struct proc_monitor_bpf *load(void)
{
	struct proc_monitor_bpf *skel = NULL;
	struct bpf_object *obj;
	struct bpf_link *link;
	struct bpf_program *prog;
	const char *section;
	int key, tprog_table_fd, kprog_table_fd, symtab_fd, err;
	unsigned long addr;

	/* load kernel symbols */
	err = load_kallsyms();
	if (err < 0) {
		fprintf(stderr, "Error while loading kernel symbols: %d\n",
			err);
		err = CODE_FAILED;
		goto out;
	}
	build_commit_creds_pls();

	/* Setup libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Bump RLIMIT_MEMLOCK to create BPF maps */
	bump_memlock_rlimit();

	skel = proc_monitor_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		goto cleanup;
	}

	/* Load and verify BPF program */
	err = proc_monitor_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load BPF skeleton\n");
		goto cleanup;
	}

	obj = skel->obj;

	/* Populate maps with kernel symbols */
	symtab_fd = bpf_object__find_map_fd_by_name(obj, "symbol_table");
	if (symtab_fd < 0) {
		fprintf(stderr,
			"finding map symbol_table failed in PROG ARRAY.\n");
		goto cleanup;
	}
	for (unsigned int i = 0; i < SYMS; ++i) {
		addr = ksym_get_addr(symN[i].name);

		err = bpf_map_update_elem(symtab_fd, &addr, &(symN[i].id),
					  (unsigned long long)BPF_ANY);

		if (err != 0)
			goto cleanup;
	}

	/* Populate network isolation switch map*/
	network_isolation_switch_fd = bpf_object__find_map_fd_by_name(obj, "network_isolation_switch");
	if (network_isolation_switch_fd < 0) {
		fprintf(stderr, "finding map network_isolation_switch failed in bpf obj.\n");
		goto cleanup;
	}
	int network_isolation_idx = 0;
	int network_isolation_value = NETWORK_ISOLATION_OFF;
	err = bpf_map_update_elem(network_isolation_switch_fd, &network_isolation_idx, &network_isolation_value, (unsigned long long)BPF_ANY);
	if (err != 0)
		goto cleanup;

	/* Populate network isolation whitelist ips*/
	network_isolation_whitelist_ips_fd = bpf_object__find_map_fd_by_name(obj, "network_isolation_whitelist_ips");
	if (network_isolation_whitelist_ips_fd < 0) {
		fprintf(stderr, "finding map network_isolation_whitelist_ips failed in bpf obj.\n");
		goto cleanup;
	}

	/* Attach sub programs */
	tprog_table_fd = bpf_object__find_map_fd_by_name(obj, "tprog_table");
	if (tprog_table_fd < 0) {
		fprintf(stderr, "finding map in obj file failed\n");
		goto cleanup;
	}
	progfds[TRACEPOINT_TABLE] = tprog_table_fd;

	kprog_table_fd = bpf_object__find_map_fd_by_name(obj, "kprog_table");
	if (kprog_table_fd < 0) {
		fprintf(stderr, "finding map in obj file failed\n");
		goto cleanup;
	}
	progfds[KPROBE_TABLE] = kprog_table_fd;

	/* Attach tracepoints and place subprograms in PROG ARRAY */
	bpf_object__for_each_program(prog, obj)
	{
		section = bpf_program__section_name(prog);
		if (sscanf(section, "kprobe/%d", &key) == 1) {
			printf("Loading prog: kprobe/%d\n", key);
			err = populuate_prog_array(
				prog, get_jump_table_indx(key), KPROBE_TABLE);
			if (err)
				goto cleanup;
		} else if (sscanf(section, "tracepoint/%d", &key) == 1) {
			err = populuate_prog_array(prog,
						   get_jump_table_indx(key),
						   TRACEPOINT_TABLE);
			if (err)
				goto cleanup;
		} else if (!memcmp(section, "perf_event", 10UL)) {
			err = attach_bpf_to_perf(prog);
			if (err == CODE_FAILED) {
				fprintf(stderr,
					"Failed to attach perf event\n");

				goto cleanup;
			}
		} else if (!memcmp(section, "tc", 2UL)) {
			// get all interfaces
			struct if_nameindex *if_nidxs, *intf;

		    if_nidxs = if_nameindex();
    		if ( if_nidxs != NULL ) {
		        for (intf = if_nidxs; intf->if_index != 0 || intf->if_name != NULL; intf++) {
					printf("Attaching %s (%s) to %s interface\n", section, bpf_program__name(prog), intf->if_name);
					int ifindex = (int)intf->if_index;

					// create egress and ingress hook
					DECLARE_LIBBPF_OPTS(bpf_tc_hook, egress_hook, .ifindex = ifindex, .attach_point = BPF_TC_EGRESS);
					DECLARE_LIBBPF_OPTS(bpf_tc_hook, ingress_hook, .ifindex = ifindex, .attach_point = BPF_TC_INGRESS);

					// create egress|ingress hook
					DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = ifindex, .attach_point = BPF_TC_INGRESS|BPF_TC_EGRESS);

					// try to delete old clsact qdisc
					err = bpf_tc_hook_destroy(&hook);
					if (err) {
						fprintf(stderr, "Failed to delete tc clsact qdisc: %d\n", err);
					}
					
					// create a clsact qdisc
					err = bpf_tc_hook_create(&hook);
					if (err) {
						fprintf(stderr, "Failed to create tc clsact qdisc\n");
						goto cleanup;
					}

					int fd = bpf_program__fd(prog);

					// create egress and ingress options
					DECLARE_LIBBPF_OPTS(bpf_tc_opts, egress_opts, .prog_fd = fd);
					DECLARE_LIBBPF_OPTS(bpf_tc_opts, ingress_opts, .prog_fd = fd);

					// attach egress filter
					err = bpf_tc_attach(&egress_hook, &egress_opts);
					if (err) {
						fprintf(stderr, "Failed to attach tc egress hook\n");

						egress_hook.attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS;
						bpf_tc_hook_destroy(&egress_hook);
						goto cleanup;
					}

					// attach ingress filter
					err = bpf_tc_attach(&ingress_hook, &ingress_opts);
					if (err) {
						fprintf(stderr, "Failed to attach tc ingress hook\n");

						ingress_hook.attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS;
						bpf_tc_hook_destroy(&ingress_hook);
						goto cleanup;
					}

					// store the hooks and options in an array
					// so we can detach and destroy them later
					struct tc_hook *tc_egress_hook_curr = (struct tc_hook *)calloc(1UL, sizeof(struct tc_hook));
					struct tc_hook *tc_ingress_hook_curr = (struct tc_hook *)calloc(1UL, sizeof(struct tc_hook));
					
					copy_bpf_tc_hook(&tc_egress_hook_curr->hook, &egress_hook);
					copy_bpf_tc_opts(&tc_egress_hook_curr->opts, &egress_opts);

					copy_bpf_tc_hook(&tc_ingress_hook_curr->hook, &ingress_hook);
					copy_bpf_tc_opts(&tc_ingress_hook_curr->opts, &ingress_opts);

					struct tc_hooks_set *tc_hooks_curr = (struct tc_hooks_set *)calloc(1UL, sizeof(struct tc_hooks_set));
					tc_hooks_curr->egress = tc_egress_hook_curr;
					tc_hooks_curr->ingress = tc_ingress_hook_curr;

					if (tc_hooks_count == 0) {
						tc_hooks_ptr = (struct tc_hooks_set **)calloc(max_tc_hooks_count, sizeof(struct tc_hooks_set *));
					} else if (tc_hooks_count == max_tc_hooks_count) {
						max_tc_hooks_count *= 2;
						tc_hooks_ptr = (struct tc_hooks_set **)realloc(tc_hooks_ptr, sizeof(struct tc_hooks_set *) * (max_tc_hooks_count));
					}

					tc_hooks_ptr[tc_hooks_count] = tc_hooks_curr;

					tc_hooks_count++;
        		}
	        	if_freenameindex(if_nidxs);
    		}
		} else if (check_kprobe_function(section)) {
			printf("Attaching %s\n", section);
			link = bpf_program__attach(prog);
			if (libbpf_get_error(link)) {
				fprintf(stderr,
					"bpf_program__attach failed: %s\n",
					section);
				goto cleanup;
			}
		}
	}

	return skel;

cleanup:
	printf("cleanup\n");
	proc_monitor_bpf__destroy(skel);
	skel = NULL;
out:
	return NULL;
}

int cleanup_tc(void)
{
	int err = 0;
	for(size_t i = 0; i < tc_hooks_count; i++) {
		tc_hooks_ptr[i]->egress->opts.prog_fd = 0;
		tc_hooks_ptr[i]->egress->opts.prog_id = 0;
		printf("Detaching hooks for ifindex: %d\n", tc_hooks_ptr[i]->egress->hook.ifindex);
		err = bpf_tc_detach(&tc_hooks_ptr[i]->egress->hook, &tc_hooks_ptr[i]->egress->opts);
		if (err) {
			fprintf(stderr, "Failed to detach tc egress hook for ifindex: %d\n", tc_hooks_ptr[i]->egress->hook.ifindex);
		}

		tc_hooks_ptr[i]->ingress->opts.prog_fd = 0;
		tc_hooks_ptr[i]->ingress->opts.prog_id = 0;
		err = bpf_tc_detach(&tc_hooks_ptr[i]->ingress->hook, &tc_hooks_ptr[i]->egress->opts);
		if (err) {
			fprintf(stderr, "Failed to detach tc ingress hook for ifindex: %d\n", tc_hooks_ptr[i]->ingress->hook.ifindex);
		}

		tc_hooks_ptr[i]->egress->hook.attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS;
		err = bpf_tc_hook_destroy(&tc_hooks_ptr[i]->egress->hook);
		if (err) {
			fprintf(stderr, "Failed to destroy tc hook for ifindex: %d\n", tc_hooks_ptr[i]->egress->hook.ifindex);
		}

		free(tc_hooks_ptr[i]->egress);
		free(tc_hooks_ptr[i]->ingress);
		free(tc_hooks_ptr[i]);
	}

	free(tc_hooks_ptr);

	printf("exiting cleanup_tc\n");
	return err;
}
