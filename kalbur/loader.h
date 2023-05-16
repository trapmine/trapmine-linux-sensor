/*
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright 2021-2022 TRAPMINE, Inc.
 */

#ifndef LOADER_H
#define LOADER_H

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wtraditional-conversion"
#pragma GCC diagnostic ignored "-Wpedantic"
#pragma GCC diagnostic ignored "-Wsign-conversion"
#pragma GCC diagnostic ignored "-Woverlength-strings"
#include <proc_monitor.skel.h>
#pragma GCC diagnostic pop

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#include <bpf/libbpf.h>
#include <linux/perf_event.h>
#include <linux/pkt_cls.h>
#pragma GCC diagnostic pop

#include <bpf/bpf.h>
#include "kalbur/rule_engine/listener.h"
#include "network_isolation.h"

int poll_buff(int, perf_buffer_sample_fn, perf_buffer_lost_fn, void *);
void handle_network_isolation_config(struct network_isolation_config *config);
int cleanup_tc(void);
struct proc_monitor_bpf *load(void);

struct tc_hook {
    struct bpf_tc_hook hook;
    struct bpf_tc_opts opts;
};

struct tc_hooks_set {
    struct tc_hook *egress;
    struct tc_hook *ingress;
};

#endif
