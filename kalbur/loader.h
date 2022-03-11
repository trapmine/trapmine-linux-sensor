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
#pragma GCC diagnostic pop

#include <bpf/bpf.h>

int poll_buff(int, perf_buffer_sample_fn, perf_buffer_lost_fn, void *);
struct proc_monitor_bpf *load(void);

#endif
