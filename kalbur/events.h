/*
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright 2021-2022 TRAPMINE, Inc.
 *
 * The eBPF code tracks various different events inside the kernel.
 * The structure of these events are described in this file.
 */

#ifndef EVENTS_H
#define EVENTS_H

#ifdef __BPF_HEADER__
#include "vmlinux.h"
typedef u64 u64_t;
typedef u32 u32_t;
typedef u16 u16_t;
typedef u8 u8_t;
#else
#include <stdint.h>
#include <sys/types.h>
typedef uint64_t u64_t;
typedef uint32_t u32_t;
typedef uint16_t u16_t;
typedef uint8_t u8_t;
#endif

// Temporary redefinition
// Remove once we build a seperate file for all
// kernel constants used in the project
#define TASK_COMM_LEN 16

/*
 * Segment with phdrs + Segment with text section
 * + Segment with data + 3*loader + 2*misc
 * + stack + vdso + vsyscall + vvar */
#define MAX_MMAP_RECORDS TYPED_MACRO(12, UL)
#define MMAP_BUFFSIZE                                                          \
	(sizeof(struct proc_mmap) * (MAX_MMAP_RECORDS) +                       \
	 sizeof(struct probe_event_header))

#define SMP_NUM 8

#define CALL(macro, ...) macro(__VA_ARGS__)
#define TYPED(value, type) value##type
#define TYPED_MACRO(value, type) CALL(TYPED, value, type)

//#define PER_CPU_STR_BUFFSIZE TYPED_MACRO((1 << 10), UL)
#define PER_CPU_STR_BUFFSIZE (1 << 10)
#define LAST_NULL_BYTE(buffsize) ((buffsize)-1)

#define PRESERVE_32_MSB(quad_word) ((quad_word >> 32) << 32)
#define PRESERVE_32_LSB(quad_word) ((quad_word << 32) >> 32)

#define PRESERVE_16_MSB(double_word) ((double_word >> 16) << 16)
#define PRESERVE_16_LSB(double_word) ((double_word << 16) >> 16)

#define WORKING_BUFF_INDX(cpu, event) ((PRESERVE_16_MSB(cpu << 16)) | event)

enum Data_T {
	Primary_Data = 1,
	String_Data = 2,
	Mmap_Data = 3,
	Dump_Data = 4,
	Max_Valid_Data_T = Dump_Data
};

struct probe_event_header {
	u64_t event_time;
	u64_t tgid_pid;
	char comm[TASK_COMM_LEN];
	int syscall_nr;
	enum Data_T data_type;
};

struct mmap_dump {
	u64_t vm_base;
	u64_t vm_len;
};

struct dump_header {
	struct probe_event_header eh;
	u64_t vm_base;
	u64_t vm_len;
	size_t dump_sz;
	size_t total_sz; // only set in zero dump_header.
};

/* Identifying information of a file
 * - filename (stored in the string buffer)
 * - length of full path
 * - inode number
 * - filesystem's magic number to which the inode belongs.
     An inode number is guaranteed to be unique inside a fs,
     therefore, (inode, fs) pair can be used to uniquely identify
     a file */
struct file_info {
	u32_t file_offset;
	u32_t path_len;
	u64_t i_ino;
	unsigned long s_magic;
};

struct creds {
	uid_t uid;
	gid_t gid;
	uid_t euid;
	gid_t egid;
};

struct proc_mmap {
	struct probe_event_header eh;
	unsigned long vm_base;
	unsigned long vm_flags;
	unsigned long vm_prot;
	unsigned long vm_len;
	struct file_info uf;
};

struct child_proc_info {
	struct probe_event_header eh;
	u64_t tgid_pid; // tgid_pid of forked process. event header contains tgid_pid of calling process.
	u64_t ppid;
	u64_t clone_flags;
};

struct mprotect_info {
	struct probe_event_header eh;
	size_t modn; // the number of vma's modified
	unsigned long start;
	unsigned long prot;
	size_t len;
};

enum STD_TYPE { STD_NONE, STD_SOCK, STD_PIPE };

#define STDIN_INDX 0
#define STDOUT_INDX 1
#define STDERR_INDX 2

struct stdio {
	unsigned long std_ino;
	enum STD_TYPE type;
};

struct process_info {
	struct probe_event_header eh;
	u64_t ppid;
	struct file_info file;
	struct {
		u32_t argv_offset;
		u32_t nargv;
	} args;
	u32_t interp_str_offset;
	struct creds credentials;
	u32_t mmap_cnt;
	int dump;
	struct stdio io[3];
};

struct exit_event {
	struct probe_event_header eh;
};

struct socket_create {
	struct probe_event_header eh;
	u64_t i_ino;
	int family;
	int type;
	int protocol;
};

struct tcp_ipv4_info {
	struct probe_event_header eh;
	u64_t i_ino;
	u64_t type;
	u16_t sport;
	u16_t dport;
	u32_t saddr;
	u32_t daddr;
};

struct tcp_ipv6_info {
	struct probe_event_header eh;
	u64_t i_ino;
	u64_t type;
	u16_t sport;
	u16_t dport;
	u64_t saddr[2];
	u64_t daddr[2];
};

struct cfg_integrity {
	struct probe_event_header eh;
	u64_t caller_addr;
};

struct ptrace_event_info {
	struct probe_event_header eh;
	long request;
	unsigned long addr;
	u64_t target_tgid_pid;
	u8_t emit;
};

struct kernel_module_load_info {
	struct probe_event_header eh;
	struct file_info f;
};

struct modprobe_overwrite {
	struct probe_event_header eh;
	char *new_path;
};

typedef union {
	struct tcp_ipv4_info t4;
	struct tcp_ipv6_info t6;
} tcp_info_t;

typedef union {
	struct process_info pinfo;
	struct child_proc_info cpinfo;
} proc_info_t;

typedef union {
	struct proc_mmap pm;
	struct mprotect_info minfo;
	struct socket_create sinfo;
	tcp_info_t t;
	struct ptrace_event_info ptrace_info;
	struct kernel_module_load_info kinfo;
} proc_activity_t;

/* Kernel symbol identifiers */
#define SOCKET_FILE_OPS 1
#define TCP_PROT 2
#define INET_OPS 3
#define PIPE_FOPS 4

#endif
