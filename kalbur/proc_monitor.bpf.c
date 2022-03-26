/*
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright 2021-2022 TRAPMINE, Inc.
 *
 * This contains the eBPF code which will collect events
 * used by the rule_engine in userspace, to detect security
 * relevant events
 */

#include "missing_defs.h"
#include "vmlinux.h"
#include "events.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>
#include "syscall_defs.h"

// ***********************************
// ******** Error Codes **************
// ***********************************
#define ESTRNOTWRITTEN 140
#define EBPFLOOKUPFAIL 141
#define EBPFUNBOUNDEDMEMACCESS 142
#define INVALIDWRITE 143
#define CTXINVALIDARG 144

/* Max possible size of array value is 1 << 25
 * https://elixir.bootlin.com/linux/v4.18/source/kernel/bpf/arraymap.c#L57
 * The array is allocated via kmalloc, which allocates contiguous memory.
 * So max size is 1 << KMALLOC_MAX_SIZE (upper bound 1 << 25) */

/* Max number of allowed args is something ridiculous
 * like PAGE_SIZE * 32 bytes.
 * This ought to be enough */
#define MAX_ARGS_READ 10

// 15 path length keeps us at the instruction count limit
#define MAX_PATH_LENGTH 15

#define PRESERVE_MMAP_INDX ((MMAP_BUFFSIZE) << 1)

#define PRESERVE_STR_INDX ((PER_CPU_STR_BUFFSIZE) << 1)

#undef KERNEL_VERSION
#define KERNEL_VERSION(a, b, c) (((a) << 16) + ((b) << 8) + (c))

#define JUMP_TARGET(target)                                                    \
	if (err < 0)                                                           \
		goto target;

#ifdef __DEBUG_BPF__
#define DEBUG_PRINTK(s, ...) bpf_printk(s, ##__VA_ARGS__);
#else
#define DEBUG_PRINTK(s, ...)                                                   \
	do {                                                                   \
	} while (0)
#endif

#ifdef __SINGULAR__
#define SINGULAR(s, ...) bpf_printk(s, ##__VA_ARGS__);
#else
#define SINGULAR(s, ...)                                                       \
	do {                                                                   \
	} while (0)
#endif

#ifdef __LOG_ERR__
#define LOG(err, s, ...)                                                       \
	if (err < 0) {                                                         \
		bpf_printk(s, ##__VA_ARGS__);                                  \
	}
#else
#define LOG(err, s, ...)                                                       \
	do {                                                                   \
	} while (0)
#endif

#define BPF_MAP(_name, _type, _key_type, _value_type, _max_entries)            \
	struct {                                                               \
		__uint(type, _type);                                           \
		__uint(max_entries, _max_entries);                             \
		__type(key, _key_type);                                        \
		__type(value, _value_type);                                    \
	} _name SEC(".maps");

#define BPF_PERF_EVENT_ARRAY_MAP(name, value_type, max_entries)                \
	BPF_MAP(name, BPF_MAP_TYPE_PERF_EVENT_ARRAY, u32, value_type,          \
		max_entries)

#define BPF_ARRAY_MAP(name, value_type, max_entries)                           \
	BPF_MAP(name, BPF_MAP_TYPE_ARRAY, u32, value_type, max_entries);

#define BPF_PER_CPU_ARRAY_MAP(name, value_type, max_entries)                   \
	BPF_MAP(name, BPF_MAP_TYPE_PERCPU_ARRAY, u32, value_type, max_entries);

#define BPF_HASH_MAP(name, key_type, value_type, max_entries)                  \
	BPF_MAP(name, BPF_MAP_TYPE_HASH, key_type, value_type, max_entries)

#define BPF_PER_CPU_HASH_MAP(name, key_type, value_type, max_entries)          \
	BPF_MAP(name, BPF_MAP_TYPE_PERCPU_HASH, key_type, value_type,          \
		max_entries);

#define BPF_PROG_ARRAY(name, max_entries)                                      \
	BPF_MAP(name, BPF_MAP_TYPE_PROG_ARRAY, u32, u32, max_entries)

// ***************************************
// ********** MISC CONSTANTS *************
// ***************************************

// ***************************************
// ********* INTERNAL STRUCTS ************
// ***************************************

/* Tracepoints context structures */
struct syscall_enter_ctx {
	u64 unused;
	long id;
	unsigned long args[6];
};

struct syscall_execve_ctx {
	u64 unused;
	int syscall_nr;
	long filename_ptr;
	long args_str_arr_ptr;
	long envp_str_arr_ptr;
};

struct syscall_enter_fork_clone_ctx {
	u64 unused;
	int syscall_nr;
	unsigned long clone_flags;
};

struct syscall_enter_mmap_ctx {
	u64 unused;
	int syscall_nr;
	unsigned long args1[2];
	unsigned long
		prot; // we use prot to decide whether to record mmap event or not.
	unsigned long args
		[3]; // at the moment we only use the syscall_nr. The other arguments are ignored.
};

struct syscall_exit_fork_clone_ctx {
	u64 unused;
	int syscall_nr;
	long pid; // This is the pid seen from the pid namespace
		// of the calling process. (Should be fixed to be the
		// the actual pid seen by host system??)
};

struct syscall_enter_clone3_args {
	u64 unused;
	int syscall_nr;
	struct clone_args *uargs;
};

struct syscall_enter_mprotect {
	u64 unused;
	int syscall_nr;
	unsigned long start;
	size_t len;
	unsigned long prot;
};

struct syscall_enter_socket {
	u64 unused;
	int syscall_nr;
	int family;
	int type;
	int protocol;
};

struct syscall_enter_ptrace {
	u64 unused;
	int syscall_nr;
	long request;
	long pid;
	unsigned long addr;
	unsigned long data;
};

struct sched_process_fork {
	u64 unused;
	char parent_com[16];
	u32 parent;
	char child_comm[16];
	u32 child;
};

struct syscall_exit {
	u64 unused;
	int syscall_nr;
	long ret;
};

/* Array Maps value types */

#define STRUCT_BUFF(size, type_name)                                           \
	typedef struct type_name##_buff {                                      \
		u8 buff[size];                                                 \
	} type_name;

/* We practically waste the last PER_CPU_STR_BUFFSIZE bytes
 * This is only present so that the verifier is sure that 
 * we do not write past memory bound.
 * This situation arises becauses the verifier does not
 * constrain upper bounds by taking into account inter variable dependence.
 */

#define PERCPU_EVENTS 5
#define MAX_EVENT_BUFFERS (SMP_NUM * PERCPU_EVENTS)

#define TOTAL_STR_BUFFSIZE ((MAX_EVENT_BUFFERS + 1) * (PER_CPU_STR_BUFFSIZE))

STRUCT_BUFF(TOTAL_STR_BUFFSIZE, str_buff_t);

/* we allocate an extra MMAP_BUFFSIZE bytes space in the buffer
 * in order to handle the same verifier quirk, discussed above with regards
 * to the string buffer */
#define TOTAL_MMAP_BUFFSIZE (MAX_EVENT_BUFFERS + 1) * (MMAP_BUFFSIZE)

STRUCT_BUFF(TOTAL_MMAP_BUFFSIZE, mmap_buff_t);

typedef struct buff_tracker {
	u32 curr_str_indx;
	u32 curr_mmap_indx;
	u32 locked;
} tracker_t;

#define GET_EVENT_METADATA(var, func)                                          \
	var = bpf_map_lookup_elem(&event_metadata_map, &tgid_pid);             \
	if (var == 0) {                                                        \
		DEBUG_PRINTK("[%ld] " func                                     \
			     ": Failed to lookup event metadata.\n",           \
			     tgid_pid >> 32);                                  \
		goto out;                                                      \
	}

typedef struct event_metadata {
	int syscall_nr; // the system call this event is tracking
	u32 wbuff; // working buffer
} event_t;

#define GET_MPROTECT_INFO(_union, elem) (_union.minfo.elem)

#define SET_MPROTECT_INFO(_union, elem, val) _union.minfo.elem = val

#define SET_PROC_MMAP(_union, elem, val) _union.pm.elem = val;

// ****************************************
// *********** MAP definitions ************
// ****************************************

/* Event metadata */
BPF_HASH_MAP(event_metadata_map, u64, event_t, MAX_EVENT_BUFFERS);

/* hash map to hold process_info struct */
BPF_HASH_MAP(proc_info_map, u64, proc_info_t, MAX_EVENT_BUFFERS);

/* hash map to hold process activity */
BPF_HASH_MAP(proc_activity_map, u64, proc_activity_t, MAX_EVENT_BUFFERS);

/* Per cpu array to persist struct proc_mmap during an execve syscall 
 * Multiple memory regions are mapped one after another during execve
 * We use this array to follow the mapping of each region */
BPF_PER_CPU_ARRAY_MAP(execve_mmap_tracker, struct proc_mmap, 1);

/* Scratch buffer to hold strings */
BPF_ARRAY_MAP(str_buffs_map, str_buff_t, 1);

/* Scratch buffer to hold mmap regions */
BPF_ARRAY_MAP(mmap_buffs_map, mmap_buff_t, 1);

/* Buffer to hold mmap dump */

// maximum supported allocation size for percpu maps as defined
// in mm/percpu.h
#define PCPU_MAX_ALLOC (32 << 10)
#define PCPU_MAX_PAGES (PCPU_MAX_ALLOC / PAGE_SIZE)
STRUCT_BUFF(PCPU_MAX_ALLOC, mmap_dump_buff_t);
BPF_PER_CPU_ARRAY_MAP(dump_streamer, mmap_dump_buff_t, 1)

/* Buffer to hold mmap regions to dump */
#define MMAP_DUMP_BIN_SZ (sizeof(struct mmap_dump) * (MAX_MMAP_RECORDS))
STRUCT_BUFF(MMAP_DUMP_BIN_SZ, mmap_dump_arr_t);

#define DUMP_ENTRIES 20
BPF_HASH_MAP(mmap_dump_bin, u64, mmap_dump_arr_t, DUMP_ENTRIES);

struct dump_indx {
	u32 indx;
	// We squeeze the event_time here, so we can
	// give a consistent value for the entire mmap dump.
	// This is needed in the userspace, where a complete message is built
	// from multiple different events, by comparing event headers for
	// equality.
	u64 event_time;
	size_t running_sz;
};
BPF_PER_CPU_ARRAY_MAP(curr_mmap_dump_map, struct dump_indx, 1);

/* Map to hold trackers for the current index of scratch buffers.
 * Each cpu gets PERCPU_EVENTS number of slots from index (cpu*PERCPU_EVENTS)
 * The reason we do this, rather than using PERCPU_MAPS, is if the process gets 
 * migrated to a different cpu, it ends up reading the incorrect tracker. 
 * This case was observed in some tests */
BPF_ARRAY_MAP(buff_tracker_map, tracker_t, MAX_EVENT_BUFFERS);
//BPF_PER_CPU_ARRAY_MAP(buff_tracker_map, tracker_t, MAX_EVENT_BUFFERS);

/* Output ringbuffer */
BPF_PERF_EVENT_ARRAY_MAP(streamer, u32, MAX_EVENT_BUFFERS);

/* jump_table routines start from 100
 * in order to differentiate their section names
 * from syscall handlers in the userspace loader code. */

#define NR_ROUTINES 8
/* Subprograms of type kprobe */
#define SAVE_MMAP_FILE 1001
#define DUMP_VM 1002
#define EXEC_REGION 1003
BPF_PROG_ARRAY(kprog_table, NR_ROUTINES);

/* Subprograms of type tracepoint */
BPF_PROG_ARRAY(tprog_table, NR_ROUTINES);

/* Table holding the addresses of some kernel symbols */
BPF_HASH_MAP(symbol_table, u64, u32, 10);

enum t_typename { TYPENAME_STRBUFF_T, TYPENAME_MMAP_BUFF_T };

// ***************************************
// ************** Helpers ****************
// ***************************************

#define MAX_ERRNO 4095

#define MY_IS_ERR_VALUE(x)                                                     \
	((unsigned long)(void *)(x) >= (unsigned long)-MAX_ERRNO)

static inline void *MY_ERR_PTR(long error)
{
	return (void *)error;
}

static inline long MY_PTR_ERR(const void *ptr)
{
	return (long)ptr;
}

static inline int MY_IS_ERR(const void *ptr)
{
	return MY_IS_ERR_VALUE((unsigned long)ptr);
}

static inline int MY_IS_ERR_OR_NULL(const void *ptr)
{
	return !ptr || MY_IS_ERR_VALUE((unsigned long)ptr);
}

__attribute__((always_inline)) static tracker_t *get_buff_tracker(u32 buff_num)
{
	tracker_t *tracker;

	tracker =
		(tracker_t *)bpf_map_lookup_elem(&buff_tracker_map, &buff_num);

	return tracker;
}

__attribute__((always_inline)) static int get_str_buff_indx(u32 buff_num)
{
	tracker_t *offset;
	offset = get_buff_tracker(buff_num);

	if (offset == 0) {
		return -EBPFLOOKUPFAIL;
	}

	return offset->curr_str_indx;
}

__attribute__((always_inline)) static int get_mmap_buff_indx(u32 buff_num)
{
	tracker_t *offset;
	offset = get_buff_tracker(buff_num);

	if (offset == 0) {
		return -EBPFLOOKUPFAIL;
	}

	return offset->curr_mmap_indx;
}

#define UNLOCK 0
#define LOCK 1

__attribute__((always_inline)) static long
set_buff_indx(u32 buff_num, u32 str_value, u32 mmap_value, u32 lock)
{
	tracker_t *tracker;
	tracker_t new_tracker;

	tracker = get_buff_tracker(buff_num);

	if (tracker == 0)
		return -EBPFLOOKUPFAIL;

	new_tracker.curr_str_indx = str_value == PRESERVE_STR_INDX ?
						  tracker->curr_str_indx :
						  str_value;
	new_tracker.curr_mmap_indx = mmap_value == PRESERVE_MMAP_INDX ?
						   tracker->curr_mmap_indx :
						   mmap_value;
	new_tracker.locked = lock;

	return bpf_map_update_elem(&buff_tracker_map, &buff_num, &new_tracker,
				   BPF_EXIST);
}

__attribute__((always_inline)) static long set_str_buff_indx(u32 buff_num,
							     u32 str_value)
{
	return set_buff_indx(buff_num, str_value, (PRESERVE_MMAP_INDX), LOCK);
}

__attribute__((always_inline)) static long set_mmap_buff_indx(u32 buff_num,
							      u32 mmap_value)
{
	return set_buff_indx(buff_num, (PRESERVE_STR_INDX), mmap_value, LOCK);
}

__attribute__((always_inline)) static long set_tracker_lock(u32 buff_num,
							    u32 lock)
{
	tracker_t *tracker;
	tracker_t new_tracker;

	tracker = get_buff_tracker(buff_num);

	if (tracker == 0)
		return -EBPFLOOKUPFAIL;

	new_tracker.curr_str_indx = tracker->curr_str_indx;
	new_tracker.curr_mmap_indx = tracker->curr_mmap_indx;

	new_tracker.locked = lock;

	return bpf_map_update_elem(&buff_tracker_map, &buff_num, &new_tracker,
				   BPF_EXIST);
}

__attribute__((always_inline)) static long get_working_buff(event_t *event)
{
	long err;
	tracker_t *tracker;
	u32 cpu, wbuff;

	cpu = bpf_get_smp_processor_id();

#pragma clang loop unroll(full)
	for (unsigned int i = 0; i < PERCPU_EVENTS; ++i) {
		wbuff = (cpu * PERCPU_EVENTS) + i;
		tracker = get_buff_tracker(wbuff);

		if (tracker == 0) {
			err = -EBPFLOOKUPFAIL;
			goto out;
		}

		if ((tracker->locked == UNLOCK) &&
		    (tracker->curr_str_indx == 0) &&
		    (tracker->curr_mmap_indx == 0)) {
			err = set_tracker_lock(wbuff, LOCK);
			if (err == 0) {
				event->wbuff = wbuff;
				goto out;
			}
		}

		if (tracker->locked == UNLOCK) {
			SINGULAR(
				"get_working_buff: locked tracker: str: %d, mmap: %d\n",
				tracker->curr_str_indx,
				tracker->curr_mmap_indx);
		}
	}

	err = -EBUSY;
out:
	if (err != 0) {
		SINGULAR("Failed to acquire working buffer: %d\n", err);
	}
	return err;
}

__attribute__((always_inline)) static int
save_to_mmap_buffer(u32 buff_num, struct proc_mmap *pm)
{
	u32 buff_indx;
	long indx = 0;
	mmap_buff_t *buffer;
	u32 new_indx;
	long err;

	err = get_mmap_buff_indx(buff_num);
	JUMP_TARGET(out);

	buff_indx = (u32)err;

	indx = (buff_num * (MMAP_BUFFSIZE)) + buff_indx;
	if ((indx > ((MMAP_BUFFSIZE)*MAX_EVENT_BUFFERS)) || (indx < 0)) {
		err = -EBPFUNBOUNDEDMEMACCESS;
		goto out;
	}

	u32 map_num = 0;
	buffer = bpf_map_lookup_elem(&mmap_buffs_map, &map_num);
	if (buffer == 0) {
		err = -EBPFLOOKUPFAIL;
		goto out;
	}

	err = bpf_probe_read(&(buffer->buff[indx]), sizeof(struct proc_mmap),
			     pm);
	JUMP_TARGET(out);

	new_indx = buff_indx + sizeof(struct proc_mmap);
	err = set_mmap_buff_indx(buff_num, new_indx);
out:
	return err;
}

__attribute__((always_inline)) static int
save_str_to_buff(u32 buff_indx, u32 buff_num, char *str)
{
	int str_size;
	u32 rem_buff_size;
	long err;
	str_buff_t *buffer;
	long indx = 0;
	str_size = 0;

	indx = (buff_num * (PER_CPU_STR_BUFFSIZE)) + buff_indx;
	if ((indx > ((PER_CPU_STR_BUFFSIZE)*MAX_EVENT_BUFFERS)) || (indx < 0)) {
		str_size = -EBPFUNBOUNDEDMEMACCESS;
		goto out;
	}

	buff_indx = buff_indx % (PER_CPU_STR_BUFFSIZE);
	rem_buff_size =
		((PER_CPU_STR_BUFFSIZE)-1) -
		buff_indx; // Last byte should always be 0, to ensure null termination

	u32 map_num = 0;
	buffer = bpf_map_lookup_elem(&str_buffs_map, &map_num);
	if (buffer == 0) {
		str_size = -EBPFLOOKUPFAIL;
		goto out;
	}

	str_size =
		bpf_probe_read_str(&(buffer->buff[indx]), rem_buff_size, str);
out:
	return str_size;
}

/* Save given string to string buffer buff_num. On error return 0.*/
__attribute__((always_inline)) static u32 save_str(char *str, u32 buff_num)
{
	int buff_indx;
	long update_err;
	int str_size;
	u32 new_indx;

	buff_indx = get_str_buff_indx(buff_num);
	if (buff_indx < 0) {
		str_size = 0;
		goto out;
	}

	str_size = save_str_to_buff(buff_indx, buff_num, str);
	if (str_size <= 0) {
		// Incase we fail to save string make sure
		// to return that no chars were saved
		str_size = 0;
		goto out;
	}

	new_indx = str_size + buff_indx;

	if ((update_err = set_str_buff_indx(buff_num, new_indx)))
		str_size = update_err;
out:
	return str_size;
}

__attribute__((always_inline)) static u64
save_str_arr_to_buff(u32 buff_num, unsigned long *args)
{
	char *arg_str;
	long err;
	unsigned long scnt;
	u64 nbyte_pair;
	u32 strs, s;

	strs = 0;
	scnt = 0;
#pragma clang loop unroll(full)
	for (unsigned int i = 0; i < MAX_ARGS_READ; ++i) {
		if (args == 0)
			goto out;

		err = bpf_probe_read(&arg_str, sizeof(char *), args);
		JUMP_TARGET(out);

		if (!arg_str) {
			goto out;
		}

		s = save_str(arg_str, buff_num);
		if (s > 0)
			strs += s;

		scnt++;

		args++;
	}

out:
	return (scnt << 32) | strs;
}

__attribute__((always_inline)) static long
save_orig_name(u32 str_buff_num, u32 path_size, const unsigned char *name)
{
	long err;
	u32 old_indx;

	/* move the buffer indx path_size bytes back.
	 * We do this inorder to delete any partial
	 * path that may have been saved */
	err = get_str_buff_indx(str_buff_num);
	JUMP_TARGET(out);

	old_indx = err - path_size;
	if (old_indx < 0) {
		err = -EINVAL;
		goto out;
	}

	err = set_str_buff_indx(str_buff_num, old_indx);
	JUMP_TARGET(out);

	// save generic file
	err = save_str((char *)name, str_buff_num);
	if (err == 0)
		err = -ESTRNOTWRITTEN;
out:
	return err;
}

/* Return size of path written
 * In case of err, we write [FILE] as the name
 * so we can still illustrate that the mmap region is 
 * backed by a file */
__attribute__((always_inline)) static long
build_dentry_name(struct dentry *d, u32 str_buff_num, u32 *path_bytes)
{
	struct dentry *dentry = d;
	unsigned int pathlen;
	struct qstr q_name;
	const unsigned char *name;
	long err;
	char root[2] = "/";
	u32 orig_indx;

	*path_bytes = 0;

#pragma clang loop unroll(full)
	for (pathlen = 0; pathlen < MAX_PATH_LENGTH; pathlen++) {
		d = dentry;

		err = bpf_core_read(&q_name, sizeof(q_name), &(dentry->d_name));
		JUMP_TARGET(generic);

		err = save_str((char *)q_name.name, str_buff_num);
		if (err == 0)
			goto generic;

		*path_bytes += err;

		err = bpf_core_read(&(dentry), sizeof(dentry),
				    &(dentry->d_parent));
		JUMP_TARGET(generic);

		// dentry->d_parent == d
		if (dentry == d) {
			if (pathlen == 0)
				pathlen++;
			goto ret;
		}
	}
ret:
	if (pathlen == MAX_PATH_LENGTH)
		goto generic;

	return pathlen;

generic:
	pathlen = 1;
	err = bpf_core_read(&q_name, sizeof(q_name), &(d->d_name));
	JUMP_TARGET(fail);

	name = q_name.name;
	err = save_orig_name(str_buff_num, *path_bytes, name);
	JUMP_TARGET(fail);

	*path_bytes = err;
	err = pathlen;
fail:
	*path_bytes = 0;
	return err;
}

__attribute__((always_inline)) static u64 save_file_path(struct file *f,
							 event_t *emeta)
{
	struct path p;
	struct dentry *d;
	u32 file_offset;
	long err;
	u32 str_size;
	long pathlen;
	u64 pathlen_pathoffset;

	if (f == 0)
		goto error;

	err = bpf_core_read(&p, sizeof(struct path), &f->f_path);
	JUMP_TARGET(error);

	err = bpf_core_read(&d, sizeof(d), &p.dentry);
	JUMP_TARGET(error);

	pathlen = build_dentry_name(d, emeta->wbuff, &str_size);
	if (pathlen < 0)
		goto error;
	err = get_str_buff_indx(emeta->wbuff);
	JUMP_TARGET(error);

	file_offset = err - str_size;
	if (file_offset < 0)
		goto error;

	pathlen_pathoffset = (u32)pathlen;
	pathlen_pathoffset = (pathlen_pathoffset << 32) | file_offset;

	return pathlen_pathoffset;

error:
	file_offset = LAST_NULL_BYTE(PER_CPU_STR_BUFFSIZE);
	pathlen_pathoffset = file_offset & 0xffffffff; // zero out pathlen

	return pathlen_pathoffset;
}

__attribute__((always_inline)) static long save_event_metadata(event_t *emd)
{
	long err;
	u64 tgid_pid = bpf_get_current_pid_tgid();

	err = bpf_map_update_elem(&event_metadata_map, &tgid_pid, emd,
				  BPF_NOEXIST);

	return err;
}

__attribute__((always_inline)) static long
handle_syscall_exit(void *syscall_data_map, event_t *emeta, u64 tgid)
{
	long err;

	u32 cpu = bpf_get_smp_processor_id();
	u32 buff = 0;
	if (emeta != NULL) {
		// clean event information
		err = bpf_map_delete_elem(&event_metadata_map, &tgid);
		LOG(err,
		    "handle_syscall_exit: Failed to delete element from event_metadata_map: %d\n",
		    err);
		// reset tracker
		err = set_str_buff_indx(emeta->wbuff, 0);
		LOG(err,
		    "handle_syscall_exit: Failed to reset str_buff index in relevant tracker: %d\n",
		    err);

		err = set_mmap_buff_indx(emeta->wbuff, 0);
		LOG(err,
		    "handle_syscall_exit: Failed to reset mmap_buff index in relevant tracker: %d\n",
		    err);
		err = set_tracker_lock(emeta->wbuff, UNLOCK);
		LOG(err,
		    "handle_syscall_exit: Failed to unlock relevant tracker: %d\n",
		    err);
	}

	if (syscall_data_map != NULL) {
		err = bpf_map_delete_elem(syscall_data_map, &tgid);
		LOG(err,
		    "handle_syscall_exit: Failed to delete event information entry from map for syscall=%d: %d\n",
		    err, emeta->syscall_nr);
	} else
		err = 0;

out:
	return err;
}

__attribute__((always_inline)) static u64 get_tgid_pid(struct task_struct *t)
{
	int err;
	u64 tgid;
	u32 pid;

	tgid = 0;
	err = BPF_CORE_READ_INTO(&tgid, t, tgid);
	JUMP_TARGET(out);

	err = BPF_CORE_READ_INTO(&pid, t, pid);
	if (err < 0) {
		tgid = 0;
		goto out;
	}

	tgid = (tgid << 32) | pid;
out:
	return tgid;
}

__attribute__((always_inline)) static u64 get_ppid()
{
	u64 tgid_pid;
	u32 pid;
	long err;
	struct task_struct *task;
	struct task_struct *parent_task;

	task = (struct task_struct *)bpf_get_current_task();

	err = bpf_core_read(&parent_task, sizeof(parent_task),
			    &(task->real_parent));
	if (err < 0) {
		tgid_pid = err;
		goto out;
	}

	err = BPF_CORE_READ_INTO(&tgid_pid, parent_task, tgid);
	if (err < 0) {
		tgid_pid = 0;
		goto out;
	}

	err = BPF_CORE_READ_INTO(&pid, parent_task, pid);
	if (err < 0) {
		tgid_pid = 0;
		goto out;
	}

	tgid_pid = (tgid_pid << 32) | pid;

out:
	return tgid_pid;
}

__attribute__((always_inline)) static void
initialize_event_header(struct probe_event_header *eh, int syscall_nr,
			u64 tgid_pid)
{
	eh->tgid_pid = tgid_pid;
	eh->syscall_nr = syscall_nr;
	eh->event_time = bpf_ktime_get_ns();
	eh->data_type = Primary_Data;
	bpf_get_current_comm(eh->comm, TASK_COMM_LEN);
}

__attribute__((always_inline)) static int
initialize_mmap_buffer(struct probe_event_header *eh_primary, int syscall_nr,
		       u64 tgid_pid, u32 buff_num)
{
	int buff_indx;
	long indx;
	mmap_buff_t *buffer;
	int err;
	u32 new_indx;
	struct probe_event_header eh;

	eh.syscall_nr = eh_primary->syscall_nr;
	eh.tgid_pid = eh_primary->tgid_pid;
	eh.event_time = eh_primary->event_time;
	bpf_get_current_comm(eh.comm, TASK_COMM_LEN);
	eh.data_type = Mmap_Data;

	buff_indx = get_mmap_buff_indx(buff_num);
	if (buff_indx < 0) {
		err = buff_indx;
		goto out;
	}

	indx = (buff_num * (MMAP_BUFFSIZE)) + buff_indx;
	if ((indx > ((MMAP_BUFFSIZE)*MAX_EVENT_BUFFERS)) || (indx < 0)) {
		err = -EBPFUNBOUNDEDMEMACCESS;
		goto out;
	}

	u32 map_num = 0;
	buffer = bpf_map_lookup_elem(&mmap_buffs_map, &map_num);
	if (buffer == 0) {
		err = -EBPFLOOKUPFAIL;
		goto out;
	}

	// write event header
	err = bpf_probe_read(&(buffer->buff[indx]),
			     sizeof(struct probe_event_header), &eh);
	JUMP_TARGET(out);

	// increment index
	new_indx = buff_indx + sizeof(struct probe_event_header);
	err = set_mmap_buff_indx(buff_num, new_indx);

out:
	return err;
}

__attribute__((always_inline)) static int
initialize_str_buffer(struct probe_event_header *eh_primary, int syscall_nr,
		      u64 tgid_pid, u32 buff_num)
{
	int buff_indx;
	long indx;
	str_buff_t *buffer;
	int err;
	u32 new_indx;
	struct probe_event_header eh;

	eh.event_time = eh_primary->event_time;
	eh.syscall_nr = eh_primary->syscall_nr;
	eh.tgid_pid = eh_primary->tgid_pid;
	bpf_get_current_comm(eh.comm, TASK_COMM_LEN);
	eh.data_type = String_Data;

	buff_indx = get_str_buff_indx(buff_num);
	if (buff_indx < 0) {
		err = buff_indx;
		goto out;
	}

	indx = (buff_num * (PER_CPU_STR_BUFFSIZE)) + buff_indx;
	if ((indx > ((PER_CPU_STR_BUFFSIZE)*MAX_EVENT_BUFFERS)) || (indx < 0)) {
		err = -EBPFUNBOUNDEDMEMACCESS;
		goto out;
	}

	u32 map_num = 0;
	buffer = bpf_map_lookup_elem(&str_buffs_map, &map_num);
	if (buffer == 0) {
		err = -EBPFLOOKUPFAIL;
		goto out;
	}

	err = bpf_probe_read(&(buffer->buff[indx]),
			     sizeof(struct probe_event_header), &eh);
	JUMP_TARGET(out);

	new_indx = buff_indx + sizeof(struct probe_event_header);
	err = set_str_buff_indx(buff_num, new_indx);
out:
	return err;
}

__attribute__((always_inline)) static int
initialize_event(event_t *emeta, u64 tgid_pid, int syscall_nr)
{
	long err;

	err = get_working_buff(emeta);
	if (err != 0)
		goto out;

	emeta->syscall_nr = syscall_nr;

	err = save_event_metadata(emeta);

out:
	if (err != 0) {
		SINGULAR("[%ld] save event metadata failed: %d\n", tgid_pid,
			 err);
	}

	return err;
}

__attribute__((always_inline)) static int
generic_event_start_handler(int sys_nr)
{
	event_t emeta;
	u64 tgid_pid;
	int err;

	tgid_pid = bpf_get_current_pid_tgid();
	err = initialize_event(&emeta, tgid_pid, sys_nr);

	return err;
}

__attribute__((always_inline)) static int generic_event_exit_handler(void *map)
{
	u64 tgid_pid;
	event_t *emeta;

	tgid_pid = bpf_get_current_pid_tgid();

	GET_EVENT_METADATA(emeta, "sys_exit_connect");

	handle_syscall_exit(map, emeta, tgid_pid);
out:
	return 0;
}

__attribute__((always_inline)) static void
handle_fork_enter(struct syscall_enter_fork_clone_ctx *ctx)
{
	proc_info_t info = {};
	u64 tgid_pid;

	tgid_pid = bpf_get_current_pid_tgid();

	initialize_event_header(&(info.cpinfo.eh), ctx->syscall_nr, tgid_pid);

	bpf_map_update_elem(&proc_info_map, &tgid_pid, &info, BPF_NOEXIST);
}

__attribute__((always_inline)) static void
handle_fork_exit(struct syscall_exit_fork_clone_ctx *ctx)
{
	u64 tgid_pid;

	tgid_pid = bpf_get_current_pid_tgid();
	handle_syscall_exit(&proc_info_map, NULL, tgid_pid);
	return;
}

__attribute__((always_inline)) static int
should_trace_probe(event_t *emeta, unsigned int syscall_nr)
{
	if (emeta->syscall_nr == syscall_nr)
		return 1;
	else
		return 0;
}

__attribute__((always_inline)) static int
should_trace_probe_mmap(event_t *emeta)
{
	int event_syscall = emeta->syscall_nr;

	if ((event_syscall == SYS_MMAP) || (event_syscall == SYS_EXECVE)) {
		return event_syscall;
	}

	return 0;
}

__attribute__((always_inline)) static long is_tmpfs_execve(u64 tgid_pid)
{
	struct process_info *pinfo;
	int err;
	err = 0;

	pinfo = bpf_map_lookup_elem(&proc_info_map, &tgid_pid);
	if (pinfo == 0) {
		err = -EBPFLOOKUPFAIL;
		goto out;
	}

	if (pinfo->dump)
		return TMPFS_MAGIC;
out:
	return err;
}

__attribute__((always_inline)) static long
save_mmap_base_addr(struct pt_regs *ctx, event_t *emeta, u64 tgid_pid)
{
	struct file *file;
	struct proc_mmap *pm;
	struct proc_mmap new_pm = { 0 };
	struct proc_mmap zero_pm = { 0 };
	void *map;
	int err;
	u64 indx;

	if (emeta->syscall_nr == SYS_EXECVE) {
		map = &execve_mmap_tracker;
		indx = 0;
	} else if (emeta->syscall_nr == SYS_MMAP) {
		map = &proc_activity_map;
		indx = tgid_pid;
	} else {
		err = -EINVAL;
		goto out;
	}

	pm = bpf_map_lookup_elem(map, &indx);
	if (pm == 0) {
		err = -EBPFLOOKUPFAIL;
		goto out;
	}

	err = bpf_probe_read(&new_pm, sizeof(struct proc_mmap), pm);
	JUMP_TARGET(out);

	/* This check enforces the order that security_mmap_addr
	 * is called after security_mmap_file, which is the pattern
	 * unique to mmap syscall.
	 * Note: if file is NULL then file_offset = PER_CPU_STR_BUFFSIZE - 1 */
	if (new_pm.uf.file_offset == 0)
		goto out;

	new_pm.vm_base = PT_REGS_PARM1(ctx);

	if (emeta->syscall_nr == SYS_EXECVE) {
		err = bpf_map_update_elem(map, &indx, &zero_pm, BPF_EXIST);
		err = save_to_mmap_buffer(emeta->wbuff, &new_pm);
	} else if (emeta->syscall_nr == SYS_MMAP)
		err = bpf_map_update_elem(map, &indx, &new_pm, BPF_EXIST);
	else
		err = -EINVAL;
out:
	return err;
}

__attribute__((always_inline)) static long calc_mmap_cnt(u32 buff_num,
							 u64 tgid_pid)
{
	long err;
	int map_cnt;
	struct process_info new_p = {};
	struct process_info *pinfo;

	pinfo = bpf_map_lookup_elem(&proc_info_map, &tgid_pid);
	if (pinfo == 0) {
		err = -EBPFLOOKUPFAIL;
		goto out;
	}

	err = get_mmap_buff_indx(buff_num);
	JUMP_TARGET(out);

	map_cnt = (err - sizeof(struct probe_event_header)) /
		  sizeof(struct proc_mmap);

	err = bpf_probe_read(&new_p, sizeof(struct process_info), pinfo);
	JUMP_TARGET(out);

	new_p.mmap_cnt = map_cnt;

	err = bpf_map_update_elem(&proc_info_map, &tgid_pid, &new_p, BPF_EXIST);

out:
	return err;
}

__attribute__((always_inline)) static long
output_arr_to_streamer(void *ctx, void *buffer_map, u64 buff_size,
		       event_t *emeta)
{
	u32 indx;
	long err;
	u32 bytes_written;
	str_buff_t *buffer;

	u32 b = 0;
	buffer = bpf_map_lookup_elem(buffer_map, &b);
	if (buffer == 0) {
		err = -EBPFLOOKUPFAIL;
		goto out;
	}

	indx = buff_size * emeta->wbuff;
	if (indx > (buff_size * MAX_EVENT_BUFFERS)) {
		err = -EBPFUNBOUNDEDMEMACCESS;
		goto out;
	}

	if (buffer_map == &str_buffs_map)
		err = get_str_buff_indx(emeta->wbuff);
	else if (buffer_map == &mmap_buffs_map)
		err = get_mmap_buff_indx(emeta->wbuff);
	else
		err = -EINVAL;
	JUMP_TARGET(out);

	bytes_written = (u32)err;
	if (bytes_written > buff_size)
		goto out;

	err = bpf_perf_event_output(ctx, &streamer, BPF_F_CURRENT_CPU,
				    &(buffer->buff[indx]),
				    bytes_written); // output

out:
	return err;
}
__attribute__((always_inline)) static long
save_credentials(struct linux_binprm *lbprm, struct process_info *new_pinfo)
{
	uid_t uid, euid;
	gid_t gid, egid;
	struct cred *credentials;
	long err;

	err = bpf_core_read(&credentials, sizeof(struct cred *), &lbprm->cred);
	JUMP_TARGET(out);

	err = bpf_core_read(&uid, sizeof(uid_t), &credentials->uid);
	JUMP_TARGET(out);

	err = bpf_core_read(&gid, sizeof(gid_t), &credentials->gid);
	JUMP_TARGET(out);

	err = bpf_core_read(&euid, sizeof(uid_t), &credentials->euid);
	JUMP_TARGET(out);

	err = bpf_core_read(&egid, sizeof(gid_t), &credentials->egid);
	JUMP_TARGET(out);

	new_pinfo->credentials.uid = uid;
	new_pinfo->credentials.gid = gid;
	new_pinfo->credentials.euid = euid;
	new_pinfo->credentials.egid = egid;
out:
	return err;
}

__attribute__((always_inline)) static long
save_file_info(struct file *f, struct file_info *finfo)
{
	unsigned long i_ino;
	unsigned long smg;
	long err;

	i_ino = 0;
	smg = 0;

	err = BPF_CORE_READ_INTO(&i_ino, f, f_inode, i_ino);
	JUMP_TARGET(out);

	err = BPF_CORE_READ_INTO(&smg, f, f_inode, i_sb, s_magic);
	JUMP_TARGET(save);
save:
	finfo->i_ino = i_ino;
	finfo->s_magic = smg;

out:
	return err;
}

__attribute__((always_inline)) static int get_jump_table_indx(int id)
{
	return id % 1000;
}

__attribute__((always_inline)) static long
get_vm_flags(struct vm_area_struct *vma)
{
	long err;
	unsigned long flags;

	u64 tgid_pid = bpf_get_current_pid_tgid();
	if (vma == 0) {
		err = -EINVAL;
		goto out;
	}

	// Permissions for a vm_area_struct is defined by vm_flags
	err = bpf_core_read(&flags, sizeof(unsigned long), &(vma->vm_flags));
	if (err < 0)
		goto out;

	err = (long)flags;
out:
	return err;
}

__attribute__((always_inline)) static long
get_vm_start(struct vm_area_struct *vma)
{
	long err;
	unsigned long vm_start;

	if (vma == 0) {
		err = -EINVAL;
		goto out;
	}

	err = bpf_core_read(&vm_start, sizeof(unsigned long), &(vma->vm_start));
	if (err < 0)
		goto out;

	err = (long)vm_start;
out:
	return err;
}

__attribute__((always_inline)) static int
set_ipv4_fields(struct tcp_ipv4_info *t, struct inet_sock *inet_sk)
{
	int err = 0;
	struct sock *sk = (struct sock *)inet_sk;

	// 1. Destination info
	err = bpf_core_read(&t->daddr, sizeof(t->daddr), &inet_sk->inet_daddr);
	JUMP_TARGET(out);

	err = bpf_core_read(&t->dport, sizeof(t->dport), &inet_sk->inet_dport);
	JUMP_TARGET(out);
	t->dport = bpf_ntohs(t->dport);

	// 2. Source info
	err = bpf_core_read(&t->saddr, sizeof(t->saddr),
			    &inet_sk->inet_rcv_saddr);
	JUMP_TARGET(out);

	err = bpf_core_read(&t->sport, sizeof(t->sport), &inet_sk->inet_num);
	JUMP_TARGET(out);
out:
	return err;
}

__attribute__((always_inline)) static int
set_ipv6_fields(struct tcp_ipv6_info *t, struct inet_sock *inet_sk)
{
	struct sock *sk = (struct sock *)inet_sk;
	int err = 0;

	// 1. Destination info
	err = bpf_core_read(&t->daddr, sizeof(t->daddr),
			    &sk->__sk_common.skc_v6_daddr);
	JUMP_TARGET(out);

	err = bpf_core_read(&t->dport, sizeof(t->dport),
			    &sk->__sk_common.skc_dport);
	JUMP_TARGET(out);
	t->dport = bpf_ntohs(t->dport);

	// 2. Source info
	err = bpf_core_read(&t->saddr, sizeof(t->saddr),
			    &sk->__sk_common.skc_v6_rcv_saddr);
	JUMP_TARGET(out);

	err = bpf_core_read(&t->sport, sizeof(t->sport), &inet_sk->inet_sport);
	JUMP_TARGET(out);

out:
	return err;
}

__attribute__((always_inline)) static int
generate_and_emit_tcp_info(struct pt_regs *ctx, int sys_nr)
{
	int err = 0;
	event_t *emeta;
	u64 pinet6; // Ptr to struct populated when type = AF_INET6
	tcp_info_t new_t = { 0 };
	tcp_info_t *t;
	u64 tgid_pid = bpf_get_current_pid_tgid();
	struct sock *sk;
	struct inet_sock *inet_sk;

	GET_EVENT_METADATA(emeta, "generate_and_emit_tcp_info");

	sk = (struct sock *)PT_REGS_PARM1(ctx);
	if (sk == 0) {
		err = -CTXINVALIDARG;
		goto error;
	}

	t = (tcp_info_t *)bpf_map_lookup_elem(&proc_activity_map, &tgid_pid);
	if (t == 0) {
		err = -EBPFLOOKUPFAIL;
		goto out;
	}

	err = bpf_probe_read(&new_t, sizeof(tcp_info_t), t);
	JUMP_TARGET(error);

	inet_sk = (struct inet_sock *)sk;

	// Since tcp_info_t is a union t.t4.eh and t.t6.eh
	// are at the same address
	initialize_event_header(&new_t.t4.eh, sys_nr, tgid_pid);

	err = bpf_core_read(&pinet6, sizeof(u64), &(inet_sk->pinet6));
	JUMP_TARGET(error);

	if (pinet6 == 0) {
		set_ipv4_fields(&new_t.t4, inet_sk);
		new_t.t4.type = AF_INET;
	} else {
		set_ipv6_fields(&new_t.t6, inet_sk);
		new_t.t6.type = AF_INET6;
	}

	err = bpf_perf_event_output(ctx, &streamer, BPF_F_CURRENT_CPU, &new_t,
				    sizeof(tcp_info_t));
error:
	err = bpf_map_delete_elem(&proc_activity_map, &tgid_pid);
out:
	return err;
}

/* We have two different functions for getting the inode number of struct socket:
 * get_inode_from_socket_alloc() and get_inode_from_socket()
 * get_inode_from_socket() takes the inode number of the socket from socket->file->f_inode.i_ino
 * get_inode_from_socket_alloc() takes the inode from socket_alloc.vfs_inode->i_ino
 * The reason for these two functions is because get_inode_from_socket_alloc() is used in the
 * security_socket_post_create() hook. At this point the struct file* member of socket has not
 * been created, so we cannot use that to get the inode number.
 *
 * get_inode_from_socket() is used in hooks where the struct file* member has been created.
 * This member is created from the same inode object as socket_alloc.vfs_inode as can be seen
 * in the following call chain: 
 * __sys_socket -> sock_map_fd -> sock_alloc_file -> alloc_file_pseudo */
__attribute__((always_inline)) static unsigned long
get_inode_from_socket_alloc(struct socket *sock)
{
	struct inode *inode_ptr;
	struct socket_alloc *sock_alloc;
	unsigned long i_ino;
	int err;
	int inode_off = offsetof(struct inode, i_ino) + 8;
	u8 data[inode_off];

	sock_alloc = (struct socket_alloc *)sock;

	err = bpf_core_read(&data, inode_off, &sock_alloc->vfs_inode);
	JUMP_TARGET(out);

	inode_ptr = (struct inode *)&data;
	return inode_ptr->i_ino;
out:
	return 0;
}
__attribute__((always_inline)) static unsigned long
get_inode_from_socket(struct socket *sock)
{
	struct file *f;
	unsigned long i_ino;
	int err;

	err = bpf_core_read(&f, sizeof(struct file *), &sock->file);
	JUMP_TARGET(out);

	err = BPF_CORE_READ_INTO(&i_ino, f, f_inode, i_ino);
	JUMP_TARGET(out);

	return i_ino;
out:
	return 0;
}

__attribute__((always_inline)) static int
fingerprint_tcp_inet_ops(struct socket *sock)
{
	struct proto_ops *pops;
	int err;
	u32 *addr_id;

	if (sock == 0) {
		err = -EINVAL;
		goto out;
	}

	err = bpf_core_read(&pops, sizeof(struct proto_ops *), &sock->ops);
	if (err < 0)
		goto out;

	addr_id = (u32 *)bpf_map_lookup_elem(&symbol_table, &pops);
	if (addr_id == 0) {
		err = -EINVAL;
		goto out;
	}

	if (*addr_id == TCP_PROT || *addr_id == INET_OPS)
		err = TCP_PROT;
out:
	return err;
}

/* Fingerprint the type of the file by the file operations
 * If fops socket and if socket's proto_ops tcp_prot,
 * then we are interested */
__attribute__((always_inline)) static int
fingerprint_tcp_socket_ops(struct socket *sock, struct file *f)
{
	int err;
	struct file_operations *fops;
	u32 *addr_id;

	if (f == 0) {
		err = -EINVAL;
		goto out;
	}

	err = bpf_core_read(&fops, sizeof(struct file_operations *), &f->f_op);
	if (err < 0)
		goto out;

	addr_id = (u32 *)bpf_map_lookup_elem(&symbol_table, &fops);
	if (addr_id == NULL) {
		err = -EINVAL;
		goto out;
	}

	if (*addr_id != SOCKET_FILE_OPS) {
		err = -EINVAL;
		goto out;
	}

	err = fingerprint_tcp_inet_ops(sock);
out:
	return err;
}

__attribute__((always_inline)) static int
test_if_file_socket(struct file *f, unsigned long *private_data)
{
	int err;

	err = bpf_core_read(private_data, sizeof(void *), &f->private_data);
	JUMP_TARGET(out);

	err = fingerprint_tcp_inet_ops((struct socket *)*private_data);

out:
	return err;
}

/* Pipe inodes are place in f.f_path.dentry->inode->i_ino;
 * see create_pipe_files() -> alloc_file_pseudo() */
__attribute__((always_inline)) static u64 get_pipe_inode(struct file *f)
{
	int err;
	u64 i_ino;

	err = BPF_CORE_READ_INTO(&i_ino, f, f_path.dentry, d_inode, i_ino);
	JUMP_TARGET(out);

	return i_ino;
out:
	return 0;
}

__attribute__((always_inline)) static int fingerprint_fops(struct file *f)
{
	int err;
	struct file_operations *fops;
	u32 *addr_id;

	if (f == 0) {
		err = -EINVAL;
		goto out;
	}

	err = bpf_core_read(&fops, sizeof(struct file_operations *), &f->f_op);
	if (err < 0)
		goto out;

	addr_id = (u32 *)bpf_map_lookup_elem(&symbol_table, &fops);
	if (addr_id == NULL) {
		err = -EINVAL;
		goto out;
	}

	err = *addr_id;
out:
	return err;
}

__attribute__((always_inline)) static unsigned long
get_standard_pipes_inodes(u64 tgid_pid)
{
	struct task_struct *curr;
	struct files_struct *files;
	struct fdtable *fdt;
	void *fdarr;
	struct file *std[3];
	int err;
	unsigned long private_data[3];
	struct process_info *pinfo;
	struct process_info new_pinfo;

	curr = (struct task_struct *)bpf_get_current_task();

	err = BPF_CORE_READ_INTO(&fdarr, curr, files, fdt, fd);
	JUMP_TARGET(out);

	err = bpf_core_read(&std, 3 * sizeof(struct files *), fdarr);
	JUMP_TARGET(out);

	pinfo = bpf_map_lookup_elem(&proc_info_map, &tgid_pid);
	if (pinfo == 0)
		goto out;

	err = bpf_probe_read(&new_pinfo, sizeof(struct process_info), pinfo);
	JUMP_TARGET(out);

#pragma clang loop unroll(full)
	for (int i = 0; i <= STDERR_INDX; ++i) {
		err = fingerprint_fops(std[i]);
		if (err == SOCKET_FILE_OPS) {
			err = test_if_file_socket(std[i], &private_data[i]);
			if (!(err < 0)) {
				new_pinfo.io[i].std_ino = get_inode_from_socket(
					(struct socket *)private_data[i]);
				new_pinfo.io[i].type = STD_SOCK;
			}
		} else if (err == PIPE_FOPS) {
			new_pinfo.io[i].std_ino = get_pipe_inode(std[i]);
			new_pinfo.io[i].type = STD_PIPE;
		}
	}

	err = bpf_map_update_elem(&proc_info_map, &tgid_pid, &new_pinfo,
				  BPF_EXIST);
	JUMP_TARGET(out);

out:
	return 0;
}

__attribute__((always_inline)) static int
initialize_dump_bin(mmap_dump_buff_t *out, u64 event_time, u64 vm_base,
		    u64 vm_len)
{
	int err;
	struct dump_header dh = { 0 };

	bpf_get_current_comm(dh.eh.comm, TASK_COMM_LEN);
	dh.eh.tgid_pid = bpf_get_current_pid_tgid();
	dh.eh.event_time = event_time;
	dh.eh.data_type = Dump_Data;
	dh.eh.syscall_nr = DUMP_MMAP_DATA;

	dh.vm_base = vm_base;
	dh.vm_len = vm_len;

	err = bpf_probe_read(&(out->buff[0]), sizeof(struct dump_header), &dh);

	return err;
}

// perf_event_output emits 4 extra bytes.
#define PERF_EVENT_EXTRA 4
__attribute__((always_inline)) static void dump_vm_region(void *ctx,
							  void *prog_map)
{
	u64 tgid_pid, vm_base, perf_out_sz;
	long err;
	u32 map_num, indx, arr_indx;
	struct dump_indx *to_dump;
	struct dump_indx new_dump_indx = { 0 };
	struct mmap_dump pm_dump;
	struct dump_header dhz = { 0 };
	mmap_dump_arr_t *buffer;

	tgid_pid = bpf_get_current_pid_tgid();

	/* Get the mmap_dump struct for the mmap region to dump */
	buffer = bpf_map_lookup_elem(&mmap_dump_bin, &tgid_pid);
	if (buffer == 0)
		goto out;

	map_num = 0;
	to_dump = bpf_map_lookup_elem(&curr_mmap_dump_map, &map_num);
	if (to_dump == 0)
		goto out;

	indx = sizeof(struct mmap_dump) * to_dump->indx;
	if (indx > (sizeof(struct mmap_dump) * MAX_MMAP_RECORDS))
		goto out;

	err = bpf_probe_read(&pm_dump, sizeof(struct mmap_dump),
			     &(buffer->buff[indx]));
	JUMP_TARGET(out);

	if (pm_dump.vm_base == 0)
		goto out;

	/* Acquire and initialize the per-cpu map holding the dump data before output */
	mmap_dump_buff_t *output =
		bpf_map_lookup_elem(&dump_streamer, &map_num);
	if (output == 0) {
		err = -EINVAL;
		goto out;
	}

	void *addr = (void *)pm_dump.vm_base;
	err = initialize_dump_bin(output, to_dump->event_time, pm_dump.vm_base,
				  pm_dump.vm_len);
	if (err < 0)
		goto out;

	arr_indx = sizeof(struct dump_header);

/* We read PAGE_SIZE bytes at a time from the mmap region. The vm_len field is a lie
	 * and does not show the actual mages of mapped virtual memory. Therefore we read
	 * page by page upto 8 pages, or until bpf_probe_read returns an error.
	 * If we read all 8 pages, we continue with the same region in the next recursion */
#pragma clang loop unroll(full)
	for (u32 i = 0; i < PCPU_MAX_PAGES;
	     i++, addr += PAGE_SIZE, arr_indx += PAGE_SIZE) {
		if (arr_indx < 0)
			goto out;

		if ((arr_indx + PAGE_SIZE) > PCPU_MAX_ALLOC)
			break;

		err = bpf_probe_read(&(output->buff[arr_indx]), PAGE_SIZE,
				     addr);
		if (err < 0)
			break;
	}

	// If er encountered error in bpf_probe_read, then all the mapped
	// pages have been read, and we contiue to the next index.
	if (err < 0) {
		map_num = 0;
		// In older kernel you might have to use bpf_probe_read(new_dump, to_dump)
		// Leaving this comment incase this error has to be resolved.
		new_dump_indx.indx = to_dump->indx + 1;
		new_dump_indx.event_time = to_dump->event_time;
		// If there was no error, then we have to continue with the same mmap regions.
		// We modify the mmap_dump struct at the current index to hold the vm_base up till
		// the address we have read, so we can continue from here in the next recursion.
	} else if (arr_indx != 0) {
		pm_dump.vm_base = (u64)addr;
		pm_dump.vm_len -= arr_indx;

		// Redo check because verifier complains.
		// We need to show the verifier that there is enough space
		// to write the new pm_dump, thus the (MAX_MMAP_RECORDS - 1)
		indx = to_dump->indx;
		if (indx > (sizeof(struct mmap_dump) * (MAX_MMAP_RECORDS - 1)))
			goto out;

		err = bpf_probe_read(&(buffer->buff[indx]),
				     sizeof(struct mmap_dump), &pm_dump);

		new_dump_indx.indx = to_dump->indx;
		new_dump_indx.event_time = to_dump->event_time;
	}

	/* emit dump to userspace */
	perf_out_sz = (u64)arr_indx;
	// Constrain arr_indx because the verifier complains.
	perf_out_sz %= PCPU_MAX_ALLOC;
	err = bpf_perf_event_output(ctx, &streamer, BPF_F_CURRENT_CPU,
				    &(output->buff[0]), perf_out_sz);
	if (err < 0)
		goto out;

	// We keep the number of bytes emitted to the userspace in the dump_index struct.
	// This value is finally emitted with the zero header, so that we can know in userspace
	// when the dump is finished.
	new_dump_indx.running_sz =
		to_dump->running_sz + arr_indx + PERF_EVENT_EXTRA;
	err = bpf_map_update_elem(&curr_mmap_dump_map, &map_num, &new_dump_indx,
				  BPF_ANY);
	JUMP_TARGET(out);

	indx = get_jump_table_indx(DUMP_VM);
	bpf_tail_call(ctx, prog_map, indx);
	SINGULAR("DUMP_VM: bpf_tail_call failed\n");
out:
	/* We get reference to to_dump again because this target maybe
	 * reached without the referece being acquired. Incase of failiure
	 * in the above code we jump here because we want to always try to
	 * emit zero header to userspace in order to signal end of dump. This is
	 * required incase the failiure happened once the dumping recursion
	 * started */
	map_num = 0;
	to_dump = bpf_map_lookup_elem(&curr_mmap_dump_map, &map_num);
	if (to_dump == 0)
		goto del;

	bpf_get_current_comm(dhz.eh.comm, TASK_COMM_LEN);
	dhz.eh.tgid_pid = tgid_pid;
	dhz.eh.event_time = to_dump->event_time;
	dhz.eh.data_type = Dump_Data;
	dhz.eh.syscall_nr = DUMP_MMAP_DATA;
	// We finally set dump_header->total_sz with the number of bytes emitted.
	dhz.total_sz = to_dump->running_sz + sizeof(struct dump_header) +
		       PERF_EVENT_EXTRA;
	bpf_perf_event_output(ctx, &streamer, BPF_F_CURRENT_CPU, &dhz,
			      sizeof(struct dump_header));

del:
	err = bpf_map_delete_elem(&mmap_dump_bin, &tgid_pid);

	return;
}

__attribute__((always_inline)) static void call_dump_vm(void *ctx,
							void *prog_map)
{
	u32 indx, map_num;
	u64 tgid_pid;
	struct dump_indx zindx = { 0 };
	mmap_dump_arr_t *buff;
	int err;

	tgid_pid = bpf_get_current_pid_tgid();

	buff = bpf_map_lookup_elem(&mmap_dump_bin, &tgid_pid);
	if (buff == 0)
		goto out;

	zindx.indx = 0;
	zindx.event_time = bpf_ktime_get_ns();

	map_num = 0;
	err = bpf_map_update_elem(&curr_mmap_dump_map, &map_num, &zindx,
				  BPF_ANY);
	JUMP_TARGET(out);

	indx = get_jump_table_indx(DUMP_VM);
	bpf_tail_call(ctx, prog_map, indx);
	SINGULAR("bpf_tail_call DUMP_VM failed \n");

out:
	return;
}

__attribute__((always_inline)) static struct vm_area_struct *
get_next_vm(struct vm_area_struct *curr_vm, struct task_struct *task)
{
	int err;
	struct mm_struct *mm;
	struct vm_area_struct *vm;

	if (curr_vm == NULL) {
		err = BPF_CORE_READ_INTO(&vm, task, mm, mmap);
		JUMP_TARGET(out);
	} else {
		err = bpf_core_read(&vm, sizeof(struct vm_area_struct *),
				    &curr_vm->vm_next);
		JUMP_TARGET(out);
	}

	return vm;
out:
	return NULL;
}

/* Check if the current task is a kernel thread */
__attribute__((always_inline)) static int task_kthread(struct task_struct *t)
{
	int ret, err;
	struct mm_struct *mm;

	ret = 0;
	err = 0;

	err = bpf_core_read(&mm, sizeof(struct mm_struct *), &(t->mm));
	if (err < 0)
		goto out;

	// Kernel threads have mm == NULL
	// Why? https://kernelnewbies.kernelnewbies.narkive.com/Glj0IaUL/active-mm-versus-mm
	if (MY_IS_ERR_OR_NULL(mm))
		ret = 1;

out:
	return ret;
}

__attribute__((always_inline)) static int task_root(struct task_struct *t)
{
	int err, ret;
	struct cred *creds;
	kuid_t uid;

	ret = 0;
	err = 0;
	err = bpf_core_read(&creds, sizeof(struct cred *), &t->real_cred);
	if (err < 0)
		goto out;

	err = bpf_core_read(&uid, sizeof(kuid_t), &creds->uid);
	if (err < 0)
		goto out;

	if (uid.val == 0)
		ret = 1;

out:
	return ret;
}

// ****************************************
// ********* Jump Table Routines **********
// ****************************************
#define KPROG(F) SEC("kprobe/" __stringify(F)) int bpf_kprobe_func_##F
#define TPROG(F) SEC("tracepoint/" __stringify(F)) int bpf_tracepoint_func_##F

KPROG(SAVE_MMAP_FILE)(struct pt_regs *ctx)
{
	u64 tgid_pid, pathlen_pathoffset, indx, flag;
	event_t *emeta;
	struct proc_mmap *pm;
	struct proc_mmap new_pm = { 0 };
	struct file *f;
	int err;
	void *map;
	u64 i_ino, s_magic;

	tgid_pid = bpf_get_current_pid_tgid();

	GET_EVENT_METADATA(emeta, "SAVE_MMAP_FILE");

	f = (struct file *)PT_REGS_PARM1(ctx);

	if (emeta->syscall_nr == SYS_EXECVE) {
		map = &execve_mmap_tracker;
		indx = 0;
		flag = BPF_ANY;
	} else {
		map = &proc_activity_map;
		indx = tgid_pid;
		flag = BPF_EXIST;
	}

	pm = bpf_map_lookup_elem(map, &indx);
	if ((pm == 0) &&
	    (emeta->syscall_nr ==
	     SYS_MMAP)) // if SYS_EXECVE && pm == 0, then maybe first time this code path is invoked, so we fall through.
		goto out;
	else if (pm != 0) {
		err = bpf_probe_read(&new_pm, sizeof(struct proc_mmap), pm);
		if (err)
			goto out;
	}

	new_pm.vm_prot = PT_REGS_PARM2(ctx);
	new_pm.vm_flags = PT_REGS_PARM3(ctx);

	pathlen_pathoffset = save_file_path(f, emeta);
	new_pm.uf.file_offset = pathlen_pathoffset & 0xffffffff;
	new_pm.uf.path_len = pathlen_pathoffset >> 32;

	// ignore error value. incase of error
	// we still want the partial data
	save_file_info(f, &new_pm.uf);

	err = bpf_map_update_elem(map, &indx, &new_pm, flag);
	JUMP_TARGET(out);

out:
	return 0;
}

KPROG(DUMP_VM)(void *ctx)
{
	dump_vm_region(ctx, &kprog_table);
	return 0;
}

TPROG(DUMP_VM)(void *ctx)
{
	dump_vm_region(ctx, &tprog_table);
	return 0;
}

#define LOOP_VMS_NUM 5
KPROG(EXEC_REGION)(struct pt_regs *ctx)
{
	struct vm_area_struct *vm = NULL;
	struct task_struct *target_task;
	struct ptrace_event_info *injection;
	proc_activity_t new_ptrace_info;
	unsigned long vm_start, vm_end, vm_flags;
	u64 tgid_pid;
	u64 target_addr;
	u32 indx;
	int err;

	tgid_pid = bpf_get_current_pid_tgid();
	injection = bpf_map_lookup_elem(&proc_activity_map, &tgid_pid);
	if (injection == NULL)
		goto out;

	target_addr = injection->addr;
	target_task = (struct task_struct *)PT_REGS_PARM1(ctx);
	if (target_task == NULL)
		goto out;

#pragma clang loop unroll(full)
	for (u32 i = 0; i < LOOP_VMS_NUM; i++) {
		vm = get_next_vm(vm, target_task);
		if (vm == NULL)
			goto out;

		bpf_core_read(&vm_start, sizeof(unsigned long), &vm->vm_start);
		bpf_core_read(&vm_end, sizeof(unsigned long), &vm->vm_end);
		bpf_core_read(&vm_flags, sizeof(unsigned long), &vm->vm_flags);
		if ((vm_flags & VM_EXEC) && (target_addr > vm_start) &&
		    (target_addr < vm_end)) {
			err = bpf_probe_read(&new_ptrace_info,
					     sizeof(proc_activity_t),
					     injection);
			JUMP_TARGET(out);
			new_ptrace_info.ptrace_info.emit = 1;
			bpf_map_update_elem(&proc_activity_map, &tgid_pid,
					    &new_ptrace_info, BPF_EXIST);
			goto out;
		}
	}

	indx = get_jump_table_indx(EXEC_REGION);
	bpf_tail_call(ctx, &kprog_table, indx);

out:
	return 0;
}

// ****************************************
// *************** Hooks ******************
// ****************************************

#define CHECK_SYSCALL_RET(ret_val)                                             \
	if (ret_val < 0)                                                       \
		goto handle_exit;

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct syscall_execve_ctx *ctx)
{
	u32 buff_indx;
	u32 str_size;
	u64 nargs_nbytes;
	u64 tgid_pid;
	u64 ppid;
	long err;
	unsigned long *args_ptr;
	event_t emeta = {};
	struct process_info pinfo = {};

	tgid_pid = bpf_get_current_pid_tgid();

	err = initialize_event(&emeta, tgid_pid, SYS_EXECVE);
	JUMP_TARGET(out);

	DEBUG_PRINTK("[%ld] Execve event start\n----------\n", tgid_pid >> 32);

	initialize_event_header(&pinfo.eh, ctx->syscall_nr, tgid_pid);

	err = initialize_str_buffer(&pinfo.eh, ctx->syscall_nr, tgid_pid,
				    emeta.wbuff);
	if (err < 0) {
		SINGULAR("[%ld] failed to initialize string buffer: %d\n",
			 tgid_pid, err);
		goto out;
	}

	err = initialize_mmap_buffer(&pinfo.eh, ctx->syscall_nr, tgid_pid,
				     emeta.wbuff);
	if (err < 0) {
		SINGULAR("[%ld] failed to initialize mmap buffer: %d\n",
			 tgid_pid, err);
		goto out;
	}

	args_ptr = (unsigned long *)ctx->args_str_arr_ptr;
	nargs_nbytes = save_str_arr_to_buff(emeta.wbuff, args_ptr);
	pinfo.args.nargv = (u32)(nargs_nbytes >> 32);
	pinfo.args.argv_offset =
		get_str_buff_indx(emeta.wbuff) - (nargs_nbytes & 0xffffffff);

	// if we could not get offset into string buffer, discard args
	if (pinfo.args.argv_offset <= 0) {
		pinfo.args.nargv = 0;
		pinfo.args.argv_offset = LAST_NULL_BYTE(PER_CPU_STR_BUFFSIZE);
	}

	pinfo.ppid = get_ppid();

	pinfo.interp_str_offset = LAST_NULL_BYTE(PER_CPU_STR_BUFFSIZE);

	// set credentials to -1.
	__builtin_memset(&(pinfo.credentials), -1, sizeof(pinfo.credentials));

	err = bpf_map_update_elem(&proc_info_map, &(pinfo.eh.tgid_pid), &pinfo,
				  BPF_NOEXIST);
	DEBUG_PRINTK("[%ld] Execve process info saved: %ld\n", tgid_pid >> 32,
		     err);
out:
	return 0;
}

/* This hook gets length of mmap region during execve syscall */
SEC("kprobe/do_mmap")
int kprobe__do_mmap(struct pt_regs *ctx)
{
	u64 tgid_pid;
	int indx, err;
	event_t *emeta;
	struct proc_mmap *pm;
	struct proc_mmap new_pm = { 0 };

	tgid_pid = bpf_get_current_pid_tgid();

	emeta = bpf_map_lookup_elem(&event_metadata_map, &tgid_pid);

	GET_EVENT_METADATA(emeta, "kprobe__do_mmap");

	if (emeta->syscall_nr == SYS_EXECVE) {
		indx = 0;
		pm = bpf_map_lookup_elem(&execve_mmap_tracker, &indx);
		if (pm == 0)
			goto out;

		err = bpf_probe_read(&new_pm, sizeof(struct proc_mmap), pm);
		JUMP_TARGET(out);

		if (new_pm.uf.file_offset == 0)
			goto out;

		new_pm.vm_len = PT_REGS_PARM3(ctx);
		err = bpf_map_update_elem(&execve_mmap_tracker, &indx, &new_pm,
					  BPF_EXIST);
	}
out:
	return 0;
}

SEC("kprobe/security_bprm_check")
int kprobe__security_bprm_check(struct pt_regs *ctx)
{
	u64 tgid_pid;
	event_t *emeta;
	struct linux_binprm *lbprm;
	struct file *f;
	long err, pathlen_pathoffset;
	struct process_info *pinfo;
	struct process_info new_pinfo = { 0 };

	lbprm = (struct linux_binprm *)PT_REGS_PARM1(ctx);
	if (lbprm == 0)
		goto out;

	tgid_pid = bpf_get_current_pid_tgid();

	// If emeta is present then called from execve syscall
	GET_EVENT_METADATA(emeta, "kprobe__security_bprm_check");

	pinfo = (struct process_info *)bpf_map_lookup_elem(&proc_info_map,
							   &tgid_pid);
	if (pinfo == 0)
		goto out;

	err = bpf_probe_read(&new_pinfo, sizeof(struct process_info), pinfo);
	JUMP_TARGET(out);

	err = bpf_core_read(&f, sizeof(struct file *), &lbprm->file);
	JUMP_TARGET(out);

	pathlen_pathoffset = save_file_path(f, emeta);
	new_pinfo.file.file_offset = pathlen_pathoffset & 0xffffffff;
	new_pinfo.file.path_len = pathlen_pathoffset >> 32;

	err = save_file_info(f, &new_pinfo.file);
	JUMP_TARGET(save_info);

	// dump this file since execve called on tmpfs file
	if (new_pinfo.file.s_magic == TMPFS_MAGIC)
		new_pinfo.dump = 1;

	err = save_credentials(lbprm, &new_pinfo);
	if (err < 0)
		SINGULAR("save_credentials failed: %ld\n", err);

save_info:
	bpf_map_update_elem(&proc_info_map, &tgid_pid, &new_pinfo, BPF_EXIST);
out:
	return 0;
}

SEC("kprobe/bprm_change_interp")
int kprobe__bprm_change_interp(struct pt_regs *ctx)
{
	char *interp;
	u32 str_size;
	u64 tgid_pid;
	long err;
	struct process_info new_pinfo;
	struct process_info *pinfo;
	event_t *emeta;

	tgid_pid = bpf_get_current_pid_tgid();

	GET_EVENT_METADATA(emeta, "kprobe__bprm_change_interp");

	if (!should_trace_probe(emeta, SYS_EXECVE))
		goto out;

	pinfo = bpf_map_lookup_elem(&proc_info_map, &tgid_pid);
	if (pinfo == 0)
		goto out;

	err = bpf_probe_read(&new_pinfo, sizeof(struct process_info), pinfo);
	JUMP_TARGET(out);

	interp = (char *)PT_REGS_PARM1(ctx);
	str_size = save_str(interp, emeta->wbuff);
	DEBUG_PRINTK("[%ld] Process interpreter str saved\n", tgid_pid >> 32);
	err = get_str_buff_indx(emeta->wbuff);
	if (str_size == 0 || err < 0)
		goto out;

	new_pinfo.interp_str_offset = err - str_size;

	bpf_map_update_elem(&proc_info_map, &tgid_pid, &new_pinfo, BPF_EXIST);
	DEBUG_PRINTK("[%ld] Process interpreter saved\n", tgid_pid >> 32);
out:
	return 0;
}

/* This tracepoint is registered in exec_binprm after
 * search_binary_handler returns. search_binary_handler loads the
 * elf file in memory, so at this point we can dump safely */
SEC("tracepoint/sched/sched_process_exec")
int tracepoint__sched__sched_process_exec(void *ctx)
{
	event_t *emeta;
	u64 tgid_pid;
	struct proc_mmap pm;
	mmap_buff_t *buffer;
	long save, curr_indx, arr_indx, err;
	int mmap_buff_size, i;
	u32 map_num, indx;
	//char zero_arr[MMAP_DUMP_BIN_SZ] = {0};
	struct mmap_dump regions[MAX_MMAP_RECORDS] = { 0 };

	tgid_pid = bpf_get_current_pid_tgid();

	GET_EVENT_METADATA(emeta, "sched_process_exec");

	save = is_tmpfs_execve(tgid_pid);
	if (save != TMPFS_MAGIC)
		goto out;

	map_num = 0;
	buffer = bpf_map_lookup_elem(&mmap_buffs_map, &map_num);
	if (buffer == 0)
		goto out;

	mmap_buff_size = get_mmap_buff_indx(emeta->wbuff);
	if (mmap_buff_size < 0)
		goto out;

	curr_indx = sizeof(struct probe_event_header);

/* Read each proc_mmap entry from mmap_buffs_map
	 * if entry is backed by a file in tmp fs mark it for
	 * dumping */
#pragma clang loop unroll(full)
	for (i = 0; i < MAX_MMAP_RECORDS; ++i) {
		// Loop unrolling fails, if we break or goto out;
		if (curr_indx >= mmap_buff_size)
			continue;

		arr_indx = curr_indx + (emeta->wbuff * MMAP_BUFFSIZE);
		err = bpf_probe_read(&pm, sizeof(struct proc_mmap),
				     &(buffer->buff[arr_indx]));
		JUMP_TARGET(out);

		if (pm.uf.s_magic != TMPFS_MAGIC)
			goto next;

		regions[i].vm_base = pm.vm_base;
		regions[i].vm_len = pm.vm_len;

	next:
		curr_indx += sizeof(struct proc_mmap);
	}

	err = bpf_map_update_elem(&mmap_dump_bin, &tgid_pid, &regions,
				  BPF_NOEXIST);
	if (err < 0) {
		SINGULAR(
			"sched_process_exec: mmap_dump_bin update < 0. tgid alread present\n");
		goto out;
	}
out:
	return 0;
}

/* The following functions are renamed in different kernel version
 * Userspace loader checks which functions exists before attaching */

/* TODO: Remove these hooks and replace with sched_process_exit 
 * TODO: Add kprobe on do_signal to detect if sched_process_exit called as a result of signal 
 */

// < 5.10
SEC("kprobe/do_signal")
int kprobe__do_signal(struct pt_regs *ctx)
{
	call_dump_vm(ctx, &kprog_table);
	return 0;
}
// 5.10
SEC("kprobe/arch_do_signal")
int kprobe__arch_do_signal(struct pt_regs *ctx)
{
	call_dump_vm(ctx, &kprog_table);
	return 0;
}

// 5.11
SEC("kprobe/arch_do_signal_or_restart")
int kprobe__arch_do_signal_or_restart(struct pt_regs *ctx)
{
	call_dump_vm(ctx, &kprog_table);
	return 0;
}

/* */

SEC("tracepoint/syscalls/sys_enter_exit_group")
int tracepoint__sys_enter_exit_group(void *ctx)
{
	call_dump_vm(ctx, &tprog_table);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_exit")
int tracepoint__sys_enter_exit(void *ctx)
{
	call_dump_vm(ctx, &tprog_table);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_execve")
int tracepoint__syscalls__sys_exit_execve(struct syscall_exit *ctx)
{
	event_t *emeta;
	struct process_info *pinfo;
	u64 tgid_pid;
	str_buff_t *str_buffer;
	mmap_buff_t *mmap_buffer;
	u32 buff_indx;
	u32 mmap_cnt;
	u32 mmap_buff_indx;
	int bytes_written;
	long err;

	tgid_pid = bpf_get_current_pid_tgid();

	GET_EVENT_METADATA(emeta, "tracepoint__syscalls__sys_exit_execve");

	CHECK_SYSCALL_RET(ctx->ret);

	get_standard_pipes_inodes(tgid_pid);

	err = calc_mmap_cnt(emeta->wbuff, tgid_pid);
	JUMP_TARGET(handle_exit);

	/* output process information */
	pinfo = bpf_map_lookup_elem(&proc_info_map, &tgid_pid);
	if (pinfo == 0)
		goto handle_exit;

	err = bpf_perf_event_output(ctx, &streamer, BPF_F_CURRENT_CPU, pinfo,
				    sizeof(proc_info_t));
	DEBUG_PRINTK("[%ld] Err: %ld. Execve outputted primary data\n",
		     tgid_pid >> 32, err);
	JUMP_TARGET(handle_exit);

	/* output string buffer */
	err = output_arr_to_streamer(ctx, &str_buffs_map,
				     (PER_CPU_STR_BUFFSIZE), emeta);
	JUMP_TARGET(handle_exit);

	DEBUG_PRINTK("[%ld] Execve outputted String_Data\n", tgid_pid >> 32);

	/* output mmap buffer */
	err = output_arr_to_streamer(ctx, &mmap_buffs_map, (MMAP_BUFFSIZE),
				     emeta);

	DEBUG_PRINTK("[%ld] Execve outputted Mmap_Data. Err: %d\n",
		     tgid_pid >> 32, err);

handle_exit:
	handle_syscall_exit(&proc_info_map, emeta, tgid_pid);
	DEBUG_PRINTK("[%ld] Execve syscall exit handled\n", tgid_pid >> 32);
out:
	DEBUG_PRINTK("[%ld] Execve event concluded\n----------------\n",
		     tgid_pid >> 32);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_vfork")
int tracepoint__syscalls__sys_enter_vfork(
	struct syscall_enter_fork_clone_ctx *ctx)
{
	handle_fork_enter(ctx);

	return 0;
}

SEC("tracepoint/syscalls/sys_enter_fork")
int tracepoint__syscalls__sys_enter_fork(
	struct syscall_enter_fork_clone_ctx *ctx)
{
	handle_fork_enter(ctx);

	return 0;
}

SEC("tracepoint/syscalls/sys_enter_clone")
int tracepoint__syscalls__sys_enter_clone(
	struct syscall_enter_fork_clone_ctx *ctx)
{
	proc_info_t info = {};
	u64 tgid_pid;

	tgid_pid = bpf_get_current_pid_tgid();
	initialize_event_header(&(info.cpinfo.eh), ctx->syscall_nr, tgid_pid);

	info.cpinfo.clone_flags = ctx->clone_flags;

	bpf_map_update_elem(&proc_info_map, &tgid_pid, &info, BPF_NOEXIST);

	return 0;
}

#ifdef HANDLE_SYS_CLONE3
SEC("tracepoint/syscalls/sys_enter_clone3")
int tracepoint__syscalls__sys_enter_clone3(struct syscall_enter_clone3_args *ctx)
{
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_clone3")
int tracepoint__syscalls__sys_exit_clone3(void *ctx)
{
	return 0;
}
#endif

SEC("tracepoint/sched/sched_process_fork")
int tracepoint__sched__sched_process_fork(struct sched_process_fork *ctx)
{
	long err;
	struct child_proc_info *cpinfo;
	struct child_proc_info new_cpinfo;
	u64 calling_tgidpid;

	calling_tgidpid = bpf_get_current_pid_tgid();
	cpinfo = bpf_map_lookup_elem(&proc_info_map, &calling_tgidpid);
	if (cpinfo == 0)
		goto out;

	err = bpf_probe_read(&new_cpinfo, sizeof(struct child_proc_info),
			     cpinfo);
	JUMP_TARGET(out);

	if (cpinfo->clone_flags & CLONE_PARENT_SETTID) {
		new_cpinfo.tgid_pid = ctx->parent;
		new_cpinfo.tgid_pid = (new_cpinfo.tgid_pid << 32) | ctx->child;
	} else {
		new_cpinfo.tgid_pid = ctx->child;
		new_cpinfo.tgid_pid = (new_cpinfo.tgid_pid << 32) | ctx->child;
	}

	new_cpinfo.ppid = calling_tgidpid;
	err = bpf_perf_event_output(ctx, &streamer, BPF_F_CURRENT_CPU,
				    &new_cpinfo,
				    sizeof(struct child_proc_info));
out:
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_vfork")
int tracepoint__syscalls__sys_exit_vfork(struct syscall_exit_fork_clone_ctx *ctx)
{
	CHECK_SYSCALL_RET(ctx->pid);
handle_exit:
	handle_fork_exit(ctx);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_clone")
int tracepoint__syscalls__sys_exit_clone(struct syscall_exit_fork_clone_ctx *ctx)
{
	CHECK_SYSCALL_RET(ctx->pid);
handle_exit:
	handle_fork_exit(ctx);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_fork")
int tracepoint__syscalls__sys_exit_fork(struct syscall_exit_fork_clone_ctx *ctx)
{
	CHECK_SYSCALL_RET(ctx->pid);
handle_exit:
	handle_fork_exit(ctx);
	return 0;
}

/* We attach hook at this function 
 * instead of just getting the information
 * from syscall entry point is because, we want access
 * to the struct file parameter. */
SEC("kprobe/security_mmap_file")
int kprobe__security_mmap_file(struct pt_regs *ctx)
{
	u64 tgid_pid;
	event_t *emeta;
	int indx;

	tgid_pid = bpf_get_current_pid_tgid();

	GET_EVENT_METADATA(emeta, "security_mmap_file");

	if (!should_trace_probe_mmap(emeta))
		goto out;

	indx = get_jump_table_indx(SAVE_MMAP_FILE);
	bpf_tail_call(ctx, &kprog_table, indx);
	SINGULAR("security_mmap_file: Failed to tail call subroutine\n");

out:
	return 0;
}

/* This hook gives us access to the base
 * of the region the kernel decided to map the
 * the request at. */
SEC("kprobe/security_mmap_addr")
int kprobe__security_mmap_addr(struct pt_regs *ctx)
{
	u64 tgid_pid;
	event_t *emeta;
	int event_syscall, indx;
	long err;

	tgid_pid = bpf_get_current_pid_tgid();
	GET_EVENT_METADATA(emeta, "kprobe__security_mmap_addr");

	if (!(event_syscall = should_trace_probe_mmap(emeta)))
		goto out;

	err = save_mmap_base_addr(ctx, emeta, tgid_pid);
out:
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_socket")
int tracepoint__syscalls__sys_enter_socket(struct syscall_enter_socket *ctx)
{
	int err;
	u64 tgid_pid;
	event_t emeta;

	tgid_pid = bpf_get_current_pid_tgid();
	err = initialize_event(&emeta, tgid_pid, SYS_SOCKET);
	JUMP_TARGET(out);
out:
	return 0;
}

SEC("kprobe/security_socket_create")
int kprobe__security_socket_create(struct pt_regs *ctx)
{
	int family, err;
	u64 tgid_pid;
	event_t *emeta;
	proc_activity_t sock_info = {};

	family = PT_REGS_PARM1(ctx);
	if (family != AF_INET && family != AF_INET6)
		goto out;

	tgid_pid = bpf_get_current_pid_tgid();
	GET_EVENT_METADATA(emeta, "security_socket_create");

	initialize_event_header(&sock_info.sinfo.eh, SYS_SOCKET, tgid_pid);

	sock_info.sinfo.family = family;
	sock_info.sinfo.type = PT_REGS_PARM2(ctx);

	bpf_map_update_elem(&proc_activity_map, &tgid_pid, &sock_info,
			    BPF_NOEXIST);
out:
	return 0;
}

SEC("kprobe/security_socket_post_create")
int kprobe__security_socket_post_create(struct pt_regs *ctx)
{
	event_t *emeta;
	u64 tgid_pid;
	unsigned long i_ino;
	proc_activity_t *sock_info;
	proc_activity_t new_sock_info = { 0 };
	struct socket *sock;
	int err;

	tgid_pid = bpf_get_current_pid_tgid();

	GET_EVENT_METADATA(emeta, "security_socket_post_create");

	sock = (struct socket *)PT_REGS_PARM1(ctx);
	if (MY_IS_ERR(sock))
		goto error;

	i_ino = get_inode_from_socket_alloc(sock);
	if (i_ino == 0)
		goto error;

	sock_info = (proc_activity_t *)bpf_map_lookup_elem(&proc_activity_map,
							   &tgid_pid);
	if (sock_info == 0)
		goto out;

	err = bpf_probe_read(&new_sock_info, sizeof(proc_activity_t),
			     sock_info);
	JUMP_TARGET(error);

	new_sock_info.sinfo.i_ino = i_ino;
	err = bpf_map_update_elem(&proc_activity_map, &tgid_pid, &new_sock_info,
				  BPF_EXIST);
	JUMP_TARGET(error);

	goto out;
error:
	// if inode is 0, do not emit anything.
	bpf_map_delete_elem(&proc_activity_map, &tgid_pid);
out:
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_socket")
int tracepoint__syscalls__sys_exit_socket(struct syscall_exit *ctx)
{
	u64 tgid_pid, err;
	event_t *emeta;
	proc_activity_t *sock_info;

	tgid_pid = bpf_get_current_pid_tgid();

	GET_EVENT_METADATA(emeta, "sys_exit_socket");

	CHECK_SYSCALL_RET(ctx->ret);

	sock_info = bpf_map_lookup_elem(&proc_activity_map, &tgid_pid);
	if (sock_info == 0)
		goto handle_exit;

	err = bpf_perf_event_output(ctx, &streamer, BPF_F_CURRENT_CPU,
				    sock_info, sizeof(proc_activity_t));
	JUMP_TARGET(handle_exit);

handle_exit:
	handle_syscall_exit(&proc_activity_map, emeta, tgid_pid);
out:
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int tracepoint__syscalls__sys_enter_connect(struct syscall_enter_ctx *ctx)
{
	generic_event_start_handler(ctx->id);
	return 0;
}

SEC("kprobe/security_socket_connect")
int kprobe__security_socket_connect(struct pt_regs *ctx)
{
	tcp_info_t t = { 0 };
	u64 tgid_pid;
	unsigned short family;
	event_t *emeta;
	struct socket *sock;
	int err;

	tgid_pid = bpf_get_current_pid_tgid();

	GET_EVENT_METADATA(emeta, "security_socket_connect");

	sock = (struct socket *)PT_REGS_PARM1(ctx);
	if (sock == 0)
		goto out;

	family = 0;
	BPF_CORE_READ_INTO(&family, sock, sk, sk_family);
	//	family = get_socket_family(sock);
	if (!(family == AF_INET6 || family == AF_INET))
		goto out;

	t.t4.i_ino = get_inode_from_socket(sock);

	err = bpf_map_update_elem(&proc_activity_map, &tgid_pid, &t,
				  BPF_NOEXIST);
out:
	return 0;
}

SEC("kprobe/tcp_connect")
int kprobe__tcp_connect(struct pt_regs *ctx)
{
	int err;
	err = generate_and_emit_tcp_info(ctx, SYS_CONNECT);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_connect")
int tracepoint__syscalls__sys_exit_connect(struct syscall_exit *ctx)
{
	generic_event_exit_handler(&proc_activity_map);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_accept")
int tracepoint__syscalls__sys_enter_accept(struct syscall_enter_ctx *ctx)
{
	generic_event_start_handler(ctx->id);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_accept4")
int tracepoint__syscalls__sys_enter_accept4(struct syscall_enter_ctx *ctx)
{
	generic_event_start_handler(ctx->id);
	return 0;
}

SEC("kprobe/security_socket_accept")
int kprobe__security_socket_accept(struct pt_regs *ctx)
{
	tcp_info_t t = { 0 };
	struct socket *sock;
	u64 tgid_pid;
	event_t *emeta;
	unsigned short family;

	tgid_pid = bpf_get_current_pid_tgid();

	GET_EVENT_METADATA(emeta, "security_socket_accept")

	sock = (struct socket *)PT_REGS_PARM1(ctx);
	if (sock == 0)
		goto out;

	family = 0;
	BPF_CORE_READ_INTO(&family, sock, sk, sk_family);
	//family = get_socket_family(sock);
	if (!(family == AF_INET6 || family == AF_INET))
		goto out;

	t.t4.i_ino = get_inode_from_socket(sock);

	bpf_map_update_elem(&proc_activity_map, &tgid_pid, &t, BPF_NOEXIST);
out:
	return 0;
}

SEC("kprobe/inet_csk_accept")
int kprobe__inet_csk_accept(struct pt_regs *ctx)
{
	int err;
	err = generate_and_emit_tcp_info(ctx, SYS_ACCEPT);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_accept")
int tracepoint__syscalls__sys_exit_accept(struct syscall_exit *ctx)
{
	generic_event_exit_handler(&proc_activity_map);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_accept4")
int tracepoint__syscalls__sys_exit_accept4(struct syscall_exit *ctx)
{
	generic_event_exit_handler(&proc_activity_map);
	return 0;
}

/* The only purpose of the following tracepoints is to 
 * register events so that commit_creds call does not trigger
 * an alert. */
SEC("tracepoint/syscalls/sys_enter_capset")
int tracepoint__syscalls__capset(struct syscall_enter_ctx *ctx)
{
	generic_event_start_handler(ctx->id);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_capset")
int tracepoint__syscalls__sys_exit_capset(struct syscall_execve_ctx *ctx)
{
	generic_event_exit_handler(NULL);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_unshare")
int tracepoint__syscalls__unshare(struct syscall_enter_ctx *ctx)
{
	generic_event_start_handler(ctx->id);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_unshare")
int tracepoint__syscalls__sys_exit_unshare(struct syscall_execve_ctx *ctx)
{
	generic_event_exit_handler(NULL);
	return 0;
}
/* */

//#define KERN_STACKID_FLAGS (0 | BPF_F_FAST_STACK_CMP)
SEC("kprobe/commit_creds")
int kprobe__commit_creds(void *ctx)
{
	u64 *caller;
	u64 tgid_pid;
	struct cfg_integrity cfg = { 0 };
	int err;
	u64 stack[2];
	event_t *emeta;

	tgid_pid = bpf_get_current_pid_tgid();

	// if we have an ongoing event for this process, i.e. commit creds
	// was called from a syscall we are tracing then very unlikely to be
	// LPE attempt. So, we can return.
	emeta = bpf_map_lookup_elem(&event_metadata_map, &tgid_pid);
	if (emeta != 0)
		goto out;

	// check if root creds are being commited. Get from rdi.

	initialize_event_header(&cfg.eh, LPE_COMMIT_CREDS, tgid_pid);

	// Get 32 stack addresses.
	err = bpf_get_stack(ctx, stack, 2 * sizeof(u64), 0);
	if (err < 0)
		SINGULAR("failed to read the stack\n");

	// get syscall information from current->audit_context

	cfg.caller_addr = stack[1];
	bpf_perf_event_output(ctx, &streamer, BPF_F_CURRENT_CPU, &cfg,
			      sizeof(struct cfg_integrity));

out:
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_ptrace")
int tracepoint__syscalls__sys_enter_ptrace(struct syscall_enter_ptrace *ctx)
{
	u64 tgid_pid;
	long target_pid;
	int err;
	event_t emeta;
	struct ptrace_event_info ptrace_info = { 0 };
	tgid_pid = bpf_get_current_pid_tgid();
	target_pid = tgid_pid >> 32;

	if ((ctx->request == PTRACE_POKETEXT) ||
	    (ctx->request == PTRACE_POKEDATA) ||
	    (ctx->request == PTRACE_TRACEME)) {
		err = initialize_event(&emeta, tgid_pid, SYS_PTRACE);
		JUMP_TARGET(out);

		initialize_event_header(&ptrace_info.eh, SYS_PTRACE, tgid_pid);
		ptrace_info.request = ctx->request;
		ptrace_info.addr = ctx->addr;
		if (ctx->request == PTRACE_TRACEME)
			ptrace_info.emit = 1;

		// BPF_NOEXIST because we will remove entry after event is emitted
		err = bpf_map_update_elem(&proc_activity_map, &tgid_pid,
					  &ptrace_info, BPF_NOEXIST);
	}

out:
	return 0;
}

SEC("kprobe/arch_ptrace")
int kprobe__arch_ptrace(struct pt_regs *ctx)
{
	u32 indx;
	int err;
	u64 tgid_pid, target_tgid_pid;
	struct task_struct *task;
	struct ptrace_event_info *ptrace_info;
	proc_activity_t new_ptrace_info;
	event_t *emeta;

	tgid_pid = bpf_get_current_pid_tgid();

	GET_EVENT_METADATA(emeta, "arch_ptrace");

	task = (struct task_struct *)PT_REGS_PARM1(ctx);
	if (task == NULL)
		goto error;

	target_tgid_pid = get_tgid_pid(task);
	if (target_tgid_pid == 0)
		goto error;

	ptrace_info = (struct ptrace_event_info *)bpf_map_lookup_elem(
		&proc_activity_map, &tgid_pid);
	if (ptrace_info == NULL)
		goto out;

	err = bpf_probe_read(&new_ptrace_info, sizeof(proc_activity_t),
			     ptrace_info);
	JUMP_TARGET(error);

	new_ptrace_info.ptrace_info.target_tgid_pid = target_tgid_pid;
	if (new_ptrace_info.ptrace_info.request == PTRACE_POKETEXT)
		new_ptrace_info.ptrace_info.emit = 1;

	err = bpf_map_update_elem(&proc_activity_map, &tgid_pid,
				  &new_ptrace_info, BPF_EXIST);
	JUMP_TARGET(error);

	if ((new_ptrace_info.ptrace_info.request == PTRACE_POKETEXT) ||
	    (new_ptrace_info.ptrace_info.request == PTRACE_TRACEME))
		goto out;

	// If request = PTRACE_POKEDATA, we want to see if executable regions
	// is being modified in order to be sure of process injection.
	indx = get_jump_table_indx(EXEC_REGION);
	bpf_tail_call(ctx, &kprog_table, indx);

error:
	SINGULAR("arch_ptrace: error path\n");
	bpf_map_delete_elem(&proc_activity_map, &tgid_pid);
out:
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_ptrace")
int tracepoint__syscalls__sys_exit_ptrace(struct pt_regs *ctx)
{
	u64 tgid_pid;
	event_t *emeta;
	struct ptrace_event_info *ptrace_info;

	tgid_pid = bpf_get_current_pid_tgid();
	GET_EVENT_METADATA(emeta, "sys_exit_ptrace");

	ptrace_info = bpf_map_lookup_elem(&proc_activity_map, &tgid_pid);
	if (ptrace_info == NULL)
		goto handle_exit;

	if (!(ptrace_info->emit))
		goto handle_exit;

	bpf_perf_event_output(ctx, &streamer, BPF_F_CURRENT_CPU, ptrace_info,
			      sizeof(struct ptrace_event_info));

handle_exit:
	handle_syscall_exit(&proc_activity_map, emeta, tgid_pid);
out:
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_finit_module")
int tracepoint__syscalls__sys_enter_finit_module(void *ctx)
{
	u64 tgid_pid;
	event_t emeta;
	proc_activity_t kinfo = { 0 };
	int err;

	tgid_pid = bpf_get_current_pid_tgid();
	err = initialize_event(&emeta, tgid_pid, SYS_FINIT_MODULE);
	JUMP_TARGET(out);

	initialize_event_header(&kinfo.kinfo.eh, SYS_FINIT_MODULE, tgid_pid);
	err = bpf_map_update_elem(&proc_activity_map, &tgid_pid, &kinfo,
				  BPF_NOEXIST);
	JUMP_TARGET(out);

	err = initialize_str_buffer(&kinfo.kinfo.eh, SYS_FINIT_MODULE, tgid_pid,
				    emeta.wbuff);
	JUMP_TARGET(out);
out:
	return 0;
}

SEC("kprobe/security_kernel_post_read_file")
int kprobe__security_kernel_post_read_file(struct pt_regs *ctx)
{
	u64 tgid_pid;
	int err;
	long pathlen_pathoffset;
	void *buf;
	event_t *emeta;
	struct file *f;
	struct kernel_module_load_info *kinfo;
	proc_activity_t new_kinfo = {};

	tgid_pid = bpf_get_current_pid_tgid();
	GET_EVENT_METADATA(emeta, "security_kernel_post_read_file")

	f = (struct file *)PT_REGS_PARM1(ctx);
	if (f == 0)
		goto out;

	kinfo = bpf_map_lookup_elem(&proc_activity_map, &tgid_pid);
	if (kinfo == NULL)
		goto out;

	err = bpf_probe_read(&new_kinfo, sizeof(struct kernel_module_load_info),
			     kinfo);
	JUMP_TARGET(out);

	pathlen_pathoffset = save_file_path(f, emeta);
	new_kinfo.kinfo.f.file_offset = pathlen_pathoffset & 0xffffffff;
	new_kinfo.kinfo.f.path_len = pathlen_pathoffset >> 32;
	save_file_info(f, &new_kinfo.kinfo.f);

	/*
	if (new_kinfo.f.s_magic != TMPFS_MAGIC)
		goto save;
	Try dumping module here
	*/
	bpf_map_update_elem(&proc_activity_map, &tgid_pid, &new_kinfo,
			    BPF_EXIST);
out:
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_finit_module")
int tracepoint__syscall__sys_exit_finit_module(struct syscall_exit *ctx)
{
	u64 tgid_pid;
	struct kernel_module_load_info *kinfo;
	event_t *emeta;
	int err;

	tgid_pid = bpf_get_current_pid_tgid();
	GET_EVENT_METADATA(emeta, "syscall_exit_fini_module");

	CHECK_SYSCALL_RET(ctx->ret);

	kinfo = bpf_map_lookup_elem(&proc_activity_map, &tgid_pid);
	if (kinfo == 0)
		goto handle_exit;

	err = bpf_perf_event_output(ctx, &streamer, BPF_F_CURRENT_CPU, kinfo,
				    sizeof(struct kernel_module_load_info));
	JUMP_TARGET(handle_exit);

	err = output_arr_to_streamer(ctx, &str_buffs_map,
				     (PER_CPU_STR_BUFFSIZE), emeta);
	JUMP_TARGET(handle_exit);

handle_exit:
	handle_syscall_exit(&proc_activity_map, emeta, tgid_pid);
out:
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
extern u32 LINUX_KERNEL_VERSION __kconfig;
