#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "profile.bpf.h"
#include <string.h>

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(key_size, sizeof(u32));
	__uint(value_size, PERF_MAX_STACK_DEPTH * sizeof(u64));
	__uint(max_entries, K_NUM_MAP_ENTRIES);
} stack_traces SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct stack_trace_key_t);
	__type(value, struct histogram_value_t);
	__uint(max_entries, K_NUM_MAP_ENTRIES);
} histogram SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct buffer);
	__uint(max_entries, 1);
} heaps_map SEC(".maps");

/*
 * get_pathname_from_path lookups pathname from path struct
 * Thanks to tracee: https://github.com/aquasecurity/tracee/blob/a6118678c6908c74d6ee26ca9183e99932d098c9/pkg/ebpf/c/common/filesystem.h#L160
*/
static __always_inline long get_pathname_from_path(u_char **path_str, struct path *path, struct buffer *out_buf)
{
	long ret;
	struct dentry *dentry, *dentry_parent, *dentry_mnt_root;
	struct vfsmount *vfsmnt;
	struct mount *mnt, *mnt_parent;
	const u_char *name;
	size_t name_len;

	dentry = BPF_CORE_READ(path, dentry); /* Directory entry of the specified path */
	vfsmnt = BPF_CORE_READ(path, mnt); /* VFS mount of the specified path */
	mnt = container_of(vfsmnt, struct mount, mnt); /* Mount struct of the VFS mount */
	mnt_parent = BPF_CORE_READ(mnt, mnt_parent); /* Parent mount of the VFS mount, if not global root */

	size_t buf_off = HALF_PERCPU_ARRAY_SIZE;

#pragma unroll
	for (int i = 0; i < MAX_PATH_COMPONENTS; i++) {

		dentry_mnt_root = BPF_CORE_READ(vfsmnt, mnt_root); /* Root of the mounted tree */
		dentry_parent = BPF_CORE_READ(dentry, d_parent); /* Parent dentry */

		/* We reached root */
		if (dentry == dentry_mnt_root || dentry == dentry_parent) {
			if (dentry != dentry_mnt_root) {
				/* Not mount root */
				break;
			}
			if (mnt != mnt_parent) {
				/* Not global root - continue with mount point path */
				dentry = BPF_CORE_READ(mnt, mnt_mountpoint);
				mnt_parent = BPF_CORE_READ(mnt, mnt_parent);
				vfsmnt = __builtin_preserve_access_index(&mnt->mnt);
				continue;
			}
			/* Global root - path fully parsed */
			break;
		}

		/* Add this dentry name to path */
		name_len = LIMIT_PATH_SIZE(BPF_CORE_READ(dentry, d_name.len));
		name = BPF_CORE_READ(dentry, d_name.name); /* directory name as quick string (qstr) */
		name_len = name_len + 1; /* Add slash */
		/* Is string buffer big enough for dentry name? */
		if (name_len > buf_off) {
			break;
		}
		/* Copy the directory name to the output buffer */
		volatile size_t new_buf_offset = buf_off - name_len; /* satisfy verifier */
		ret = bpf_probe_read_kernel_str(
			&(out_buf->data[LIMIT_HALF_PERCPU_ARRAY_SIZE(new_buf_offset)]), /* satisfy verifier */
			name_len, name);
		if (ret < 0) {
		      return ret;
		}
		if (ret > 1) {
			buf_off -= 1; /* Remove null byte termination with slash sign */
			buf_off = LIMIT_HALF_PERCPU_ARRAY_SIZE(buf_off); /* satisfy verifier */
			out_buf->data[buf_off] = '/';
			buf_off -= ret - 1;
			buf_off = LIMIT_HALF_PERCPU_ARRAY_SIZE(buf_off); /* satisfy verifier */
		} else {
			/* If copied size is 0 or 1 we have an error (path can't be null nor an empty string) */
			break;
		}

		/* Go one level up */
		dentry = dentry_parent;
	}

	/* Is string buffer big enough for slash? */
	if (buf_off != 0) {
		/* Add leading slash */
		buf_off -= 1;
		buf_off = LIMIT_HALF_PERCPU_ARRAY_SIZE(buf_off); /* satisfy verifier */
		out_buf->data[buf_off] = '/';
	}

	/* Null terminate the path string */
	out_buf->data[HALF_PERCPU_ARRAY_SIZE - 1] = 0;
	*path_str = &out_buf->data[buf_off];
	return HALF_PERCPU_ARRAY_SIZE - buf_off - 1;
}

/*
 * get_task_exe_pathname returns the task exe_file pathname.
 * This does not apply to kernel threads as they share the same memory-mapped address space,
 * as opposed to user address space.
 */
static __always_inline u_char* get_task_exe_pathname(struct task_struct *task)
{
	u_char *file_path = NULL;
	/* Get ref file from the task's user space memory mapping descriptor */
	struct file *file = BPF_CORE_READ(task, mm, exe_file);
	/*
	 * Instruct compiler to generate CO-RE relocation records for any accesses
	 * to aggregate data structures in file's path
	 */
	struct path *path = __builtin_preserve_access_index(&file->f_path); /* File's path */

	/* Get buffer from per-CPU array map */
	u32 zero = 0;
	struct buffer *string_buf = (struct buffer *)bpf_map_lookup_elem(&heaps_map, &zero);
	if (string_buf == NULL) {
		return NULL;
	}
	/* Write path string from path struct to the buffer */
	get_pathname_from_path(&file_path, path, string_buf);
	return file_path;
}

SEC("perf_event")
int sample_stack_trace(struct bpf_perf_event_data* ctx)
{
	char exe_path_dbg_fmt[] = "pid=%d comm=%s exe_path=%s\n";
	struct stack_trace_key_t key;
	struct histogram_value_t *value;
	struct bpf_perf_event_value value_buf;
	u64 one = 1;
	char comm[TASK_COMM_LEN];
	int ret;

	struct task_struct *task = (struct task_struct *)bpf_get_current_task(); /* Current task struct */
	u_char *exe_path = get_task_exe_pathname(task);
	if (exe_path == NULL) {
		return 0;
	}

	key.pid = bpf_get_current_pid_tgid() >> 32;

	/* Sample the user and kernel stack traces, and record in the stack_traces structure. */
	key.kernel_stack_id = bpf_get_stackid(ctx, &stack_traces, 0 | BPF_F_FAST_STACK_CMP);
	key.user_stack_id = bpf_get_stackid(ctx, &stack_traces, 0 | BPF_F_FAST_STACK_CMP | BPF_F_USER_STACK);
	if ((int)key.kernel_stack_id < 0 && (int)key.user_stack_id < 0) {
		return 0;
	}

	bpf_get_current_comm(&comm, sizeof(comm));

	/* Check binary file path excluding kernel threads */
	if ((int)key.user_stack_id > 0 && strcmp((const char*)exe_path, "") == 0) {
		bpf_trace_printk(exe_path_dbg_fmt, sizeof(exe_path_dbg_fmt), key.pid, comm, exe_path);
	}

	value = (struct histogram_value_t*)bpf_map_lookup_elem(&histogram, &key);
	if (value) {
		(*value).count++;
		(*value).exe_path = exe_path;
	} else {
		struct histogram_value_t value = { .count = one, .exe_path = exe_path};
		bpf_map_update_elem(&histogram, &key, &value, BPF_NOEXIST);
		bpf_trace_printk(exe_path_dbg_fmt, sizeof(exe_path_dbg_fmt), key.pid, comm, exe_path);
	}

	return 0;
}

char _license[] SEC("license") = "GPL";

