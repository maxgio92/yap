#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "profile.bpf.h"

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(key_size, sizeof(u32));
	__uint(value_size, PERF_MAX_STACK_DEPTH * sizeof(u64));
	__uint(max_entries, K_NUM_MAP_ENTRIES);
} stack_traces SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct stack_trace_key_t);
	__type(value, u64);
	__uint(max_entries, K_NUM_MAP_ENTRIES);
} histogram SEC(".maps");

SEC("perf_event")
int sample_stack_trace(struct bpf_perf_event_data* ctx)
{
	char time_fmt1[] = "Time Enabled: %llu, Time Running: %llu";
	char time_fmt2[] = "Get Time Failed, ErrCode: %d";
	char addr_fmt[] = "Address recorded on event: %llx";
	char fmt[] = "Stack trace id: tgid %d ip %llx count %llu\n";

	struct stack_trace_key_t key;
	struct bpf_perf_event_value value_buf;
	u64 *count, one = 1;
	int ret;

	key.pid = bpf_get_current_pid_tgid() >> 32;

	/* Sample the user and kernel stack traces, and record in the stack_traces structure. */
	key.user_stack_id = bpf_get_stackid(ctx, &stack_traces, 0 | BPF_F_USER_STACK);
	key.kernel_stack_id = bpf_get_stackid(ctx, &stack_traces, 0);
	if ((int)key.user_stack_id < 0 && (int)key.kernel_stack_id < 0) {
		bpf_trace_printk(fmt, sizeof(fmt), key.pid, PT_REGS_IP(&ctx->regs));
	}

	/* Debug */
	ret = bpf_perf_prog_read_value(ctx, (void *)&value_buf, sizeof(struct bpf_perf_event_value));
	if (!ret)
		bpf_trace_printk(time_fmt1, sizeof(time_fmt1), value_buf.enabled, value_buf.running);
	else
		bpf_trace_printk(time_fmt2, sizeof(time_fmt2), ret);

	if (ctx->addr != 0)
		bpf_trace_printk(addr_fmt, sizeof(addr_fmt), ctx->addr);

	count = bpf_map_lookup_elem(&histogram, &key);
	if(count) {
		(*count)++;
		bpf_trace_printk(fmt, sizeof(fmt), key.pid, PT_REGS_IP(&ctx->regs), (u64*)*count);
	} else {
		bpf_map_update_elem(&histogram, &key, &one, BPF_NOEXIST);
		bpf_trace_printk(fmt, sizeof(fmt), key.pid, PT_REGS_IP(&ctx->regs), (u64*)*count);
	}

	return 0;
}

char _license[] SEC("license") = "GPL";
