#define K_NUM_MAP_ENTRIES	65536
#define PERF_MAX_STACK_DEPTH	127

struct stack_trace_key_t {
	u32 pid;
	u32 kernel_stack_id;
	u32 user_stack_id;
};
