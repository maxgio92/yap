/*
 * Copyright 2018- The Pixie Authors.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/bpf_perf_event.h>
#include <linux/ptrace.h>

#include "perf_profiler_types.h"

const int kNumMapEntries = 65536;

// bcc way
BPF_STACK_TRACE(stack_traces, kNumMapEntries);

/*
 * libbpf way
 *
struct {
  __uint(type, BPF_MAP_TYPE_STACK_TRACE);
  __uint(max_entries, kNumMapEntries);
   __uint(value_size, PERF_MAX_STACK_DEPTH * sizeof(u64));
  __type(key, u32);
} stack_traces SEC(".maps");
*/

// bcc way
BPF_HASH(histogram, struct stack_trace_key_t, uint64_t, kNumMapEntries);

/*
 * libbpf way
 *
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, kNumMapEntries);
  __type(key, struct stack_trace_key_t);
  __type(value, u64);
} histogram SEC(".maps");
*/

int sample_stack_trace(struct bpf_perf_event_data* ctx) {
  // Sample the user stack trace, and record in the stack_traces structure.
  u64 user_stack_id = stack_traces.get_stackid(&ctx->regs, BPF_F_USER_STACK);

  // Sample the kernel stack trace, and record in the stack_traces structure.
  u64 kernel_stack_id = stack_traces.get_stackid(&ctx->regs, 0);

  // Update the counters for this user+kernel stack trace pair.
  struct stack_trace_key_t key = {};
  u64 pid = bpf_get_current_pid_tgid() >> 32;
  key.pid = pid;
  key.user_stack_id = user_stack_id;
  key.kernel_stack_id = kernel_stack_id;

  /*
   * BCC way
   *
  u64 zero = 0;
  histogram.lookup_or_try_init(&key, &zero);
  */
  histogram.atomic_increment(key);

  /*
   * libbpf way
   *
  u64* count = bpf_map_lookup_elem(&histogram, &key);
  if(count){
     u64 c = *count;
     c++;
     bpf_map_update_elem(&histogram, &key, &c, BPF_EXIST);
  }else{
     u64 one = 1;
     bpf_map_update_elem(&histogram, &key, &one, BPF_NOEXIST);
  }
  */

  /*
   * DEBUG
   *
  bpf_trace_printk("Stack trace id: tgid %d\n", sizeof("Stack trace id: tgid %d\n"), key.pid);
  bpf_trace_printk("Stack trace id: user stack id %d - kernel stack id %d \n", sizeof("Stack trace id: user stack id %d - kernel stack id %d \n"), key.user_stack_id);
  bpf_trace_printk("Key: Current tgid %d;", (u64)pid);
  bpf_trace_printk("Key: User stack id is %d;", (u64)user_stack_id);
  bpf_trace_printk("Key: Kernel stack id is %d;", (u64)kernel_stack_id);
  */

  u64 *count = histogram.lookup(&key);

  /*
   * DEBUG
   *
  if (count) {
    bpf_trace_printk("Stack trace count is %llu\n", (u64*)*count);
  }
  */

  return 0;
}
