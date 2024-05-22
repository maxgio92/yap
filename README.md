# Yet Another Profiler

> This project is in **development** phase.

This is yet another low-overhead kernel-assisted sampling-based CPU time continuous profile. It does not need instrumentation in the profiled binary.

A simple sampling eBPF program attached to a timer collects:
- stack traces
- sampled stack trace counts

The data collected from the kernel is analysed in user-space to summarise residency fraction.
That is, for a stack trace, the percentage of samples that contained that path out of the total amount of samples.

This information extracted from the collected data expresses, for a specific process, which functions are mostly executing.

## How it works

The sampling eBPF probe is attached to a perf [CPU clock software event](https://elixir.bootlin.com/linux/v6.8.5/source/include/uapi/linux/perf_event.h#L119).

The user and kernel stack traces that are running on the current CPU are available to the eBPF program that will run in the context of the interrupted process via the [`bpf_get_stackid`](https://elixir.bootlin.com/linux/v6.8.5/source/kernel/bpf/stackmap.c#L283) eBPF helper.
The user or kernel stack will be available depending on the context during which the process was interrupted.

The hard work of stack walking is made easy by the Linux kernel thanks to the fact that frame instruction pointers of the sampled stack traces are available in kernel space via the [`BPF_MAP_TYPE_STACK_TRACE`](https://elixir.bootlin.com/linux/v6.8.5/source/include/uapi/linux/bpf.h#L914) eBPF map.

The information about how much a specific stack has been sampled is tracked with counters stored in an histogram eBPF map, which is keyed by:
- User stack ID
- Kernel stack ID
- PID to filter later on

and made available to userspace, alongside the stack traces.

In userspace symbolization is made with frame instruction pointer addresses read from the map.

Finally the information is extracted as percentage of profile time a stack trace has been executing.

## Quickstart

```shell
$ sudo profiler --pid 591488
{"level":"debug","message":"loading ebpf object"}
{"level":"debug","message":"getting the loaded ebpf program"}
{"level":"debug","message":"opening the sampling software cpu block perf event"}
{"level":"debug","message":"attaching the ebpf program to the sampling perf event for cpu #0"}
{"level":"debug","message":"opening the sampling software cpu block perf event"}
{"level":"debug","message":"attaching the ebpf program to the sampling perf event for cpu #1"}
{"level":"debug","message":"opening the sampling software cpu block perf event"}
{"level":"debug","message":"attaching the ebpf program to the sampling perf event for cpu #2"}
{"level":"debug","message":"opening the sampling software cpu block perf event"}
{"level":"debug","message":"attaching the ebpf program to the sampling perf event for cpu #3"}
{"level":"debug","message":"opening the sampling software cpu block perf event"}
{"level":"debug","message":"attaching the ebpf program to the sampling perf event for cpu #4"}
{"level":"debug","message":"opening the sampling software cpu block perf event"}
{"level":"debug","message":"attaching the ebpf program to the sampling perf event for cpu #5"}
{"level":"debug","message":"opening the sampling software cpu block perf event"}
{"level":"debug","message":"attaching the ebpf program to the sampling perf event for cpu #6"}
{"level":"debug","message":"opening the sampling software cpu block perf event"}
{"level":"debug","message":"attaching the ebpf program to the sampling perf event for cpu #7"}
{"level":"info","message":"collecting data"}

^C{"level":"info","message":"terminating..."}
{"level":"info","message":"received signal, analysing data"}
{"level":"debug","message":"getting the stack traces ebpf map"}
{"level":"debug","message":"getting the stack trace counts (histogram) ebpf maps"}
{"level":"debug","message":"iterating over the retrieved histogram items"}

70% main(); compute(); matrix_multiply()
10% main(); read_data(); read_file()
 5% main(); compute(); matrix_multiply(); prepare()
```

## Build

### Build all

```shell
make profiler
```

### eBPF probe only

```shell
make profiler/bpf
```

## Thanks

- Pixie:
  - [pixie-demos/ebpf-profiler](https://github.com/pixie-io/pixie-demos/tree/main/ebpf-profiler)
  - [Building a continuous profiler](https://blog.px.dev/cpu-profiling/)
- Linux:
  - [samples/bpf/trace_event_user.c](https://github.com/torvalds/linux/blob/8f2c057754b25075aa3da132cd4fd4478cdab854/samples/bpf/trace_event_user.c)
  - [samples/bpf/trace_event_kern.c](https://github.com/torvalds/linux/blob/8f2c057754b25075aa3da132cd4fd4478cdab854/samples/bpf/trace_event_kern.c)
- Brendan Gregg:
  - [Linux eBPF Stack Trace Hack](https://www.brendangregg.com/blog/2016-01-18/ebpf-stack-trace-hack.html)