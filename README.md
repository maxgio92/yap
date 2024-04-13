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
...
```

## Build

### Build all

```shell
make profiler
```

Build eBPF probe only:

```shell
make profiler/bpf
```
