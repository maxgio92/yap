package main

import "C"
import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"github.com/iovisor/gobpf/bcc"
	"github.com/iovisor/gobpf/pkg/ksym"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
	libc "modernc.org/libc/sys/types"
	"os"
	"time"

	. "github.com/maxgio92/perf-profiler-go/internal/utils"
)

type Options struct {
	pid      int
	duration int
}

type HistogramKey struct {
	Pid libc.Pid_t

	// UserStackId, an index into the stack-traces map.
	UserStackId libc.U_int32_t

	// KernelStackId, an index into the stack-traces map.
	KernelStackId libc.U_int32_t
}

// StackTrace is an array of instruction pointers (IP).
// 127 is the size of the trace, as for the default PERF_MAX_STACK_DEPTH.
type StackTrace [127]libc.Ulong

const (
	probeFile = "kernel/perf_profiler.bpf.c"
	probeName = "sample_stack_trace"

	stackTracesMapName = "stack_traces"
	histogramMapName   = "histogram"

	samplingPeriodMillis = 11

	userSymUnknown   = "[USER_UNKNOWN]"
	kernelSymUnknown = "[KERN_UNKNOWN]"
)

func main() {
	o := new(Options)

	flag.IntVar(&o.pid, "pid", 0, "The PID of the process")
	flag.IntVar(&o.duration, "duration", 0, "The duration in seconds for the profiling")

	flag.Parse()

	if o.pid == 0 || o.duration == 0 {
		Fail("error validating arguments")
	}

	source, err := os.ReadFile(probeFile)
	CheckErr(err)

	// Compile the code and generates a new BPF bpfModule.
	bpfModule := bcc.NewModule(string(source), []string{"-fcf-protection"})
	if bpfModule == nil {
		return
	}
	defer bpfModule.Close()

	// LoadPerfEvent loads a program of type BPF_PROG_TYPE_PERF_EVENT.
	// The program will run on software perf event, which in this case will be
	// a sampling CPU clock perf event, in order to allow the program to run
	// on a specific cron schedule.
	// When a specified number of clock samples occur, the kernel will trigger the program.
	fd, err := bpfModule.LoadPerfEvent(probeName)
	CheckErr(errors.Wrap(err, "error loading the sampling probe"))

	//cpus, err := numcpus.GetOnline()
	//CheckErr(errors.Wrap(err, "error getting online cpus"))

	//for i := 0; i < cpus; i++ {
	// go-bpf lib's AttachPerfEvent leverages libbpf bpf_attach_perf_event that calls
	// perf_event_open syscall (sys_perf_event_open).
	CheckErr(bpfModule.AttachPerfEvent(

		// If type is PERF_TYPE_SOFTWARE, we are measuring software events provided by the kernel.
		unix.PERF_TYPE_SOFTWARE,

		// This reports the CPU clock, a high-resolution per-CPU timer.
		unix.PERF_COUNT_SW_CPU_CLOCK,

		// sample_period and sample_freq are mutually exclusive.
		//
		// A "sampling" event is one that generates an overflow notification every N events,
		// where N is given by sample_period.
		samplingPeriodMillis*1000*1000,

		// sample_freq can be used if you wish to use frequency rather than period.
		// The kernel will adjust the sampling period to try and achieve the desired rate.
		0,

		// The pid as argument.
		-1,

		// CPU.
		-1,
		//i,

		// The group_fd argument allows event groups to be created. An event group has one event which
		// is the group leader. A single event on its own is created with group_fd = -1 and is considered
		// to be a group with only 1 member.
		-1,

		// The program file descriptor.
		fd,
	))
	//}

	stackTraces := bcc.NewTable(bpfModule.TableId(stackTracesMapName), bpfModule)
	histogram := bcc.NewTable(bpfModule.TableId(histogramMapName), bpfModule)

	result := make(map[string]int, 0)

	time.Sleep(time.Duration(o.duration) * time.Second)

	fmt.Println("Stack trace histogram map")
	for it := histogram.Iter(); it.Next(); {
		histogramKeyBin := it.Key()
		count := it.Leaf()

		var histogramKey HistogramKey
		CheckErr(binary.Read(bytes.NewBuffer(histogramKeyBin), binary.LittleEndian, &histogramKey))

		// Check that the pid matches.
		if int(histogramKey.Pid) != o.pid {
			continue
		}

		var symbolsStr string

		fmt.Printf("\tmatched stack trace executed %d times\n\t\tpid: %v\n",
			binary.LittleEndian.Uint64(count), histogramKey.Pid)

		fmt.Printf("\t\tkernel stack id: %v\n", histogramKey.KernelStackId)

		// Check if the trace is of kernel or user stack.
		if histogramKey.KernelStackId != 0 {
			stackTrace, err := getStackTrace(stackTraces, histogramKey.KernelStackId)
			if err == nil && stackTrace != nil {
				symbolsStr += getStackTraceSyms(stackTrace, kernelSymUnknown)
			}
		}
		fmt.Printf("\t\tuser stack id: %v\n", histogramKey.UserStackId)

		if histogramKey.UserStackId != 0 {
			stackTrace, err := getStackTrace(stackTraces, histogramKey.UserStackId)
			if err == nil && stackTrace != nil {
				symbolsStr += getStackTraceSyms(stackTrace, userSymUnknown)
			}
		}

		// Increment the result map value for the histogramKey stack symbol string (e.g. "main;subfunc;")
		result[symbolsStr]++
	}
}

func getStackTrace(stackTracesMap *bcc.Table, id libc.U_int32_t) (*StackTrace, error) {
	key := make([]byte, 4)
	binary.LittleEndian.PutUint32(key, id)

	stackBinary, err := stackTracesMap.Get(key)
	if err != nil {
		return nil, err
	}

	var stackTrace StackTrace
	err = binary.Read(bytes.NewBuffer(stackBinary), binary.LittleEndian, &stackTrace)
	if err != nil {
		return nil, err
	}

	return &stackTrace, nil
}

func getStackTraceSyms(stackTrace *StackTrace, unknown string) string {
	var symbolsStr string
	for _, ip := range stackTrace {
		if ip != 0 {
			sym, err := ksym.Ksym(fmt.Sprintf("%016x", ip))
			if err != nil {
				sym = unknown
			}
			fmt.Printf("\t\t\t%#016x\t%s\n", ip, sym)
			symbolsStr += sym
			symbolsStr += ";"
		}
	}
	return symbolsStr
}
