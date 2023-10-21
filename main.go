package main

import "C"
import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/maxgio92/gobpf/bcc"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
	libc "modernc.org/libc/sys/types"

	. "github.com/maxgio92/perf-profiler-go/internal/utils"
)

type Options struct {
	pid      int
	duration int
}

type HistogramKey struct {
	Pid int32

	// UserStackId, an index into the stack-traces map.
	UserStackId uint32

	// KernelStackId, an index into the stack-traces map.
	KernelStackId uint32
}

// StackTrace is an array of instruction pointers (IP).
// 127 is the size of the trace, as for the default PERF_MAX_STACK_DEPTH.
type StackTrace [127]uint64

const (
	probeFile = "kernel/perf_profiler.bpf.c"
	probeName = "sample_stack_trace"

	stackTracesMapName = "stack_traces"
	histogramMapName   = "histogram"

	samplingPeriodMillis = 11

	symUnknown = "[UNKNOWN]"
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

	fmt.Printf("PID\t\tTIMES\tKERNEL STACK ID\tKERNEL STACK TRACE\tUSER STACK ID\tUSER STACK TRACE\n")

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

		fmt.Printf("%v\t%v\t\t", histogramKey.Pid, binary.LittleEndian.Uint64(count))

		fmt.Printf("%v\t\t", histogramKey.KernelStackId)

		if histogramKey.KernelStackId != 0 {
			stackTrace, err := getStackTrace(stackTraces, histogramKey.KernelStackId)
			if err == nil && stackTrace != nil {
				symbolsStr += getStackTraceSyms(bpfModule, int(histogramKey.Pid), stackTrace, false)
			}
		}
		fmt.Printf("%v\t\t\t", histogramKey.UserStackId)

		if histogramKey.UserStackId != 0 {
			stackTrace, err := getStackTrace(stackTraces, histogramKey.UserStackId)
			if err == nil && stackTrace != nil {
				symbolsStr += getStackTraceSyms(bpfModule, int(histogramKey.Pid), stackTrace, true)
			}
		}

		fmt.Printf("\n")

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

func getStackTraceSyms(module *bcc.Module, pid int, stackTrace *StackTrace, user bool) string {
	var symbolsStr string
	if !user {
		pid = -1
	}
	for _, ip := range stackTrace {
		if ip != 0 {
			sym := module.GetSymbolByAddr(ip, pid)
			if sym == "" {
				sym = symUnknown
				fmt.Printf("%#016x %s; ", ip, sym)
			} else {
				fmt.Printf("%s; ", sym)
			}
			symbolsStr += sym
			symbolsStr += ";"
		}
	}

	fmt.Printf("\t")

	return symbolsStr
}
