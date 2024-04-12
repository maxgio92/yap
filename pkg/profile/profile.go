package profile

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

type HistogramKey struct {
	Pid int32

	// UserStackId, an index into the stack-traces map.
	UserStackId uint32

	// KernelStackId, an index into the stack-traces map.
	KernelStackId uint32
}

// StackTrace is an array of instruction pointers (IP).
// 127 is the size of the profile, as for the default PERF_MAX_STACK_DEPTH.
type StackTrace [127]uint64

type Profile struct {
	pid                  int
	duration             int
	samplingPeriodMillis uint64
	probeFilepath        string
	probeName            string
	mapStackTraces       string
	mapHistogram         string
}

func NewProfile(opts ...ProfileOption) *Profile {
	profile := new(Profile)
	for _, f := range opts {
		f(profile)
	}

	return profile
}

func (t *Profile) RunProfile() error {
	bpfModule, err := bpf.NewModuleFromFile(t.probeFilepath)
	if err != nil {
		return errors.Wrap(err, "error creating the BPF module object")
	}
	defer bpfModule.Close()

	if err := bpfModule.BPFLoadObject(); err != nil {
		return errors.Wrap(err, "error loading the BPF program")
	}

	prog, err := bpfModule.GetProgram(t.probeName)
	if err != nil {
		return errors.Wrap(err, "error getting the BPF program object")
	}

	// The perf event attribute set.
	attr := &unix.PerfEventAttr{

		// If type is PERF_TYPE_SOFTWARE, we are measuring software events provided by the kernel.
		Type: unix.PERF_TYPE_SOFTWARE,

		// This reports the CPU clock, a high-resolution per-CPU timer.
		Config: unix.PERF_COUNT_SW_CPU_CLOCK,

		// A "sampling" event is one that generates an overflow notification every N events,
		// where N is given by sample_period.
		// sample_freq can be used if you wish to use frequency rather than period.
		// sample_period and sample_freq are mutually exclusive.
		// The kernel will adjust the sampling period to try and achieve the desired rate.
		Sample: t.samplingPeriodMillis * 1000 * 1000,
	}

	// Create the perf event file descriptor that corresponds to one event that is measured.
	// We're measuring a clock timer software event just to run the program on a periodic schedule.
	// When a specified number of clock samples occur, the kernel will trigger the program.
	evt, err := unix.PerfEventOpen(
		// The attribute set.
		attr,

		// the specified task.
		t.pid,
		// this is invalid. See man(2) perf_event_open.
		// For some reason it worked in bcc through the BPF Module API.
		// -1,

		// on any CPU.
		-1,

		// The group_fd argument allows event groups to be created. An event group has one event which
		// is the group leader. A single event on its own is created with group_fd = -1 and is considered
		// to be a group with only 1 member.
		-1,

		// The program file descriptor.
		prog.FileDescriptor(),
	)
	if err != nil {
		return errors.Wrap(err, "error creating the perf event")
	}
	defer func() {
		if err := unix.Close(evt); err != nil {
			log.Fatalf("Failed to close perf event: %v", err)
		}
	}()

	// Attach the BPF program to the sampling perf event.
	if _, err = prog.AttachPerfEvent(prog.FileDescriptor()); err != nil {
		return errors.Wrap(err, "error attaching the BPF probe to the sampling perf event")
	}

	stackTraces, err := bpfModule.GetMap(t.mapStackTraces)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("error getting %s BPF map", t.mapStackTraces))
	}

	histogram, err := bpfModule.GetMap(t.mapHistogram)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("error getting %s BPF map", t.mapHistogram))
	}

	// Iterate over the stack profile counts histogram map.
	result := make(map[string]int, 0)

	for it := histogram.Iterator(); it.Next(); {
		k := it.Key()
		count, err := histogram.GetValue(unsafe.Pointer(&k))
		if err != nil {
			return errors.Wrap(err, fmt.Sprintf("error getting stack profile count for key %v", k))
		}

		var key HistogramKey
		if err = binary.Read(bytes.NewBuffer(k), binary.LittleEndian, &key); err != nil {
			return errors.Wrap(err, fmt.Sprintf("error reading the stack profile count key %v", k))
		}

		// Skip stack profile counts of other tasks.
		if int(key.Pid) != t.pid {
			continue
		}

		fmt.Printf("%v\t%v\t\t", key.Pid, binary.LittleEndian.Uint64(count))
		fmt.Printf("%v\t\t", key.KernelStackId)

		var symbols string

		if key.KernelStackId != 0 {
			st, err := getStackTrace(stackTraces, key.KernelStackId)
			if err == nil && st != nil {
				symbols += getSymbols(bpfModule, t.pid, st, false)
			} else {
				fmt.Printf("error getting user stack trace for id %d", key.KernelStackId)
			}
		}

		if key.UserStackId != 0 {
			st, err := getStackTrace(stackTraces, key.UserStackId)
			if err == nil && st != nil {
				symbols += getSymbols(bpfModule, t.pid, st, true)
			} else {
				fmt.Printf("error getting user stack trace for id %d", key.UserStackId)
			}
		}

		// Increment the result map value for the stack trace symbol string (e.g. "main;subfunc;")
		result[symbols]++
	}

	return nil
}

func getStackTrace(stackTracesMap *bpf.BPFMap, id uint32) (*StackTrace, error) {
	key := make([]byte, 4)
	binary.LittleEndian.PutUint32(key, id)

	stackBinary, err := stackTracesMap.GetValue(unsafe.Pointer(&key))
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

func getSymbols(bpfModule *bpf.Module, pid int, stackTrace *StackTrace, user bool) string {
	var symbols string
	if !user {
		pid = -1
	}
	for _, ip := range stackTrace {
		if ip != 0 {
			sym := fmt.Sprintf("%#016x %s; ", ip, "[UNKOWN]")
			symbols += sym
			symbols += ";"
		}
	}

	return symbols
}
