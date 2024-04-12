package profile

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"runtime"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/pkg/errors"
	log "github.com/rs/zerolog"
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
	samplingPeriodMillis uint64
	probe                []byte
	probeName            string
	mapStackTraces       string
	mapHistogram         string
	logger               log.Logger
}

func NewProfile(opts ...ProfileOption) *Profile {
	profile := new(Profile)
	for _, f := range opts {
		f(profile)
	}

	return profile
}

func (t *Profile) RunProfile(ctx context.Context) error {
	bpfModule, err := bpf.NewModuleFromBuffer(t.probe, t.probeName)
	if err != nil {
		return errors.Wrap(err, "error creating the BPF module object")
	}
	defer bpfModule.Close()

	t.logger.Debug().Msg("loading ebpf object")

	if err := bpfModule.BPFLoadObject(); err != nil {
		return errors.Wrap(err, "error loading the BPF program")
	}

	t.logger.Debug().Msg("getting the loaded ebpf program")

	prog, err := bpfModule.GetProgram(t.probeName)
	if err != nil {
		return errors.Wrap(err, "error getting the BPF program object")
	}

	cpusonline := runtime.NumCPU()

	for i := 0; i < cpusonline; i++ {

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

		t.logger.Debug().Msg("opening the sampling software cpu block perf event")

		// Create the perf event file descriptor that corresponds to one event that is measured.
		// We're measuring a clock timer software event just to run the program on a periodic schedule.
		// When a specified number of clock samples occur, the kernel will trigger the program.
		evt, err := unix.PerfEventOpen(
			// The attribute set.
			attr,

			// the specified task.
			//t.pid,
			-1,

			// on the Nth CPU.
			i,

			// The group_fd argument allows event groups to be created. An event group has one event which
			// is the group leader. A single event on its own is created with group_fd = -1 and is considered
			// to be a group with only 1 member.
			-1,

			// The flags.
			0,
		)
		if err != nil {
			return errors.Wrap(err, "error creating the perf event")
		}
		defer func() {
			if err := unix.Close(evt); err != nil {
				t.logger.Fatal().Err(err).Msg("failed to close perf event")
			}
		}()

		t.logger.Debug().Msgf("attaching the ebpf program to the sampling perf event for cpu #%d", i)

		// Attach the BPF program to the sampling perf event.
		if _, err = prog.AttachPerfEvent(evt); err != nil {
			return errors.Wrap(err, "error attaching the BPF probe to the sampling perf event")
		}
	}

	t.logger.Info().Msg("collecting data")

	<-ctx.Done()

	t.logger.Info().Msg("received signal, analysing data")

	t.logger.Debug().Msg("getting the stack traces ebpf map")

	stackTraces, err := bpfModule.GetMap(t.mapStackTraces)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("error getting %s BPF map", t.mapStackTraces))
	}

	t.logger.Debug().Msg("getting the stack trace counts (histogram) ebpf maps")

	histogram, err := bpfModule.GetMap(t.mapHistogram)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("error getting %s BPF map", t.mapHistogram))
	}

	// Iterate over the stack profile counts histogram map.
	result := make(map[string]int, 0)

	t.logger.Debug().Msg("iterating over the retrieved histogram items")

	for it := histogram.Iterator(); it.Next(); {
		k := it.Key()

		t.logger.Debug().Msgf("element key=%v", k)

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
