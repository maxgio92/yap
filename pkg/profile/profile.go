package profile

import (
	"C"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"github.com/maxgio92/cpu-profiler/pkg/symcache"
	"github.com/maxgio92/cpu-profiler/pkg/symtable"
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
	symCache             *symcache.SymCache
	symTabELF            *symtable.ELFSymTab
}

func NewProfile(opts ...ProfileOption) *Profile {
	profile := new(Profile)
	for _, f := range opts {
		f(profile)
	}
	profile.symCache = symcache.NewSymCache()
	profile.symTabELF = symtable.NewELFSymTab()

	return profile
}

func (t *Profile) RunProfile(ctx context.Context) (map[string]float64, error) {
	bpf.SetLoggerCbs(bpf.Callbacks{
		Log: func(level int, msg string) {
			return
		},
	})

	bpfModule, err := bpf.NewModuleFromBuffer(t.probe, t.probeName)
	if err != nil {
		return nil, errors.Wrap(err, "error creating the BPF module object")
	}
	defer bpfModule.Close()

	t.logger.Debug().Msg("loading ebpf object")

	if err := bpfModule.BPFLoadObject(); err != nil {
		return nil, errors.Wrap(err, "error loading the BPF program")
	}

	t.logger.Debug().Msg("getting the loaded ebpf program")

	prog, err := bpfModule.GetProgram(t.probeName)
	if err != nil {
		return nil, errors.Wrap(err, "error getting the BPF program object")
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
			return nil, errors.Wrap(err, "error creating the perf event")
		}
		defer func() {
			if err := unix.Close(evt); err != nil {
				t.logger.Fatal().Err(err).Msg("failed to close perf event")
			}
		}()

		t.logger.Debug().Msgf("attaching the ebpf program to the sampling perf event for cpu #%d", i)

		// Attach the BPF program to the sampling perf event.
		if _, err = prog.AttachPerfEvent(evt); err != nil {
			return nil, errors.Wrap(err, "error attaching the BPF probe to the sampling perf event")
		}
	}

	t.logger.Info().Msg("collecting data")

	<-ctx.Done()

	t.logger.Debug().Msg("received signal, analysing data")
	t.logger.Debug().Msg("getting the stack traces ebpf map")

	stackTraces, err := bpfModule.GetMap(t.mapStackTraces)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("error getting %s BPF map", t.mapStackTraces))
	}

	t.logger.Debug().Msg("getting the stack trace counts (histogram) ebpf maps")

	histogram, err := bpfModule.GetMap(t.mapHistogram)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("error getting %s BPF map", t.mapHistogram))
	}

	binprmInfo, err := bpfModule.GetMap("binprm_info")
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("error getting %s BPF map", "binprm_info"))
	}

	// Iterate over the stack profile counts histogram map.
	countTable := make(map[string]int, 0)

	t.logger.Debug().Msg("iterating over the retrieved histogram items")

	sampleCount := 0
	for it := histogram.Iterator(); it.Next(); {
		k := it.Key()

		// Get count for the specific sampled stack trace.
		v, err := histogram.GetValue(unsafe.Pointer(&k[0]))
		if err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("error getting stack profile count for key %v", k))
		}
		count := int(binary.LittleEndian.Uint64(v))

		var key HistogramKey
		if err = binary.Read(bytes.NewBuffer(k), binary.LittleEndian, &key); err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("error reading the stack profile count key %v", k))
		}

		// Skip stack profile counts of other tasks.
		if int(key.Pid) != t.pid {
			continue
		}

		exePath, err := t.getExePath(binprmInfo, key.Pid)
		if err != nil {
			return nil, errors.Wrap(err, "error getting exe path item")
		}

		if err = t.symTabELF.Load(*exePath); err != nil {
			t.logger.Err(err).Msg("error loading the ELF symtable")
		}

		t.logger.Debug().Int32("pid", key.Pid).Str("exe_path", *exePath).Int("stack trace count", count).Msg("got stack traces")

		var symbols string

		if int32(key.UserStackId) >= 0 {
			trace, err := t.getStackTrace(stackTraces, key.UserStackId)
			if err != nil {
				t.logger.Err(err).Uint32("id", key.UserStackId).Msg("error getting user stack trace")
				return nil, errors.Wrap(err, "error getting user stack")
			}
			symbols += t.getTraceSymbols(t.pid, trace, true)
		}

		if int32(key.KernelStackId) >= 0 {
			st, err := t.getStackTrace(stackTraces, key.KernelStackId)
			if err != nil {
				t.logger.Err(err).Uint32("id", key.KernelStackId).Msg("error getting kernel stack trace")
				return nil, errors.Wrap(err, "error getting kernel stack")
			}
			symbols += t.getTraceSymbols(t.pid, st, false)
		}

		// Increment the countTable map value for the stack trace symbol string (e.g. "main;subfunc;")
		sampleCount += count
		countTable[symbols] += count
	}

	fractionTable := make(map[string]float64, len(countTable))
	for trace, count := range countTable {
		residencyFraction := float64(count) / float64(sampleCount)
		fractionTable[trace] = residencyFraction
	}

	return fractionTable, nil
}

func (t Profile) getExePath(binprmInfoMap *bpf.BPFMap, pid int32) (*string, error) {
	v, err := binprmInfoMap.GetValue(unsafe.Pointer(&pid))
	if err != nil {
		return nil, err
	}
	v = v[:clen(v)]
	vs := string(v)

	return &vs, nil
}

func (t *Profile) getStackTrace(stackTraces *bpf.BPFMap, id uint32) (*StackTrace, error) {
	stackBinary, err := stackTraces.GetValue(unsafe.Pointer(&id))
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

func (p *Profile) getTraceSymbols(pid int, stackTrace *StackTrace, user bool) string {
	var symbols string
	if !user {
		pid = -1
	}

	for _, ip := range stackTrace {
		if ip == 0 {
			continue
		}
		// Try with the per-process symbol cache.
		s, err := p.symCache.Get(ip)
		if err != nil {
			// Try with the ELF symtable section.
			s, err = p.symTabELF.GetSymbol(ip)
			if err != nil || s == "" {
				symbols += fmt.Sprintf("%#016x;", ip)
			}
		}
		symbols += fmt.Sprintf("%s;", s)
	}

	return symbols
}
