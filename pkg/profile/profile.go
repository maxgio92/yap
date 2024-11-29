package profile

import (
	"C"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"github.com/maxgio92/yap/pkg/symtable"
	"sync"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/pkg/errors"
	log "github.com/rs/zerolog"
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

type Profiler struct {
	pid                  int
	samplingPeriodMillis uint64
	probe                []byte
	probeName            string
	mapStackTraces       string
	mapHistogram         string
	logger               log.Logger
	symTabELF            *symtable.ELFSymTab
}

func NewProfiler(opts ...ProfileOption) *Profiler {
	profile := new(Profiler)
	for _, f := range opts {
		f(profile)
	}
	profile.symTabELF = symtable.NewELFSymTab()

	return profile
}

func (p *Profiler) RunProfile(ctx context.Context) (map[string]float64, error) {
	bpf.SetLoggerCbs(bpf.Callbacks{
		Log: func(level int, msg string) {
			return
		},
	})

	bpfModule, err := bpf.NewModuleFromBuffer(p.probe, p.probeName)
	if err != nil {
		return nil, errors.Wrap(err, "error creating the BPF module object")
	}
	defer bpfModule.Close()
	p.logger.Debug().Msg("loading BPF object")

	if err := bpfModule.BPFLoadObject(); err != nil {
		return nil, errors.Wrap(err, "error loading the BPF program")
	}
	p.logger.Debug().Msg("getting the loaded BPF program")

	prog, err := bpfModule.GetProgram(p.probeName)
	if err != nil {
		return nil, errors.Wrap(err, "error getting the BPF program object")
	}
	p.logger.Debug().Msg("attaching the BPF program sampler")

	if err = p.attachSampler(prog); err != nil {
		return nil, errors.Wrap(err, "error attaching the sampler")
	}
	p.logger.Info().Msg("collecting data")

	// Collect data until interrupt.
	<-ctx.Done()

	p.logger.Debug().Msg("received signal, analysing data")
	p.logger.Debug().Msg("getting the stack traces BPF map")

	stackTracesMap, err := bpfModule.GetMap(p.mapStackTraces)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("error getting %s BPF map", p.mapStackTraces))
	}
	p.logger.Debug().Msg("getting the stack trace counts (histogramMap) BPF maps")

	histogramMap, err := bpfModule.GetMap(p.mapHistogram)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("error getting %s BPF map", p.mapHistogram))
	}

	binprmInfo, err := bpfModule.GetMap("binprm_info")
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("error getting %s BPF map", "binprm_info"))
	}

	// Iterate over the stack profile counts histogramMap map.
	histogram := make(map[string]int, 0)
	p.logger.Debug().Msg("iterating over the retrieved histogramMap items")

	totalSamples := 0

	// Try to load symbols.
	symbolizationWG := &sync.WaitGroup{}
	symbolizationWG.Add(1)
	go func() {
		defer symbolizationWG.Done()

		// Get process executable path on filesystem.
		exePath, err := p.getExePath(binprmInfo, int32(p.pid))
		if err != nil {
			p.logger.Debug().Str("path", *exePath).Int("pid", p.pid).Msg("error getting executable path for symbolization")
			return
		}
		p.logger.Debug().Str("path", *exePath).Int("pid", p.pid).Msg("executable path found")

		// Try to load ELF symbol table, if it's an ELF executable.
		if err = p.symTabELF.Load(*exePath); err != nil {
			p.logger.Debug().Err(err).Msg("error loading the ELF symbol table")
			return
		}
	}()

	// For each function (HistogramKey) sampled.
	for it := histogramMap.Iterator(); it.Next(); {
		k := it.Key()

		// Get count for the specific sampled stack trace.
		v, err := histogramMap.GetValue(unsafe.Pointer(&k[0]))
		if err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("error getting stack profile count for key %v", k))
		}
		count := int(binary.LittleEndian.Uint64(v))

		var key HistogramKey
		if err = binary.Read(bytes.NewBuffer(k), binary.LittleEndian, &key); err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("error reading the stack profile count key %v", k))
		}

		// Skip stack profile counts of other tasks.
		if int(key.Pid) != p.pid {
			continue
		}
		p.logger.Debug().Int("pid", p.pid).Uint32("user_stack_id", key.UserStackId).Uint32("kernel_stack_id", key.KernelStackId).Int("count", count).Msg("got stack traces")

		var symbols string

		// Wait for the symbols to be loaded.
		symbolizationWG.Wait()

		// Append symbols from user stack.
		if int32(key.UserStackId) >= 0 {
			stackTrace, err := p.getStackTraceByID(stackTracesMap, key.UserStackId)
			if err != nil {
				p.logger.Err(err).Uint32("id", key.UserStackId).Msg("error getting user stack trace")
				return nil, errors.Wrap(err, "error getting user stack")
			}
			symbols += p.getSymbolsFromStackTrace(stackTrace)
		}

		// Append symbols from kernel stack.
		if int32(key.KernelStackId) >= 0 {
			stackTrace, err := p.getStackTraceByID(stackTracesMap, key.KernelStackId)
			if err != nil {
				p.logger.Err(err).Uint32("id", key.KernelStackId).Msg("error getting kernel stack trace")
				return nil, errors.Wrap(err, "error getting kernel stack")
			}
			symbols += p.getSymbolsFromStackTrace(stackTrace)
		}

		// Increment the histogram map value for the stack trace symbol string (e.g. "main;subfunc;")
		totalSamples += count
		histogram[symbols] += count
	}

	return p.buildResidencyTable(histogram, totalSamples), nil
}
