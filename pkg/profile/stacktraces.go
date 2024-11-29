package profile

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
)

// getStackTraceByID returns a StackTrace struct from the BPF_MAP_TYPE_STACK_TRACE map,
// keyed by stack ID returned by the get_stackid BPF helper.
func (p *Profiler) getStackTraceByID(stackTraces *bpf.BPFMap, stackID uint32) (*StackTrace, error) {
	v, err := stackTraces.GetValue(unsafe.Pointer(&stackID))
	if err != nil {
		return nil, err
	}

	var stackTrace StackTrace
	err = binary.Read(bytes.NewBuffer(v), binary.LittleEndian, &stackTrace)
	if err != nil {
		return nil, err
	}

	return &stackTrace, nil
}

// getHumanReadableStackTrace returns a string containing the resolved symbols separated by ';'
// for the process of the ID that is passed as argument.
// Symbolization is supported for non-stripped ELF executable binaries, because the .symtab
// ELF section is looked up.
func (p *Profiler) getHumanReadableStackTrace(stackTrace *StackTrace) string {
	var symbols string

	for _, ip := range stackTrace {
		if ip == 0 {
			continue
		}
		s, err := p.symTabELF.GetSymbol(ip)
		if err != nil || s == "" {
			symbols += fmt.Sprintf("%#016x;", ip)
		}
		symbols += fmt.Sprintf("%s;", s)
	}

	return symbols
}
