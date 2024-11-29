package profile

import (
	"bytes"
	"encoding/binary"
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
