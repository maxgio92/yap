package profile

import (
	"fmt"
	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/pkg/errors"
	"os"
	"unsafe"
)

// getExePath returns the path of the executable for the specified process ID.
// It checks the validity of the path shared in the binprm BPF hash map.
// It falls back to the proc filesystem.
func (p *Profiler) getExePath(binprmInfoMap *bpf.BPFMap, pid int32) (*string, error) {
	v, err := binprmInfoMap.GetValue(unsafe.Pointer(&pid))
	if err != nil {
		return nil, err
	}
	v = v[:clen(v)]
	vs := string(v)

	_, err = os.Stat(vs)
	if err == nil {
		return &vs, nil
	}
	p.logger.Debug().Err(err).Str("path", vs).Msg("executable file not found")

	// Fallback to procfs.
	path, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return nil, errors.Wrap(err, "error getting executable path from procfs")
	}
	if _, err = os.Stat(path); err != nil {
		return nil, errors.Wrap(err, "error getting executable path from procfs")
	}

	return &path, nil
}
