package profile

import "fmt"

// getTraceSymbols returns a string containing the resolved symbols separated by ';'
// for the process of the ID that is passed as argument.
// Symbolization is supported for non-stripped ELF executable binaries, because the .symtab
// ELF section is looked up.
func (p *Profiler) getTraceSymbols(pid int, stackTrace *StackTrace, user bool) string {
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
			s, err := p.symTabELF.GetSymbol(ip)
			if err != nil || s == "" {
				symbols += fmt.Sprintf("%#016x;", ip)
			}
		}
		symbols += fmt.Sprintf("%s;", s)
	}

	return symbols
}
