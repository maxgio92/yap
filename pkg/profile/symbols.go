package profile

import "fmt"

// getSymbolsFromStackTrace returns a string containing the resolved symbols separated by ';'
// for the process of the ID that is passed as argument.
// Symbolization is supported for non-stripped ELF executable binaries, because the .symtab
// ELF section is looked up.
func (p *Profiler) getSymbolsFromStackTrace(stackTrace *StackTrace) string {
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
