package symtable

import (
	"debug/elf"
	"github.com/pkg/errors"
)

// ELFSymTab is one of the possible abstractions around executable
// file symbol tables, for ELF files.
type ELFSymTab struct {
	symtab []elf.Symbol
}

func NewELFSymTab() *ELFSymTab {
	return new(ELFSymTab)
}

// Load loads from the underlying filesystem the ELF file
// with debug/elf.Open and stores it in the ELFSymTab struct.
func (e *ELFSymTab) Load(pathname string) error {
	// Skip load if file elf.File has already been loaded.
	if e.symtab != nil {
		return nil
	}
	file, err := elf.Open(pathname)
	if err != nil {
		return errors.Wrap(err, "opening ELF file")
	}
	syms, err := file.Symbols()
	if err != nil {
		return errors.Wrap(err, "getting ELF symtable")
	}
	e.symtab = syms

	return nil
}

// GetSymbol returns symbol name from an instruction pointer address
// reading the ELF symbol table.
func (e *ELFSymTab) GetSymbol(ip uint64) (string, error) {
	var sym string
	if e.symtab == nil {
		return "", errors.New("ELF symbols not loaded")
	}
	for _, s := range e.symtab {
		if ip >= s.Value && ip < (s.Value+s.Size) {
			sym = s.Name
		}
	}

	return sym, nil
}
