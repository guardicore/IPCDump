package bpf

import (
    "github.com/iovisor/gobpf/bcc"
    "errors"
    "strings"
    "fmt"
)

type BpfBuilder struct {
    bpfIncludes map[string]struct{}
    bpfSources string
    loaded bool
}

const bpfHeader = `
#define KBUILD_MODNAME "IPCDUMP"
`

var bpfIncludes = make(map[string]struct{})
var bpfSources string

var loaded = false

func NewBpfBuilder() *BpfBuilder {
    return &BpfBuilder{bpfIncludes: make(map[string]struct{})}
}

func (b *BpfBuilder) AddIncludes(includeSrc string) error {
    for _, line := range strings.Split(strings.TrimSuffix(includeSrc, "\n"), "\n") {
        lineKey := strings.TrimSpace(line)

        if len(lineKey) == 0 {
            continue
        }

        if !strings.HasPrefix(lineKey, "#include") {
            return fmt.Errorf("non-include line \"%s\" in include sources\n", line)
        }

        b.bpfIncludes[lineKey] = struct{}{}
    }
    return nil
}

func (b *BpfBuilder) AddSources(src string) {
    b.bpfSources += src + "\n\n"
}

func (b *BpfBuilder) LoadModule() (*BpfModule, error) {
    if b.loaded {
        return nil, errors.New("bpf module has already been loaded")
    }

    var bpfIncludeSrc string
    for k := range b.bpfIncludes {
        bpfIncludeSrc += k + "\n"
    }

    finalBpfProgram := bpfHeader + "\n\n" + bpfIncludeSrc + "\n\n" + b.bpfSources
    m := bcc.NewModule(finalBpfProgram, []string{})

    if m == nil {
        //return nil, errors.New("failed to compile bpf module.\n\nsource dump:\n\n" + finalBpfProgram)
        return nil, errors.New("failed to compile bpf module.\n\nsource dump:\n\n")
    }

    b.loaded = true
    return NewBpfModule(m), nil
}

