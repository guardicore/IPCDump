package bpf

import (
	"sync"

	"github.com/iovisor/gobpf/bcc"
)

type BpfModule struct {
	mod *bcc.Module
	mu  sync.Mutex
}

func NewBpfModule(mod *bcc.Module) *BpfModule {
	return &BpfModule{mod: mod}
}

func (b *BpfModule) Close() {
	m := b.Get()
	m.Close()
	b.Put()
}

func (b *BpfModule) Get() *bcc.Module {
	b.mu.Lock()
	return b.mod
}

func (b *BpfModule) Put() {
	b.mu.Unlock()
}

func (b BpfModule) Table(tableName string) *bcc.Table {
	// no lock needed for this
	return bcc.NewTable(b.mod.TableId(tableName), b.mod)
}

func (b BpfModule) InitPerfMap(channel chan []byte, tableName string, lostChan chan uint64) (*bcc.PerfMap, error) {
	table := b.Table(tableName)
	return bcc.InitPerfMap(table, channel, lostChan)
}
