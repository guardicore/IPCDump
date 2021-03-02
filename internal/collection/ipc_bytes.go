package collection

import (
	"fmt"

	"github.com/guardicode/ipcdump/internal/bpf"
	"github.com/guardicode/ipcdump/internal/events"
)

var bpfUtilSource = `
#ifdef COLLECT_IPC_BYTES

#define MAX_EVENT_SIZE 0x8000
#define REMAINING_BYTES_BUFFER(t) \
    u16 bytes_len; \
    u16 pad0;  \
    u16 pad1;  \
    u16 pad2;  \
    unsigned char bytes[MAX_EVENT_SIZE-sizeof(u64)-sizeof(t)]


#ifndef COLLECT_IPC_BYTES_MAX
#define COLLECT_IPC_BYTES_MAX (MAX_EVENT_SIZE)
#endif

#define BYTES_BUF_LEN(e, count) ((u16)(min(min((u64)sizeof((e)->bytes), (u64)(count)), (u64)(COLLECT_IPC_BYTES_MAX))))
#define EVENT_SIZE(e) ((u32)(min(offsetof(typeof(*e), bytes) + (e)->bytes_len, (unsigned long)MAX_EVENT_SIZE)))


#else  // !COLLECT_IPC_BYTES


#define REMAINING_BYTES_BUFFER(t) \
    u16 bytes_len_always_zero; \
    u16 pad0; \
    u16 pad1; \
    u16 pad2
#define EVENT_SIZE(e) (sizeof(*(e)))

#endif
`

func SetupIpcBytesOutput(bpfBuilder *bpf.BpfBuilder, dumpBytes bool, dumpBytesMax uint) error {
	if dumpBytes {
		bpfBuilder.AddSources("#define COLLECT_IPC_BYTES")
		if dumpBytesMax > 0 {
			bpfBuilder.AddSources(fmt.Sprintf("#define COLLECT_IPC_BYTES_MAX (%v)", dumpBytesMax))
		}

		bytesLimit := -1
		if dumpBytesMax != 0 {
			bytesLimit = (int)(dumpBytesMax)
		}
		if err := events.SetEmitOutputBytesLimit(bytesLimit); err != nil {
			return fmt.Errorf("failed to set output bytes limit: %w\n", err)
		}
	}

	bpfBuilder.AddSources(bpfUtilSource)
	return nil
}
