package collection

import (
    "os"
    "flag"
    "time"
    "testing"
    "github.com/guardicode/ipcdump/internal/events"
)

func NopEmit(events.IpcEvent) error {
    return nil
}
func NopLostEmit(events.EmittedEventType, uint64, time.Time) error {
    return nil
}

func TestMain(m *testing.M) {
    var noReplaceEmit bool
    flag.BoolVar(&noReplaceEmit, "E", false, "do not replace emit with nop (useful for debugging)")
    flag.Parse()

    if !noReplaceEmit {
        events.EmitOutputFunc = NopEmit
        events.EmitOutputLostFunc = NopLostEmit
    }

	os.Exit(m.Run())
}
