module github.com/guardicore/ipcdump/internal/collection

go 1.15

require (
	github.com/guardicore/ipcdump/internal/bpf v0.0.0-00010101000000-000000000000
	github.com/guardicore/ipcdump/internal/events v0.0.0-00010101000000-000000000000
	github.com/iovisor/gobpf v0.0.0-20200614202714-e6b321d32103
	github.com/mitchellh/go-ps v1.0.0
	golang.org/x/sys v0.0.0-20201024232916-9f70ab9862d5
	honnef.co/go/netdb v0.0.0-20150201073656-a416d700ae39
)

replace github.com/guardicore/ipcdump/internal/events => ../events

replace github.com/guardicore/ipcdump/internal/bpf => ../bpf
