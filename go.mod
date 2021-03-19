module github.com/guardicore/ipcdump

go 1.15

require (
	github.com/guardicore/ipcdump/internal/bpf v0.0.0
	github.com/guardicore/ipcdump/internal/collection v0.0.0
	github.com/guardicore/ipcdump/internal/events v0.0.0
	github.com/iovisor/gobpf v0.0.0-20200614202714-e6b321d32103
	github.com/mitchellh/go-ps v1.0.0
	github.com/shirou/gopsutil v2.20.9+incompatible
	honnef.co/go/netdb v0.0.0-20150201073656-a416d700ae39 // indirect
)

replace github.com/guardicore/ipcdump/internal/collection => ./internal/collection

replace github.com/guardicore/ipcdump/internal/events => ./internal/events

replace github.com/guardicore/ipcdump/internal/bpf => ./internal/bpf
