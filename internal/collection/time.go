package collection

import (
    "time"
    "golang.org/x/sys/unix"
)

var startMonotonicClockStamp uint64
var startTime time.Time

func init() {
    var ts unix.Timespec
    if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err == nil {
        startTime = time.Now()
        startMonotonicClockStamp = (uint64)(ts.Nano())
    }
}

func TsFromKtime(timestamp uint64) time.Time {
    timeSinceStart := time.Duration(timestamp - startMonotonicClockStamp)
    return startTime.Add(timeSinceStart * time.Nanosecond)
}


