package dave

import (
	"fmt"
	"sync/atomic"
)

// LogSeverity is the severity of a log message. Values match libdave.
type LogSeverity int

// Log severities.
const (
	LogVerbose LogSeverity = 0
	LogInfo    LogSeverity = 1
	LogWarning LogSeverity = 2
	LogError   LogSeverity = 3
	LogNone    LogSeverity = 4
)

// LogSink receives library log messages.
type LogSink func(severity LogSeverity, message string)

var logSink atomic.Pointer[LogSink]

// SetLogSink installs a process-wide log sink (libdave daveSetLogSinkCallback).
// A nil sink disables logging, which is the default.
func SetLogSink(sink LogSink) {
	if sink == nil {
		logSink.Store(nil)
		return
	}
	logSink.Store(&sink)
}

func logf(severity LogSeverity, format string, args ...any) {
	if p := logSink.Load(); p != nil {
		(*p)(severity, fmt.Sprintf(format, args...))
	}
}
