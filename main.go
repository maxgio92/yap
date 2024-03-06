package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/maxgio92/perf-profiler-go/pkg/profile"
)

func main() {
	var pid, duration int
	flag.IntVar(&pid, "pid", 0, "The PID of the process")
	flag.IntVar(&duration, "duration", 0, "The duration in seconds for the profiling")

	flag.Parse()

	profiler := profile.NewProfile(
		profile.WithPID(pid),
		profile.WithDuration(duration),
		profile.WithSamplingPeriodMillis(11),
		profile.WithProbeName("sample_stack_trace"),
		profile.WithProbeFilepath("kernel/profile.o"),
		profile.WithMapStackTraces("stack_traces"),
		profile.WithMapHistogram("histogram"),
	)

	// Run profile.
	if err := profiler.RunProfile(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
