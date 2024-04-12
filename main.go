package main

import (
	"embed"
	"flag"
	"fmt"
	"os"
	"path"

	"github.com/maxgio92/perf-profiler-go/pkg/profile"
)

//go:embed output/*
var eBPFObject embed.FS

func main() {
	var pid, duration int
	flag.IntVar(&pid, "pid", 0, "The PID of the process")
	flag.IntVar(&duration, "duration", 30, "The duration in seconds for the profiling")

	flag.Usage = func() {
		fmt.Printf("Usage: %s [options] [command]\n", path.Base(os.Args[0]))
		fmt.Printf("Options:\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	if pid == 0 {
		fmt.Println("pid is mandatory")
		os.Exit(1)
	}

	if duration <= 0 {
		fmt.Println("duration must be greater than 0")
		os.Exit(1)
	}

	profiler := profile.NewProfile(
		profile.WithPID(pid),
		profile.WithDuration(duration),
		profile.WithSamplingPeriodMillis(11),
		profile.WithProbeName("sample_stack_trace"),
		profile.WithProbeFilepath("output/profile.o"),
		profile.WithMapStackTraces("stack_traces"),
		profile.WithMapHistogram("histogram"),
	)

	// Run profile.
	if err := profiler.RunProfile(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
