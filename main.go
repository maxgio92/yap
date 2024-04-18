package main

import (
	"context"
	"embed"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path"
	"syscall"

	"github.com/maxgio92/cpu-profiler/pkg/profile"
	log "github.com/rs/zerolog"
)

//go:embed output/*
var probeFS embed.FS

func main() {
	var pid int
	flag.IntVar(&pid, "pid", 0, "The PID of the process")
	debug := flag.Bool("debug", false, "Sets log level to debug")

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

	probe, err := probeFS.ReadFile("output/profile.bpf.o")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	logger := log.New(os.Stdout).Level(log.InfoLevel)
	if *debug {
		logger = logger.Level(log.DebugLevel)
	}

	profiler := profile.NewProfile(
		profile.WithPID(pid),
		profile.WithSamplingPeriodMillis(11),
		profile.WithProbeName("sample_stack_trace"),
		profile.WithProbe(probe),
		profile.WithMapStackTraces("stack_traces"),
		profile.WithMapHistogram("histogram"),
		profile.WithLogger(logger),
	)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL)

	go func() {
		<-ctx.Done()
		logger.Info().Msg("terminating...")
		cancel()
	}()

	// Run profile.
	report, err := profiler.RunProfile(ctx)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// Print stack traces residency fraction table.
	fmt.Println("Residency\tStack trace")
	for k, v := range report {
		fmt.Printf("%.1f%%\t\t%s\n", v*100, k)
	}
}
