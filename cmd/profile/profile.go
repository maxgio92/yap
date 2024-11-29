package profile

import (
	"fmt"
	"os"

	log "github.com/rs/zerolog"
	"github.com/spf13/cobra"

	"github.com/maxgio92/yap/internal/commands/options"
	"github.com/maxgio92/yap/pkg/profile"
)

type Options struct {
	pid int
	*options.CommonOptions
}

func NewCommand(opts *options.CommonOptions) *cobra.Command {
	o := &Options{0, opts}

	cmd := &cobra.Command{
		Use:   "profile",
		Short: "profile executes a sampling profiling and returns as result the residency fraction per stack trace",
		RunE:  o.Run,
	}
	cmd.Flags().IntVar(&o.pid, "pid", 0, "the PID of the process")
	cmd.MarkFlagRequired("pid")

	return cmd
}

func (o *Options) Run(_ *cobra.Command, _ []string) error {
	if o.Debug {
		o.Logger = o.Logger.Level(log.DebugLevel)
	}

	profiler := profile.NewProfiler(
		profile.WithPID(o.pid),
		profile.WithSamplingPeriodMillis(11),
		profile.WithProbeName("sample_stack_trace"),
		profile.WithProbe(o.Probe),
		profile.WithMapStackTraces("stack_traces"),
		profile.WithMapHistogram("histogram"),
		profile.WithLogger(o.Logger),
	)

	// Run profile.
	report, err := profiler.RunProfile(o.Ctx)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// Print stack traces residency fraction table.
	fmt.Println("Residency Stack trace")
	for k, v := range report {
		fmt.Printf("%4.1f%%     %s\n", v*100, k)
	}

	return nil
}
