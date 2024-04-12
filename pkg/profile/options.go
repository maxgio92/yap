package profile

import (
	log "github.com/rs/zerolog"
)

type ProfileOption func(profile *Profile)

func WithPID(pid int) ProfileOption {
	return func(t *Profile) {
		t.pid = pid
	}
}

func WithDuration(duration int) ProfileOption {
	return func(t *Profile) {
		t.duration = duration
	}
}

func WithSamplingPeriodMillis(period uint64) ProfileOption {
	return func(t *Profile) {
		t.samplingPeriodMillis = period
	}
}

func WithProbe(probe []byte) ProfileOption {
	return func(t *Profile) {
		t.probe = probe
	}
}

func WithProbeName(name string) ProfileOption {
	return func(t *Profile) {
		t.probeName = name
	}
}

func WithMapStackTraces(name string) ProfileOption {
	return func(t *Profile) {
		t.mapStackTraces = name
	}
}

func WithMapHistogram(name string) ProfileOption {
	return func(t *Profile) {
		t.mapHistogram = name
	}
}

func WithLogger(logger log.Logger) ProfileOption {
	return func(t *Profile) {
		t.logger = logger
	}
}
