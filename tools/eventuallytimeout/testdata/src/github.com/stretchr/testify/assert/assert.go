package assert

import (
	"testing"
	"time"
)

type TestingT interface {
	Errorf(format string, args ...any)
}

type CollectT struct{}

type Assertions struct{}

func New(*testing.T) *Assertions { return &Assertions{} }

func Eventually(TestingT, func() bool, time.Duration, time.Duration, ...any) bool {
	return true
}

func EventuallyWithT(TestingT, func(*CollectT), time.Duration, time.Duration, ...any) bool {
	return true
}

func (*Assertions) Eventually(func() bool, time.Duration, time.Duration, ...any) bool {
	return true
}
