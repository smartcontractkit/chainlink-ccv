package require

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type Assertions struct{}

func New(*testing.T) *Assertions { return &Assertions{} }

func Eventually(assert.TestingT, func() bool, time.Duration, time.Duration, ...any) {}

func Eventuallyf(assert.TestingT, func() bool, time.Duration, time.Duration, string, ...any) {
}

func EventuallyWithTf(assert.TestingT, func(*assert.CollectT), time.Duration, time.Duration, string, ...any) {
}

func (*Assertions) Eventually(func() bool, time.Duration, time.Duration, ...any) {}
