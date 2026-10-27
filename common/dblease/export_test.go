package dblease

// SetExitForTest replaces the lease's Fatal exit, which would end the test process.
func SetExitForTest(l *Lease, exit func(msg string)) { l.exit = exit }
