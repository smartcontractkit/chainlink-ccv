// Package rmncurseconformance provides shared contract tests for
// chainaccess.RMNCurseReader. Implementations supply a test harness
// (deploy + curse + clear) and a factory to build a reader for the
// deployed RMN Remote address. Chain teams implement the harness and wire
// a reader (e.g. NewEVMSourceReader) to the same deployment the harness uses.
package rmncurseconformance
