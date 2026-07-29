// Package headtrackerconformance provides shared contract tests for
// chainaccess.HeadTracker implementations. Implementations supply a HeadTracker
// plus an Oracle (typically raw RPC or height-based reads) to compare against
// ground truth via [Oracle.BlockHeaderByNumber].
//
// Tests are intended as integration opt-in: wire a live [HeadTracker] and
// [Oracle] in your test package and call [Run].
package headtrackerconformance
