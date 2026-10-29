// Package common mirrors the repo's common package for analyzer tests.
package common

import "context"

func EnsureDBConnectionContext(ctx context.Context, db any) error { return nil }
