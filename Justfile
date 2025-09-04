# Default: show available recipes
default:
    just --list

# Install dependencies.
deps:
	@command -v gomods >/dev/null 2>&1 || go install github.com/jmank88/gomods@v0.1.5
	
# Run go test on all modules.
test: deps
	gomods -w go test ./...
