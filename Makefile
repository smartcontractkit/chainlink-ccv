
.PHONY: install

install-dependencies:
	@if command -v just >/dev/null 2>&1; then \
		: ; \
	elif uname -s | grep -q Darwin; then \
		brew install just; \
	elif command -v apt-get >/dev/null; then \
		sudo apt-get install -y just; \
	elif command -v dnf >/dev/null; then \
		sudo dnf install -y just; \
	elif command -v pacman >/dev/null; then \
		sudo pacman -Sy --noconfirm just; \
	else \
		@echo "No supported package manager found."; \
		@echo "Please install just manually: https://github.com/casey/just#installation"; \
		exit 1; \
	fi
	echo "✅ just installed at: $$(command -v just)"; \
	echo "Available Justfiles..."; \
	for f in $$(find . -type f \( -name 'Justfile' -o -name '*.just' \)); do \
		echo ""; \
		echo "📂 Found: $$f"; \
		just --list --justfile $$f || echo "⚠️ Failed to parse $$f"; \
	done
