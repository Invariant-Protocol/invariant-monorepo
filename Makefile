# ==============================================================================
# INVARIANT PROTOCOL - BUILD & TEST ORCHESTRATOR
# ==============================================================================

.PHONY: all setup check prep test build clean run-local

all: check test build

setup:
	@echo "🛠️ Installing required development tools..."
	cargo install sqlx-cli --no-default-features --features rustls,postgres
	cargo install cargo-chef

check:
	@echo "🔍 Running compilation checks..."
	cargo check --workspace

prep:
	@echo "💾 Updating SQLx offline metadata..."
	cargo sqlx prepare --workspace

test:
	@echo "🧪 Running cryptographic and logic tests..."
	cargo test --workspace

build: prep
	@echo "🏗️ Building optimized binaries..."
	cargo build --release --workspace

clean:
	@echo "🧹 Cleaning ephemeral files..."
	cargo clean
	@if exist crates\invariant_engine\INVARIANT_AUDIT_REPORT.json del /q crates\invariant_engine\INVARIANT_AUDIT_REPORT.json
	@if exist artifacts rmdir /s /q artifacts

run-local: prep
	@echo "🚀 Booting local Invariant Node (Docker required)..."
	docker compose -f docker-compose.yml up db redis -d
	cargo run --bin invariant_server