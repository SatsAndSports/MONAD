fmt:
	cargo fmt --all -- --config-path rustfmt.toml

fmt-check:
	cargo fmt --all -- --check --config-path rustfmt.toml

test:
	cargo test

lint:
	cargo clippy --all-targets --all-features -- -D warnings

check: fmt-check test
