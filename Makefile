fmt:
	cargo fmt --all -- --config-path rustfmt.toml

fmt-check:
	cargo fmt --all -- --check --config-path rustfmt.toml

test:
	cargo test

stress-tiny:
	cargo test -p monad-relay --test stress -- --ignored stress_three_hop_quic_tiny --nocapture

stress-small:
	cargo test -p monad-relay --test stress -- --ignored stress_three_hop_quic_small --nocapture

stress-medium:
	cargo test -p monad-relay --test stress -- --ignored stress_three_hop_quic_medium --nocapture

stress-custom:
	cargo test -p monad-relay --test stress -- --ignored stress_three_hop_quic_configurable --nocapture

lint:
	cargo clippy --all-targets --all-features -- -D warnings

check: fmt-check test
