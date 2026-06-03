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

stress-stable-5hop:
	ulimit -n 65536 && \
	echo "ulimit -n=$$(ulimit -n)" && \
	NO_COLOR=1 RUST_LOG=error \
	MONAD_STRESS_RELAYS=10 \
	MONAD_STRESS_CIRCUITS=200 \
	MONAD_STRESS_HOPS=5 \
	MONAD_STRESS_STREAMS=25 \
	MONAD_STRESS_PAYLOAD_BYTES=3000 \
	cargo test -p monad-relay --test stress -- --ignored stress_three_hop_quic_configurable --nocapture

stress-transport-extreme:
	ulimit -n 524288 && \
	echo "ulimit -n=$$(ulimit -n)" && \
	NO_COLOR=1 RUST_LOG=error \
	MONAD_STRESS_RELAYS=10 \
	MONAD_STRESS_CIRCUITS=100 \
	MONAD_STRESS_HOPS=5 \
	MONAD_STRESS_STREAMS=25000 \
	MONAD_STRESS_MAX_IN_FLIGHT_PER_CIRCUIT=25000 \
	MONAD_STRESS_TARGETS=100 \
	MONAD_STRESS_PAYLOAD_BYTES=256 \
	cargo test -p monad-relay --test stress -- --ignored stress_three_hop_quic_configurable --nocapture

stress-payment-buffered:
	ulimit -n 524288 && \
	echo "ulimit -n=$$(ulimit -n)" && \
	NO_COLOR=1 RUST_LOG=error \
	MONAD_STRESS_PAYMENT_MODE=buffered \
	MONAD_STRESS_INITIAL_PAYMENT_MSATS=100000 \
	MONAD_STRESS_PAYMENT_CHUNK_MSATS=100000 \
	MONAD_STRESS_TARGET_BUFFER_MSATS=20000 \
	MONAD_STRESS_PAYMENT_STATUS_POLL_MS=100 \
	MONAD_STRESS_RELAYS=10 \
	MONAD_STRESS_CIRCUITS=25 \
	MONAD_STRESS_HOPS=5 \
	MONAD_STRESS_STREAMS=2500 \
	MONAD_STRESS_MAX_IN_FLIGHT_PER_CIRCUIT=10 \
	MONAD_STRESS_TARGETS=100 \
	MONAD_STRESS_PAYLOAD_BYTES=256 \
	cargo test -p monad-relay --test stress -- --ignored stress_three_hop_quic_configurable --nocapture

stress-payment-relink:
	ulimit -n 524288 && \
	echo "ulimit -n=$$(ulimit -n)" && \
	NO_COLOR=1 RUST_LOG=error \
	MONAD_STRESS_PAYMENT_MODE=relink-buffered \
	MONAD_STRESS_CHANNEL_CAPACITY_MSATS=300000 \
	MONAD_STRESS_INITIAL_PAYMENT_MSATS=100000 \
	MONAD_STRESS_PAYMENT_CHUNK_MSATS=100000 \
	MONAD_STRESS_TARGET_BUFFER_MSATS=20000 \
	MONAD_STRESS_PAYMENT_STATUS_POLL_MS=100 \
	MONAD_STRESS_RELAYS=10 \
	MONAD_STRESS_CIRCUITS=10 \
	MONAD_STRESS_HOPS=5 \
	MONAD_STRESS_STREAMS=2500 \
	MONAD_STRESS_MAX_IN_FLIGHT_PER_CIRCUIT=10 \
	MONAD_STRESS_TARGETS=100 \
	MONAD_STRESS_PAYLOAD_BYTES=256 \
	cargo test -p monad-relay --test stress -- --ignored stress_three_hop_quic_configurable --nocapture

lint:
	cargo clippy --all-targets --all-features -- -D warnings

check: fmt-check test
