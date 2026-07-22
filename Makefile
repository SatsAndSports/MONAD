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

# Approx wall time on clanker's machine: ~22m41s
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

# Approx wall time on clanker's machine: ~1m59s
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

# Approx wall time on clanker's machine: ~29s
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

# Approx wall time on clanker's machine: ~1m30s (60s run + setup/teardown)
stress-chaos-rebuild:
	NO_COLOR=1 RUST_LOG=error \
	MONAD_CHAOS_HOPS=3 \
	MONAD_CHAOS_DURATION_SECS=60 \
	MONAD_CHAOS_RESTART_INTERVAL_MS=2000 \
	MONAD_CHAOS_CONCURRENT_PROBES=4 \
	cargo test -p monad-relay --test integration -- --ignored chaos_configured_client_restarts --nocapture

# Approx wall time on clanker's machine: ~5m30s (300s run + setup/teardown)
stress-chaos-rebuild-intense:
	NO_COLOR=1 RUST_LOG=error \
	MONAD_CHAOS_HOPS=5 \
	MONAD_CHAOS_DURATION_SECS=300 \
	MONAD_CHAOS_RESTART_INTERVAL_MS=1000 \
	MONAD_CHAOS_CONCURRENT_PROBES=8 \
	MONAD_CHAOS_RECOVERY_DEADLINE_MS=30000 \
	cargo test -p monad-relay --test integration -- --ignored chaos_configured_client_restarts --nocapture

# Approx wall time on clanker's machine: ~1m30s (60s run + setup/teardown)
stress-chaos-rebuild-abrupt:
	NO_COLOR=1 RUST_LOG=error \
	MONAD_CHAOS_HOPS=3 \
	MONAD_CHAOS_DURATION_SECS=60 \
	MONAD_CHAOS_RESTART_INTERVAL_MS=1000 \
	MONAD_CHAOS_CONCURRENT_PROBES=4 \
	MONAD_CHAOS_KILL_MODE=abrupt \
	MONAD_CHAOS_RECOVERY_DEADLINE_MS=30000 \
	cargo test -p monad-relay --test integration -- --ignored chaos_configured_client_restarts --nocapture

lint:
	cargo clippy --all-targets --all-features -- -D warnings

check: fmt-check test
