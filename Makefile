fmt:
	cargo fmt --all -- --config-path rustfmt.toml

fmt-check:
	cargo fmt --all -- --check --config-path rustfmt.toml

test:
	cargo test

test-funds-lifecycle:
	cargo build -p monad-client -p monad-relay --bins
	MONAD_FUNDS_CLIENT_BIN=$(CURDIR)/target/debug/monad-client \
	MONAD_FUNDS_RELAY_BIN=$(CURDIR)/target/debug/monad-relay \
	cargo test -p monad-relay --test funds_lifecycle -- --ignored --exact process_funds_lifecycle --nocapture

test-funds-crashes:
	cargo build -p monad-client -p monad-relay --bins --features monad-client/funds-lifecycle-test,monad-relay/funds-lifecycle-test --target-dir "$(CURDIR)/target/funds-lifecycle"
	MONAD_FUNDS_CLIENT_BIN="$(CURDIR)/target/funds-lifecycle/debug/monad-client" \
	MONAD_FUNDS_RELAY_BIN="$(CURDIR)/target/funds-lifecycle/debug/monad-relay" \
	cargo test -p monad-relay --features monad-relay/funds-lifecycle-test --target-dir "$(CURDIR)/target/funds-lifecycle" --test funds_lifecycle -- --ignored --nocapture --test-threads=1 --skip process_seeded_funds_stress

stress-funds-lifecycle:
	cargo build -p monad-client -p monad-relay --bins --features monad-client/funds-lifecycle-test,monad-relay/funds-lifecycle-test --target-dir "$(CURDIR)/target/funds-lifecycle"
	MONAD_FUNDS_CLIENT_BIN="$(CURDIR)/target/funds-lifecycle/debug/monad-client" \
	MONAD_FUNDS_RELAY_BIN="$(CURDIR)/target/funds-lifecycle/debug/monad-relay" \
	cargo test -p monad-relay --features monad-relay/funds-lifecycle-test --target-dir "$(CURDIR)/target/funds-lifecycle" --test funds_lifecycle -- --ignored --nocapture --exact process_seeded_funds_stress

stress-tiny:
	cargo test -p monad-relay --test stress -- --ignored stress_three_hop_quic_tiny --nocapture

stress-small:
	cargo test -p monad-relay --test stress -- --ignored stress_three_hop_quic_small --nocapture

stress-medium:
	cargo test -p monad-relay --test stress -- --ignored stress_three_hop_quic_medium --nocapture

stress-custom:
	cargo test -p monad-relay --test stress -- --ignored stress_three_hop_quic_configurable --nocapture

# Manual only. Measurement excludes provisioning, setup and staggered warmup.
# Use MONAD_CAPACITY_PROFILE=dev for a quick development smoke test.
stress-payment-capacity:
	@sessions="$${MONAD_CAPACITY_SESSIONS-25}"; \
	case "$$sessions" in ''|*[!0-9]*) \
		printf '%s\n' 'Error: MONAD_CAPACITY_SESSIONS must be an integer in 1..100000.' >&2; exit 2;; esac; \
	if ! [ "$$sessions" -ge 1 ] || ! [ "$$sessions" -le 100000 ]; then \
		printf '%s\n' 'Error: MONAD_CAPACITY_SESSIONS must be in 1..100000.' >&2; exit 2; fi; \
	required=$$(expr "$$sessions" \* 2 + 512); \
	limit=$$(ulimit -Sn) || exit 2; \
	if [ "$$limit" != unlimited ] && [ "$$limit" -lt "$$required" ]; then \
		printf 'Error: capacity test with %s sessions requires a soft file-descriptor limit of at least %s; current limit is %s.\n' "$$sessions" "$$required" "$$limit" >&2; \
		printf 'Raise the limit (subject to your hard limit), then rerun the same command:\n  ulimit -Sn %s\n' "$$required" >&2; \
		exit 2; \
	fi
	NO_COLOR=1 RUST_LOG="$${RUST_LOG:-error}" \
	cargo test -j "$${CARGO_BUILD_JOBS:-2}" --profile "$${MONAD_CAPACITY_PROFILE:-release}" \
	-p monad-relay --test integration payment_capacity::single_relay_payment_capacity \
	-- --ignored --exact --nocapture

# One-minute measured trial; provisioning and warmup take additional time.
stress-payment-capacity-1500:
	MONAD_CAPACITY_SESSIONS=1500 \
	MONAD_CAPACITY_SETUP_CONCURRENCY=64 \
	MONAD_CAPACITY_DURATION_SECS=60 \
	$(MAKE) stress-payment-capacity

stress-stable-5hop:
	ulimit -Sn 65536 && \
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
	ulimit -Sn 524288 && \
	echo "ulimit -n=$$(ulimit -n)" && \
	NO_COLOR=1 RUST_LOG=error \
	MONAD_STRESS_RELAYS=10 \
	MONAD_STRESS_CIRCUITS=100 \
	MONAD_STRESS_HOPS=5 \
	MONAD_STRESS_STREAMS=25000 \
	MONAD_STRESS_MAX_IN_FLIGHT_PER_CIRCUIT=25000 \
	MONAD_STRESS_MAX_OPEN_CONNECTS_PER_SESSION=30000 \
	MONAD_STRESS_MAX_CONNECT_SETUPS_PER_SESSION=30000 \
	MONAD_STRESS_MAX_OPEN_CONNECTS_PER_RELAY=300000 \
	MONAD_STRESS_MAX_CONNECT_SETUPS_PER_RELAY=300000 \
	MONAD_STRESS_TARGETS=100 \
	MONAD_STRESS_PAYLOAD_BYTES=256 \
	cargo test -p monad-relay --test stress -- --ignored stress_three_hop_quic_configurable --nocapture

# Approx wall time on clanker's machine: ~1m59s
stress-payment-buffered:
	ulimit -Sn 524288 && \
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
	ulimit -Sn 524288 && \
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
