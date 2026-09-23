"""Real release-pinned mints, fake Lightning, private disposable databases.

Run using the pinned Nutshell Poetry environment (for its Cashu crypto helpers).
No production wallet code or mint validation is patched. stdout is a safe JSONL
observation log; child logs and test proofs never leave the private temp directory.
"""

import argparse
import contextlib
import copy
import ipaddress
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from cashu.core.crypto.b_dhke import hash_to_curve, step1_alice, step3_alice
from cashu.core.crypto.secp import PublicKey

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
PINS = {
    "nutshell": "a9749146c6bd7f9ab75375a050e9ba795cee301c",
    "nutmix": "7a2329480b7119d5c2e9e16936462a6e7886e91c",
}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


HTTP = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())


def loopback_url(url):
    assert url.startswith("http://") and not any(c.isspace() for c in url)
    parsed = urllib.parse.urlsplit(url)
    assert parsed.scheme == "http" and parsed.hostname
    assert parsed.username is None and parsed.password is None
    assert not parsed.query and not parsed.fragment
    assert "?" not in url and "#" not in url
    assert parsed.path in ("", "/")
    assert parsed.port is None or 0 < parsed.port < 65536
    assert ipaddress.ip_address(parsed.hostname).is_loopback


def emit(**record):
    print(json.dumps(record, sort_keys=True), flush=True)


def request(url, path, payload=None):
    loopback_url(url)
    data = None if payload is None else json.dumps(payload).encode()
    req = urllib.request.Request(url + path, data, {"Content-Type": "application/json"})
    try:
        response = HTTP.open(req, timeout=15)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        body = response.read()
        return response.status, json.loads(body)


def ok(url, path, payload=None):
    status, body = request(url, path, payload)
    assert status == 200, f"HTTP {status} at {path} (body private)"
    return body


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def stop(child):
    # The leader can exit while a descendant still owns sockets or DB locks.
    try:
        os.killpg(child.pid, signal.SIGTERM)
    except ProcessLookupError:
        child.wait(timeout=10)
        return
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        child.poll()  # Reap the leader independently of its process group.
        try:
            os.killpg(child.pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.05)
    else:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(child.pid, signal.SIGKILL)
    child.wait(timeout=10)


@contextlib.contextmanager
def server(name, root, args):
    p = port()
    url = f"http://127.0.0.1:{p}"
    env = dict(os.environ, MONAD_CHARACTERIZATION_PORT=str(p))
    container = None
    child = None
    with (root / f"{name}.log").open("wb") as log:
        try:
            if name == "nutshell":
                env.update(
                    MINT_PRIVATE_KEY="disposable characterization seed",
                    MINT_BACKEND_BOLT11_SAT="FakeWallet",
                    MINT_DATABASE=str(root / "nutshell-db"),
                    MINT_AUTH_DATABASE=str(root / "nutshell-auth"),
                    MINT_RATE_LIMIT="false",
                    MINT_INPUT_FEE_PPK="0",
                    FAKEWALLET_DELAY_INCOMING_PAYMENT="0",
                    DEBUG="false",
                )
                cmd = [sys.executable, str(HERE / "nutshell_adapter.py")]
                cwd = args.nutshell
            elif name == "nutmix":
                container = f"monad-characterization-{os.getpid()}"
                subprocess.run(
                    [
                        "docker",
                        "run",
                        "--rm",
                        "-d",
                        "--name",
                        container,
                        "-e",
                        "POSTGRES_PASSWORD=disposable",
                        "-e",
                        "POSTGRES_USER=postgres",
                        "-p",
                        "127.0.0.1::5432",
                        "postgres:16.8",
                    ],
                    check=True,
                    stdout=log,
                    stderr=log,
                    timeout=120,
                )
                binding = subprocess.check_output(
                    ["docker", "port", container, "5432/tcp"], text=True
                ).strip()
                for _ in range(120):
                    ready = subprocess.run(
                        # The image's initialization server accepts Unix sockets
                        # before the final TCP server is ready.
                        [
                            "docker",
                            "exec",
                            container,
                            "pg_isready",
                            "-h",
                            "127.0.0.1",
                            "-U",
                            "postgres",
                        ],
                        stdout=log,
                        stderr=log,
                    )
                    if ready.returncode == 0:
                        break
                    time.sleep(0.5)
                else:
                    raise RuntimeError("Postgres readiness timeout")
                env.update(
                    DATABASE_URL=f"postgres://postgres:disposable@{binding}/postgres?sslmode=disable",
                    MINT_PRIVATE_KEY="01" * 32,
                    MINT_LIGHTNING_BACKEND="FakeWallet",
                    NETWORK="regtest",
                    XDG_CONFIG_HOME=str(root),
                    GIN_MODE="release",
                )
                cmd = [str(args.nutmix_build / "monad-characterization")]
                cwd = args.nutmix_build
            else:
                cmd = [
                    str(args.cdk_binary),
                    "--ignored",
                    "--exact",
                    "characterization_cdk_server",
                    "--nocapture",
                ]
                cwd = REPO
            child = subprocess.Popen(
                cmd, cwd=cwd, env=env, stdout=log, stderr=log, start_new_session=True
            )
            for _ in range(120):
                if child.poll() is not None:
                    raise RuntimeError(f"{name} exited before readiness")
                try:
                    ok(url, "/v1/keysets")
                    break
                except (OSError, ValueError, AssertionError):
                    time.sleep(0.5)
            else:
                raise RuntimeError(f"{name} readiness timeout")
            emit(mint=name, event="ready", url=url, pid=child.pid)
            yield url
        finally:
            try:
                if child is not None:
                    stop(child)
            finally:
                if container is not None:
                    subprocess.run(
                        ["docker", "rm", "-f", "-v", container],
                        stdout=log,
                        stderr=log,
                        check=True,
                        timeout=30,
                    )
            emit(mint=name, event="cleaned")


def active(url):
    return next(
        k
        for k in ok(url, "/v1/keysets")["keysets"]
        if k["unit"] == "sat" and k["active"]
    )


def outputs(keyset, amounts):
    messages, private = [], []
    for amount in amounts:
        secret = os.urandom(32).hex()
        blinded, r = step1_alice(secret)
        messages.append({"amount": amount, "id": keyset, "B_": blinded.format().hex()})
        private.append((secret, r))
    return messages, private


def unblind(url, messages, private, signatures):
    assert len(messages) == len(signatures)
    proofs = []
    for message, (secret, r), signature in zip(messages, private, signatures):
        assert (
            signature["id"] == message["id"]
            and signature["amount"] == message["amount"]
        )
        keys = ok(url, "/v1/keys/" + signature["id"])["keysets"][0]["keys"]
        c = step3_alice(
            PublicKey(bytes.fromhex(signature["C_"])),
            r,
            PublicKey(bytes.fromhex(keys[str(message["amount"])])),
        )
        proofs.append(
            {
                "amount": message["amount"],
                "id": message["id"],
                "secret": secret,
                "C": c.format().hex(),
            }
        )
    return proofs


def mint(url, amounts):
    keyset = active(url)
    assert keyset.get("input_fee_ppk", 0) == 0, "ordinary matrix uses zero fees"
    quote = ok(url, "/v1/mint/quote/bolt11", {"amount": sum(amounts), "unit": "sat"})
    for _ in range(100):
        state = ok(url, "/v1/mint/quote/bolt11/" + quote["quote"])
        if state.get("state") == "PAID" or state.get("paid"):
            break
        time.sleep(0.1)
    messages, private = outputs(keyset["id"], amounts)
    response = ok(
        url, "/v1/mint/bolt11", {"quote": quote["quote"], "outputs": messages}
    )
    return unblind(url, messages, private, response["signatures"])


def states(url, inputs, expected):
    ys = [hash_to_curve(p["secret"].encode()).format().hex() for p in inputs]
    result = ok(url, "/v1/checkstate", {"Ys": ys})["states"]
    assert len(result) == len(ys)
    assert {s["Y"]: s["state"] for s in result} == dict.fromkeys(ys, expected)


def restore(url, messages, signatures=None):
    result = ok(url, "/v1/restore", {"outputs": messages})
    returned = result.get("signatures", result.get("promises"))
    assert returned is not None
    if signatures is None:
        assert not result["outputs"] and not returned
    else:
        assert [
            {k: x[k] for k in ("amount", "id", "B_")} for x in result["outputs"]
        ] == messages

        # DLEQ is optional in restore. Compare exact signed points, IDs and amounts.
        def fields(xs):
            return [{k: x[k] for k in ("amount", "id", "C_")} for x in xs]

        assert fields(returned) == fields(signatures)
    return returned


def rejected(name, case, url, inputs, messages, inactive_code):
    status, body = request(url, "/v1/swap", {"inputs": inputs, "outputs": messages})
    assert 400 <= status < 600, f"{case}: unexpectedly accepted"
    states(url, inputs, "UNSPENT")
    restore(url, messages)
    # Mint errors can echo keysets or points. Never emit proof secrets or long hex.
    safe = re.sub(r"[0-9a-fA-F]{32,}", "<redacted-hex>", json.dumps(body))
    for proof in inputs:
        assert proof["secret"] not in safe
    emit(
        mint=name,
        case=case,
        status=status,
        code=body.get("code"),
        body=json.loads(safe),
        all_inputs="UNSPENT",
        exact_restore_outputs=0,
    )
    expected = {
        "cdk": {
            "unknown_output": 12001,
            "unknown_input": 12001,
            "inactive_output_after_rotation": 12002,
        },
        "nutmix": {
            "unknown_output": 12001,
            "unknown_input": 12001,
            "inactive_output_after_rotation": inactive_code,
        },
        "nutshell": {
            "unknown_output": 11000,
            "unknown_input": 0,
            "inactive_output_after_rotation": 12002,
        },
    }
    assert (
        status == 400 and body.get("code") == expected[name][case]
    ), "pinned observation changed"


def characterize(name, url, inactive_code=12001):
    inputs = mint(url, [8, 8])
    old = inputs[0]["id"]
    messages, private = outputs(old, [16])
    response = ok(url, "/v1/swap", {"inputs": inputs, "outputs": messages})
    states(url, inputs, "SPENT")
    restore(url, messages, response["signatures"])
    emit(
        mint=name,
        case="active_swap",
        status=200,
        all_inputs="SPENT",
        exact_restore_outputs=1,
    )
    inputs = unblind(url, messages, private, response["signatures"])
    unknown = "00" + "ab" * 7
    assert all(k["id"] != unknown for k in ok(url, "/v1/keysets")["keysets"])
    messages, _ = outputs(unknown, [16])
    rejected(name, "unknown_output", url, inputs, messages, inactive_code)
    messages, _ = outputs(old, [16])
    bad_inputs = copy.deepcopy(inputs)
    bad_inputs[0]["id"] = unknown
    rejected(name, "unknown_input", url, bad_inputs, messages, inactive_code)
    # The exact output request is prepared before a real administrative rotation.
    ok(url, "/_test/rotate", {})
    new = active(url)["id"]
    assert new != old
    assert any(
        k["id"] == old and not k["active"] for k in ok(url, "/v1/keysets")["keysets"]
    )
    rejected(
        name, "inactive_output_after_rotation", url, inputs, messages, inactive_code
    )
    messages, private = outputs(new, [16])
    response = ok(url, "/v1/swap", {"inputs": inputs, "outputs": messages})
    states(url, inputs, "SPENT")
    emit(mint=name, case="inactive_input_active_output", status=200, all_inputs="SPENT")
    # Discard the accepted response as a wallet would; retain only the oracle copy.
    # This is restore evidence, not a claim of a network proxy fault injection.
    oracle = response["signatures"]
    del response
    ok(url, "/_test/rotate", {})
    assert active(url)["id"] != new
    restored = restore(url, messages, oracle)
    recovered = unblind(url, messages, private, restored)
    states(url, recovered, "UNSPENT")
    emit(
        mint=name,
        case="accepted_restore_after_rotation",
        exact_restore_outputs=len(restored),
        recovered_outputs="UNSPENT",
        resubmissions=0,
    )


def lifecycle(name, case, url, root, args):
    proofs = root / f"{name}-bootstrap.json"
    proofs.write_text(json.dumps(mint(url, [16384])))
    env = dict(
        os.environ,
        MONAD_CHARACTERIZATION_URL=url,
        MONAD_CHARACTERIZATION_CASE=case,
        MONAD_CHARACTERIZATION_PROOFS=str(proofs),
        MONAD_FUNDS_CLIENT_BIN=str(args.client_binary),
        MONAD_FUNDS_RELAY_BIN=str(args.relay_binary),
    )
    log_path = root / f"{name}-{case}.log"
    with log_path.open("wb") as log:
        child = subprocess.Popen(
            [
                str(args.lifecycle_binary),
                "--ignored",
                "--exact",
                "external_mint_signed_lifecycle",
                "--nocapture",
            ],
            cwd=REPO,
            env=env,
            stdout=log,
            stderr=log,
            start_new_session=True,
        )
        try:
            code = child.wait(timeout=150)
        finally:
            stop(child)
    log_text = log_path.read_text()
    evidence = [
        line
        for line in log_text.splitlines()
        if re.fullmatch(
            r"external rejection status=\d+ code=\d+ all_inputs_unspent=\d+ restore_outputs=0",
            line,
        )
    ]
    panic = "panicked at" in log_text
    emit(
        mint=name,
        case="MONAD_" + case,
        exit_code=code,
        panic=panic,
        rejection_evidence=evidence,
    )
    return code == 0 and not panic


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nutshell", type=Path)
    parser.add_argument("--nutmix", type=Path)
    parser.add_argument("--nutmix-revision", default=PINS["nutmix"])
    parser.add_argument("--nutmix-inactive-code", type=int, choices=[12001, 12002])
    parser.add_argument("--cdk-binary", type=Path)
    parser.add_argument("--lifecycle-binary", type=Path)
    parser.add_argument(
        "--client-binary",
        type=Path,
        default=REPO / "target/funds-lifecycle/debug/monad-client",
    )
    parser.add_argument(
        "--relay-binary",
        type=Path,
        default=REPO / "target/funds-lifecycle/debug/monad-relay",
    )
    parser.add_argument(
        "--temp-dir",
        type=Path,
        help="private artifacts parent (default: system temp directory)",
    )
    parser.add_argument(
        "--cases",
        nargs="+",
        default=[
            "baseline",
            "opening-loss",
            "opening-rotation-loss",
            "close-loss",
            "close-rotation",
            "close-rotation-loss",
            "refund-loss",
            "refund-rotation",
            "refund-rotation-loss",
            "drain-loss",
            "drain-rotation",
            "drain-rotation-loss",
        ],
    )
    parser.add_argument(
        "--mints",
        nargs="+",
        default=["cdk", "nutmix", "nutshell"],
        choices=["cdk", "nutmix", "nutshell"],
    )
    args = parser.parse_args()
    if not __debug__:
        parser.error("run without Python optimization; assertions are the test oracle")
    os.umask(0o077)
    if "cdk" in args.mints and args.cdk_binary is None:
        parser.error("--cdk-binary is required for CDK")
    if "nutmix" in args.mints:
        if not re.fullmatch(r"[0-9a-f]{40}", args.nutmix_revision):
            parser.error("--nutmix-revision must be a full immutable SHA")
        if args.nutmix_revision == PINS["nutmix"]:
            if args.nutmix_inactive_code not in (None, 12001):
                parser.error("release Nutmix expectations cannot be changed")
            args.nutmix_inactive_code = 12001
        elif args.nutmix_inactive_code is None:
            parser.error("candidate revisions require explicit --nutmix-inactive-code")
    for name in (
        "cdk_binary",
        "lifecycle_binary",
        "client_binary",
        "relay_binary",
        "nutshell",
        "nutmix",
        "temp_dir",
    ):
        if getattr(args, name) is not None:
            setattr(args, name, getattr(args, name).resolve())
    for name, sha in PINS.items():
        if name not in args.mints:
            continue
        checkout = getattr(args, name)
        if checkout is None:
            parser.error(f"--{name} is required for the selected backend")
        if name == "nutmix":
            sha = args.nutmix_revision
        actual = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=checkout, text=True
        ).strip()
        assert actual == sha, f"{name}: not the configured immutable revision"
        subprocess.run(
            ["git", "diff", "--quiet", "HEAD", "--"], cwd=checkout, check=True
        )
    root = Path(
        tempfile.mkdtemp(prefix="monad-mint-characterization-", dir=args.temp_dir)
    )
    failed = True
    try:
        if "nutmix" in args.mints:
            # Clone tracked content only. Never overwrite supplied untracked packages.
            args.nutmix_build = root / "nutmix-source"
            subprocess.run(
                [
                    "git",
                    "clone",
                    "--no-hardlinks",
                    "--no-checkout",
                    str(args.nutmix.resolve()),
                    str(args.nutmix_build),
                ],
                check=True,
                timeout=120,
            )
            subprocess.run(
                ["git", "checkout", "--detach", args.nutmix_revision],
                cwd=args.nutmix_build,
                check=True,
                timeout=120,
            )
            adapter = args.nutmix_build / "cmd" / "monad-characterization"
            adapter.mkdir()  # Refuse a collision with tracked upstream source.
            shutil.copyfile(HERE / "nutmix_adapter.go", adapter / "main.go")
            subprocess.run(
                [
                    "go",
                    "build",
                    "-o",
                    "monad-characterization",
                    "./cmd/monad-characterization",
                ],
                cwd=args.nutmix_build,
                check=True,
                timeout=600,
            )
            emit(
                mint="nutmix",
                revision=args.nutmix_revision,
                inactive_code=args.nutmix_inactive_code,
            )
        failed = False
        for name in args.mints:
            try:
                with server(name, root, args) as url:
                    characterize(name, url, args.nutmix_inactive_code)
                    if args.lifecycle_binary:
                        for case in args.cases:
                            failed |= not lifecycle(name, case, url, root, args)
            except Exception as error:
                failed = True
                # Do not print exception arguments: libraries may embed proof data.
                emit(mint=name, event="FAILED", error_type=type(error).__name__)
                emit(
                    mint=name,
                    frames=[
                        f"{Path(f.filename).name}:{f.lineno}:{f.name}"
                        for f in traceback.extract_tb(error.__traceback__)
                    ],
                )
        if failed:
            emit(event="private_failure_logs", path=str(root))
        else:
            shutil.rmtree(root)
    finally:
        emit(event="complete", failed=failed)
    return int(failed)


if __name__ == "__main__":
    sys.exit(main())
