"""Demo CLI for presidio-hardened-opcua — PRES-EDU-CSM-101 Experiment 1.

Usage
-----
  python main.py --gen-certs
  python main.py --mode server  --security None            --port 4840
  python main.py --mode client  --security None            --endpoint opc.tcp://localhost:4840
  python main.py --mode server  --security SignAndEncrypt  --port 4840
  python main.py --mode client  --security SignAndEncrypt  --endpoint opc.tcp://localhost:4840 \\
                 --cert certs/client_cert.der --key certs/client_key.pem
  python main.py --benchmark    --endpoint opc.tcp://localhost:4840
"""

from __future__ import annotations

import argparse
import datetime
import logging
import sys
import time
from pathlib import Path

logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")

# ---------------------------------------------------------------------------
# Demo process tags — simulated ICS field data
# ---------------------------------------------------------------------------
DEMO_TAGS = {
    "Temperature_Zone1": 72.4,
    "Pressure_Line_A": 2.35,
    "Valve_State_V01": 1,
    "Flow_Rate_F01": 145.2,
}

DEMO_NS = "urn:presidio:demo:server"
CERTS_DIR = Path("certs")


# ---------------------------------------------------------------------------
# Certificate generation
# ---------------------------------------------------------------------------
def _make_key():
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption())
    return key, pem


def _make_cert(subject_name: str, key, issuer_name: str | None = None, issuer_key=None):
    import ipaddress

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography.x509.oid import NameOID

    name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, subject_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Presidio Demo"),
        ]
    )
    issuer_x509_name = (
        name
        if issuer_name is None
        else x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, issuer_name),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Presidio Demo"),
            ]
        )
    )
    signing_key = key if issuer_key is None else issuer_key
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer_x509_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("localhost"), x509.IPAddress(ipaddress.IPv4Address("127.0.0.1"))]
            ),
            critical=False,
        )
        .sign(signing_key, hashes.SHA256())
    )
    der = cert.public_bytes(Encoding.DER)
    pem = cert.public_bytes(Encoding.PEM)
    return cert, der, pem


def cmd_gen_certs(_args) -> None:
    CERTS_DIR.mkdir(exist_ok=True)

    print("Generating demo certificates in ./certs/ ...")

    # CA (self-signed)
    ca_key, ca_key_pem = _make_key()
    ca_cert, _ca_der, ca_pem = _make_cert("Presidio Demo CA", ca_key)
    (CERTS_DIR / "ca_cert.pem").write_bytes(ca_pem)
    (CERTS_DIR / "ca_key.pem").write_bytes(ca_key_pem)

    # Server cert signed by CA
    srv_key, srv_key_pem = _make_key()
    _srv_cert, srv_der, srv_pem = _make_cert(
        "Presidio Demo Server", srv_key, issuer_name="Presidio Demo CA", issuer_key=ca_key
    )
    (CERTS_DIR / "server_cert.pem").write_bytes(srv_pem)
    (CERTS_DIR / "server_cert.der").write_bytes(srv_der)
    (CERTS_DIR / "server_key.pem").write_bytes(srv_key_pem)

    # Client cert signed by CA
    cli_key, cli_key_pem = _make_key()
    _cli_cert, cli_der, cli_pem = _make_cert(
        "Presidio Demo Client", cli_key, issuer_name="Presidio Demo CA", issuer_key=ca_key
    )
    (CERTS_DIR / "client_cert.pem").write_bytes(cli_pem)
    (CERTS_DIR / "client_cert.der").write_bytes(cli_der)
    (CERTS_DIR / "client_key.pem").write_bytes(cli_key_pem)

    # Untrusted cert: self-signed, NOT signed by CA
    unt_key, unt_key_pem = _make_key()
    _unt_cert, unt_der, unt_pem = _make_cert("Untrusted Self-Signed", unt_key)
    (CERTS_DIR / "untrusted_cert.pem").write_bytes(unt_pem)
    (CERTS_DIR / "untrusted_cert.der").write_bytes(unt_der)
    (CERTS_DIR / "untrusted_key.pem").write_bytes(unt_key_pem)

    print("  certs/ca_cert.pem         — self-signed CA")
    print("  certs/server_cert.der/pem — server cert (CA-signed)")
    print("  certs/server_key.pem      — server private key")
    print("  certs/client_cert.der/pem — client cert (CA-signed, trusted)")
    print("  certs/client_key.pem      — client private key")
    print("  certs/untrusted_cert.der  — self-signed (NOT trusted by Presidio policy)")
    print("  certs/untrusted_key.pem   — untrusted private key")
    print("\nDone. Use these certs with --mode server/client --security SignAndEncrypt.")


# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------
def cmd_server(args) -> None:
    import opcua
    from opcua import ua

    from presidio_opcua.security import SecurityPolicy
    from presidio_opcua.server import HardenedServer

    endpoint = f"opc.tcp://0.0.0.0:{args.port}"

    if args.security == "None":
        print(f"[server] Starting in NONE (no security) mode on {endpoint}")
        print("[server] WARNING: all process values are transmitted in cleartext.")
        srv = opcua.Server()
        srv.set_endpoint(endpoint)
        srv.set_security_policy([ua.SecurityPolicyType.NoSecurity])
    else:
        print(f"[server] Starting in {args.security} mode on {endpoint}")
        if not (CERTS_DIR / "server_cert.pem").exists():
            print("[server] ERROR: certificates not found. Run --gen-certs first.")
            sys.exit(1)
        policy = SecurityPolicy(allow_self_signed=True, allow_no_security=False)
        srv = HardenedServer(security_policy=policy)
        srv.set_endpoint(endpoint)
        srv.load_certificate(str(CERTS_DIR / "server_cert.pem"))
        srv.load_private_key(str(CERTS_DIR / "server_key.pem"))
        if args.security == "SignAndEncrypt":
            srv.set_security_policy([ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt])
        else:
            srv.set_security_policy([ua.SecurityPolicyType.Basic256Sha256_Sign])

    ns = srv.register_namespace(DEMO_NS)
    proc = srv.nodes.objects.add_object(ns, "DemoProcess")
    nodes = {}
    for name, val in DEMO_TAGS.items():
        var = proc.add_variable(ns, name, val)
        var.set_writable()
        nodes[name] = var

    srv.start()
    mode_label = args.security
    print(f"[server] Running ({mode_label}). Tags: {list(DEMO_TAGS.keys())}")
    print("[server] Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        srv.stop()
        print("[server] Stopped.")


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------
def cmd_client(args) -> None:
    from presidio_opcua.client import HardenedClient
    from presidio_opcua.security import PresidioSecurityError, SecurityPolicy

    print(f"[client] Connecting to {args.endpoint} (security={args.security})")

    if args.security == "None":
        policy = SecurityPolicy(allow_no_security=True)
        client = HardenedClient(args.endpoint, security_policy=policy)
    else:
        # Validate certificate before attempting connection
        cert_path = Path(args.cert) if args.cert else CERTS_DIR / "client_cert.der"
        key_path = Path(args.key) if args.key else CERTS_DIR / "client_key.pem"
        server_cert = CERTS_DIR / "server_cert.pem"

        # allow_self_signed=False → rejects any self-signed cert (including untrusted_cert.der)
        policy = SecurityPolicy(allow_self_signed=False, allow_no_security=False)
        client = HardenedClient(args.endpoint, security_policy=policy)
        try:
            sec_string = f"Basic256Sha256,{args.security},{cert_path},{key_path},{server_cert}"
            client.set_security_string(sec_string)
        except (PresidioSecurityError, ValueError) as exc:
            print(f"\n[client] REJECTED by Presidio security policy: {exc}")
            print("[client] This simulates BadCertificateUntrusted from the server.")
            sys.exit(1)

    t0 = time.monotonic()
    try:
        client.connect()
    except Exception as exc:  # noqa: BLE001
        print(f"[client] Connection failed: {exc}")
        sys.exit(1)

    elapsed_ms = (time.monotonic() - t0) * 1000
    print(f"[client] Connected in {elapsed_ms:.1f} ms")

    # Read demo tags
    try:
        root = client.get_objects_node()
        process = None
        for child in root.get_children():
            try:
                if "DemoProcess" in child.get_browse_name().Name:
                    process = child
                    break
            except Exception:  # noqa: BLE001
                pass

        if process is None:
            print("[client] DemoProcess node not found.")
        else:
            print("\n[client] Process tag values:")
            for var in process.get_children():
                try:
                    name = var.get_browse_name().Name
                    value = var.get_value()
                    print(f"  {name:<30} = {value}")
                except Exception:  # noqa: BLE001
                    pass
    except Exception as exc:  # noqa: BLE001
        print(f"[client] Error reading tags: {exc}")
    finally:
        client.disconnect()
        print("[client] Disconnected.")


# ---------------------------------------------------------------------------
# Benchmark
# ---------------------------------------------------------------------------
def cmd_benchmark(args) -> None:
    from presidio_opcua.client import HardenedClient
    from presidio_opcua.security import SecurityPolicy

    endpoint = args.endpoint
    n = 5
    print(f"[benchmark] Measuring connection time ({n} rounds) to {endpoint}")
    print()

    # --- None mode ---
    times_none = []
    policy = SecurityPolicy(allow_no_security=True)
    for _ in range(n):
        client = HardenedClient(endpoint, security_policy=policy)
        t0 = time.monotonic()
        try:
            client.connect()
            times_none.append((time.monotonic() - t0) * 1000)
            client.disconnect()
        except Exception:  # noqa: BLE001
            times_none.append(float("nan"))

    avg_none = sum(t for t in times_none if t == t) / max(sum(1 for t in times_none if t == t), 1)

    # --- SignAndEncrypt mode (only if certs exist) ---
    avg_sec = None
    server_cert = CERTS_DIR / "server_cert.pem"
    client_cert = CERTS_DIR / "client_cert.der"
    client_key = CERTS_DIR / "client_key.pem"
    if server_cert.exists() and client_cert.exists():
        times_sec = []
        policy_sec = SecurityPolicy(allow_self_signed=False, allow_no_security=False)
        for _ in range(n):
            client = HardenedClient(endpoint, security_policy=policy_sec)
            try:
                sec_str = f"Basic256Sha256,SignAndEncrypt,{client_cert},{client_key},{server_cert}"
                client.set_security_string(sec_str)
                t0 = time.monotonic()
                client.connect()
                times_sec.append((time.monotonic() - t0) * 1000)
                client.disconnect()
            except Exception:  # noqa: BLE001
                times_sec.append(float("nan"))
        avg_sec = sum(t for t in times_sec if t == t) / max(sum(1 for t in times_sec if t == t), 1)

    print(f"  None mode avg connection time:             {avg_none:>8.1f} ms")
    if avg_sec is not None:
        print(f"  SignAndEncrypt mode avg connection time:   {avg_sec:>8.1f} ms")
        overhead = avg_sec - avg_none
        print(f"  Overhead of TLS + certificate exchange:    {overhead:>8.1f} ms")
    else:
        print("  SignAndEncrypt: certs not found — run --gen-certs and start a secure server.")
    print()
    print("  IEC 62443 note: None mode achieves SL 0 (no authentication).")
    print("  SignAndEncrypt achieves SL 2+ (mutual authentication, encrypted channel).")


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(
        description="presidio-hardened-opcua demo — PRES-EDU-CSM-101 Experiment 1"
    )
    parser.add_argument("--mode", choices=["server", "client"], help="Run as server or client")
    parser.add_argument(
        "--security",
        choices=["None", "Sign", "SignAndEncrypt"],
        default="SignAndEncrypt",
        help="OPC-UA security mode",
    )
    parser.add_argument("--port", type=int, default=4840, help="Server port (default: 4840)")
    parser.add_argument(
        "--endpoint", default="opc.tcp://localhost:4840", help="Server endpoint URL"
    )
    parser.add_argument("--cert", help="Client certificate path (.der)")
    parser.add_argument("--key", help="Client private key path (.pem)")
    parser.add_argument("--gen-certs", action="store_true", help="Generate demo certificates")
    parser.add_argument(
        "--benchmark", action="store_true", help="Benchmark connection time per mode"
    )

    args = parser.parse_args()

    if args.gen_certs:
        cmd_gen_certs(args)
    elif args.benchmark:
        cmd_benchmark(args)
    elif args.mode == "server":
        cmd_server(args)
    elif args.mode == "client":
        cmd_client(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
