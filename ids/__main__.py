"""CLI entrypoint:  python -m ids [--demo] [--iface eth0] [--port 8080]"""
from __future__ import annotations

import argparse

import uvicorn

from .config import config
from .server import create_app


def main() -> None:
    parser = argparse.ArgumentParser(description="Signature-based Network IDS")
    parser.add_argument("--iface", help="interface to capture on (default: scapy default)")
    parser.add_argument("--filter", help="BPF capture filter, e.g. 'not port 22'")
    parser.add_argument("--host", default=None, help="web bind host (default 0.0.0.0)")
    parser.add_argument("--port", type=int, default=None, help="web port (default 8080)")
    parser.add_argument("--demo", action="store_true", help="force synthetic demo traffic")
    parser.add_argument("--rules", help="path to rules JSON")
    args = parser.parse_args()

    if args.iface:
        config.interface = args.iface
    if args.filter:
        config.bpf_filter = args.filter
    if args.host:
        config.host = args.host
    if args.port:
        config.port = args.port
    if args.demo:
        config.demo = True
    if args.rules:
        from pathlib import Path
        config.rules_path = Path(args.rules)

    app = create_app(config)
    uvicorn.run(app, host=config.host, port=config.port, log_level="info")


if __name__ == "__main__":
    main()
