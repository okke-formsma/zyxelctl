"""Command-line interface for zyxelctl."""

from __future__ import annotations

import argparse
import json
import os
import sys

from .client import ZyxelError, ZyxelRouter


def _add_selectors(p: argparse.ArgumentParser) -> None:
    p.add_argument("--index", type=int, help="rule index")
    p.add_argument("--description", help="rule name/description")
    p.add_argument("--client", dest="internal_client", help="forwarded-to LAN IP")


def _selectors(args: argparse.Namespace) -> dict:
    return dict(
        index=args.index,
        description=args.description,
        internal_client=args.internal_client,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="zyxelctl", description="Control a Zyxel router (login + port forwards)."
    )
    parser.add_argument(
        "--host",
        default=os.environ.get("ZYXEL_HOST", "http://192.168.1.1"),
        help="router base URL (env ZYXEL_HOST, default http://192.168.1.1)",
    )
    parser.add_argument(
        "--user",
        default=os.environ.get("ZYXEL_USER", "admin"),
        help="username (env ZYXEL_USER, default admin)",
    )
    parser.add_argument(
        "--password",
        default=os.environ.get("ZYXEL_PASSWORD"),
        help="password (env ZYXEL_PASSWORD)",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="do not verify TLS certificates",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="list port-forward rules")

    p_reset = sub.add_parser(
        "reset", help="toggle a port-forward rule off then on (the Zyxel fix)"
    )
    _add_selectors(p_reset)

    p_enable = sub.add_parser("enable", help="enable a port-forward rule")
    _add_selectors(p_enable)

    p_disable = sub.add_parser("disable", help="disable a port-forward rule")
    _add_selectors(p_disable)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.password:
        print("error: no password (pass --password or set ZYXEL_PASSWORD)", file=sys.stderr)
        return 2

    try:
        with ZyxelRouter(
            args.host, args.user, args.password, verify_tls=not args.insecure
        ) as router:
            if args.command == "list":
                rules = router.get_port_forwards()
                print(json.dumps(rules, indent=2))
            elif args.command == "reset":
                rule = router.reset_port_forward(**_selectors(args))
                print(f"reset OK: rule {rule.get('Index')} "
                      f"({rule.get('Description')}) Enable={rule.get('Enable')}")
            elif args.command == "enable":
                router.set_port_forward_enabled(True, **_selectors(args))
                print("enabled")
            elif args.command == "disable":
                router.set_port_forward_enabled(False, **_selectors(args))
                print("disabled")
    except ZyxelError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
