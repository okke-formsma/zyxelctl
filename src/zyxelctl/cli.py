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


def _coerce(value: str):
    """Turn a CLI string into int / bool / str so rule fields get sane types."""
    if value.lower() in ("true", "false"):
        return value.lower() == "true"
    try:
        return int(value)
    except ValueError:
        return value


def _parse_set(pairs: list[str] | None) -> dict:
    """Parse repeated ``--set KEY=VALUE`` flags into a dict of typed changes."""
    changes: dict = {}
    for item in pairs or []:
        if "=" not in item:
            raise SystemExit(f"--set expects KEY=VALUE, got {item!r}")
        key, value = item.split("=", 1)
        changes[key] = _coerce(value)
    return changes


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

    p_add = sub.add_parser("add", help="add a new port-forward rule")
    p_add.add_argument("--description", required=True, help="rule name")
    p_add.add_argument(
        "--client", dest="internal_client", required=True, help="forwarded-to LAN IP"
    )
    p_add.add_argument(
        "--external-port", type=int, required=True, help="WAN port to forward"
    )
    p_add.add_argument(
        "--internal-port", type=int, help="LAN port (default: same as external)"
    )
    p_add.add_argument(
        "--protocol", default="ALL", choices=["TCP", "UDP", "ALL"],
        help="ALL = TCP+UDP (default)",
    )
    p_add.add_argument("--external-port-end", type=int, help="end of WAN port range")
    p_add.add_argument("--internal-port-end", type=int, help="end of LAN port range")
    p_add.add_argument("--interface", help="WAN interface (default: from existing rules)")
    p_add.add_argument(
        "--disabled", action="store_true", help="create the rule disabled"
    )

    p_update = sub.add_parser("update", help="modify fields of an existing rule")
    _add_selectors(p_update)
    p_update.add_argument(
        "--set", dest="sets", action="append", metavar="KEY=VALUE",
        help="rule field to change (repeatable), e.g. --set Protocol=ALL",
    )

    p_delete = sub.add_parser("delete", help="delete a port-forward rule")
    _add_selectors(p_delete)

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
            elif args.command == "add":
                rule = router.add_port_forward(
                    description=args.description,
                    internal_client=args.internal_client,
                    external_port=args.external_port,
                    internal_port=args.internal_port,
                    protocol=args.protocol,
                    external_port_end=args.external_port_end,
                    internal_port_end=args.internal_port_end,
                    interface=args.interface,
                    enable=not args.disabled,
                )
                print(f"added: {rule['Description']} {rule['Protocol']} "
                      f"{rule['ExternalPortStart']}->{rule['InternalClient']}:"
                      f"{rule['InternalPortStart']}")
            elif args.command == "update":
                changes = _parse_set(args.sets)
                if not changes:
                    print("error: nothing to change (pass --set KEY=VALUE)",
                          file=sys.stderr)
                    return 2
                rule = router.update_port_forward(changes, **_selectors(args))
                print(f"updated: rule {rule.get('Index')} "
                      f"({rule.get('Description')}) {changes}")
            elif args.command == "delete":
                rule = router.delete_port_forward(**_selectors(args))
                print(f"deleted: rule {rule.get('Index')} ({rule.get('Description')})")
    except ZyxelError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
