"""Client for the Zyxel web configurator API (RSA + AES encrypted)."""

from __future__ import annotations

import base64
import json
import os
import time
from typing import Any

import requests
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.serialization import load_pem_public_key

__all__ = [
    "ZyxelRouter",
    "ZyxelError",
    "LoginError",
    "RuleNotFoundError",
]


class ZyxelError(Exception):
    """Base error for all zyxelctl failures."""


class LoginError(ZyxelError):
    """Authentication with the router failed."""


class RuleNotFoundError(ZyxelError):
    """No port-forward rule matched the given criteria."""


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _aes_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> str:
    """AES-256-CBC + PKCS7, returned as base64 (matches the router's CryptoJS)."""
    padder = PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return _b64(encryptor.update(padded) + encryptor.finalize())


def _aes_decrypt(b64_ciphertext: str, key: bytes, iv: bytes) -> bytes:
    raw = base64.b64decode(b64_ciphertext)
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(raw) + decryptor.finalize()
    unpadder = PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


class ZyxelRouter:
    """A logged-in session to a Zyxel router's web configurator.

    The web UI fetches the router's RSA public key, generates a random AES-256
    session key, and sends the credentials encrypted with AES while the AES key
    itself is RSA-encrypted. That same AES key is then reused for every
    subsequent ``/cgi-bin/DAL`` request and response; a rotating ``sessionkey``
    is sent as the ``CSRFToken`` header on writes. This client replicates that.

    Example::

        with ZyxelRouter("http://192.168.1.1", "admin", "secret") as router:
            router.reset_port_forward(description="seedbox")
    """

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        *,
        timeout: float = 15.0,
        verify_tls: bool = True,
    ) -> None:
        self.host = host.rstrip("/")
        self.username = username
        self.password = password
        self.timeout = timeout
        self._session = requests.Session()
        self._session.verify = verify_tls
        self._aes_key: bytes | None = None
        self._sessionkey: str | None = None

    # -- session lifecycle -------------------------------------------------

    def login(self) -> "ZyxelRouter":
        """Authenticate. Returns ``self`` so it can be chained."""
        pem = self._get("/getRSAPublickKey").json()["RSAPublicKey"]
        public_key = load_pem_public_key(pem.encode())

        key = os.urandom(32)
        iv = os.urandom(16)
        creds = json.dumps(
            {
                "Input_Account": self.username,
                "Input_Passwd": _b64(self.password.encode()),
                "currLang": "en",
                "RememberPassword": 0,
                "SHA512_password": False,
            }
        ).encode()

        encrypted_key = public_key.encrypt(_b64(key).encode(), asym_padding.PKCS1v15())
        body = {
            "iv": _b64(iv),
            "key": _b64(encrypted_key),
            "content": _aes_encrypt(creds, key, iv),
        }
        resp = self._session.post(
            f"{self.host}/UserLogin", json=body, timeout=self.timeout
        )
        data = self._decrypt_response(resp, key)
        if data.get("result") != "ZCFG_SUCCESS":
            raise LoginError(data.get("result") or "login failed")
        self._aes_key = key
        self._sessionkey = data.get("sessionkey")
        return self

    @property
    def logged_in(self) -> bool:
        return self._aes_key is not None

    # -- port forwards -----------------------------------------------------

    def get_port_forwards(self) -> list[dict[str, Any]]:
        """Return all port-forward (NAT) rules as a list of dicts."""
        return self._dal_get("nat").get("Object", [])

    def set_port_forward_enabled(
        self,
        enabled: bool,
        *,
        index: int | None = None,
        description: str | None = None,
        internal_client: str | None = None,
    ) -> dict[str, Any]:
        """Enable or disable a single port-forward rule.

        Identify the rule by ``index`` (the router's rule index), ``description``
        (its name), and/or ``internal_client`` (the LAN IP it forwards to). At
        least one criterion is required; all given must match.
        """
        rule = self._find_rule(
            self.get_port_forwards(),
            index=index,
            description=description,
            internal_client=internal_client,
        )
        updated = dict(rule)
        updated["Enable"] = enabled
        data = self._dal_put("nat", updated)
        if data.get("result") != "ZCFG_SUCCESS":
            raise ZyxelError(f"failed to update rule: {data.get('result')}")
        return updated

    def reset_port_forward(
        self,
        *,
        index: int | None = None,
        description: str | None = None,
        internal_client: str | None = None,
        delay: float = 3.0,
    ) -> dict[str, Any]:
        """Toggle a rule off then on (the workaround for Zyxel dropping it).

        Returns the rule after re-enabling. Raises if it does not come back
        enabled.
        """
        criteria = dict(
            index=index, description=description, internal_client=internal_client
        )
        self.set_port_forward_enabled(False, **criteria)
        time.sleep(delay)
        self.set_port_forward_enabled(True, **criteria)
        time.sleep(delay)
        rule = self._find_rule(self.get_port_forwards(), **criteria)
        if not rule.get("Enable"):
            raise ZyxelError("rule did not come back enabled after reset")
        return rule

    def add_port_forward(
        self,
        *,
        description: str,
        internal_client: str,
        external_port: int,
        internal_port: int | None = None,
        protocol: str = "ALL",
        external_port_end: int | None = None,
        internal_port_end: int | None = None,
        interface: str | None = None,
        enable: bool = True,
        set_remote_ip: bool = False,
        remote_host: str = "",
        auto_detect_wan_status: bool = False,
    ) -> dict[str, Any]:
        """Create a new port-forward rule (the router assigns its ``Index``).

        ``protocol`` is one of ``"TCP"``, ``"UDP"`` or ``"ALL"`` (TCP+UDP).
        ``internal_port`` defaults to ``external_port``; the ``*_end`` arguments
        default to their respective start, i.e. a single-port forward.
        ``interface`` is the WAN interface (e.g. ``"IP.Interface.4"``); if
        omitted it is taken from the existing rules.

        Returns the rule that was sent.
        """
        if interface is None:
            existing = self.get_port_forwards()
            if not existing:
                raise ZyxelError(
                    "cannot infer interface (no existing rules); pass interface="
                )
            interface = existing[0]["Interface"]

        ext_end = external_port if external_port_end is None else external_port_end
        int_start = external_port if internal_port is None else internal_port
        int_end = int_start if internal_port_end is None else internal_port_end

        rule = {
            "Enable": enable,
            "Protocol": protocol,
            "Description": description,
            "Interface": interface,
            "ExternalPortStart": external_port,
            "ExternalPortEnd": ext_end,
            "InternalPortStart": int_start,
            "InternalPortEnd": int_end,
            "InternalClient": internal_client,
            "SetRemoteIP": set_remote_ip,
            "RemoteHost": remote_host,
            "X_ZYXEL_AutoDetectWanStatus": auto_detect_wan_status,
        }
        data = self._dal_post("nat", rule)
        if data.get("result") != "ZCFG_SUCCESS":
            raise ZyxelError(f"failed to add rule: {data.get('result')}")
        return rule

    def update_port_forward(
        self,
        changes: dict[str, Any],
        *,
        index: int | None = None,
        description: str | None = None,
        internal_client: str | None = None,
    ) -> dict[str, Any]:
        """Modify fields of an existing rule.

        Select the rule by ``index`` / ``description`` / ``internal_client``,
        then overwrite the keys in ``changes`` (raw Zyxel rule keys, e.g.
        ``{"Protocol": "ALL", "ExternalPortStart": 6881}`` — the same keys
        ``get_port_forwards()`` returns). Returns the updated rule.
        """
        if not changes:
            raise ValueError("changes must be a non-empty dict of rule fields")
        rule = self._find_rule(
            self.get_port_forwards(),
            index=index,
            description=description,
            internal_client=internal_client,
        )
        updated = dict(rule)
        updated.update(changes)
        data = self._dal_put("nat", updated)
        if data.get("result") != "ZCFG_SUCCESS":
            raise ZyxelError(f"failed to update rule: {data.get('result')}")
        return updated

    def delete_port_forward(
        self,
        *,
        index: int | None = None,
        description: str | None = None,
        internal_client: str | None = None,
    ) -> dict[str, Any]:
        """Delete a single port-forward rule (matched like the others).

        Returns the rule that was deleted.
        """
        rule = self._find_rule(
            self.get_port_forwards(),
            index=index,
            description=description,
            internal_client=internal_client,
        )
        data = self._dal_delete("nat", Index=rule["Index"])
        if data.get("result") != "ZCFG_SUCCESS":
            raise ZyxelError(f"failed to delete rule: {data.get('result')}")
        return rule

    # -- internals ---------------------------------------------------------

    @staticmethod
    def _find_rule(
        rules: list[dict[str, Any]],
        *,
        index: int | None,
        description: str | None,
        internal_client: str | None,
    ) -> dict[str, Any]:
        if index is None and description is None and internal_client is None:
            raise ValueError(
                "specify at least one of index, description, internal_client"
            )
        matches = [
            r
            for r in rules
            if (index is None or r.get("Index") == index)
            and (description is None or r.get("Description") == description)
            and (internal_client is None or r.get("InternalClient") == internal_client)
        ]
        if not matches:
            raise RuleNotFoundError(
                f"no rule matched index={index!r} description={description!r} "
                f"internal_client={internal_client!r}"
            )
        if len(matches) > 1:
            raise ZyxelError(
                f"{len(matches)} rules matched; narrow the criteria "
                f"(e.g. add index=)"
            )
        return matches[0]

    def _get(self, path: str) -> requests.Response:
        return self._session.get(f"{self.host}{path}", timeout=self.timeout)

    def _decrypt_response(
        self, resp: requests.Response, key: bytes | None = None
    ) -> dict[str, Any]:
        key = key or self._aes_key
        if key is None:
            raise ZyxelError("not logged in")
        obj = resp.json()
        if isinstance(obj, dict) and "content" in obj and "iv" in obj:
            iv = base64.b64decode(obj["iv"])[:16]
            return json.loads(_aes_decrypt(obj["content"], key, iv))
        return obj

    def _dal_get(self, oid: str) -> dict[str, Any]:
        self._require_login()
        resp = self._session.get(
            f"{self.host}/cgi-bin/DAL?oid={oid}", timeout=self.timeout
        )
        return self._decrypt_response(resp)

    def _csrf_headers(self) -> dict[str, str]:
        return {"CSRFToken": self._sessionkey} if self._sessionkey else {}

    def _track_sessionkey(self, data: dict[str, Any]) -> dict[str, Any]:
        # The sessionkey rotates on every write; keep the latest for the next one.
        if data.get("sessionkey"):
            self._sessionkey = data["sessionkey"]
        return data

    def _dal_write(self, method: str, oid: str, obj: dict[str, Any]) -> dict[str, Any]:
        """``POST`` (create) or ``PUT`` (edit) an object on the DAL endpoint.

        The body is the object AES-encrypted to ``{content, iv}`` with the
        session key, exactly as the web UI does for writes.
        """
        self._require_login()
        iv = os.urandom(16)
        body = {
            "content": _aes_encrypt(json.dumps(obj).encode(), self._aes_key, iv),
            "iv": _b64(iv),
        }
        resp = self._session.request(
            method,
            f"{self.host}/cgi-bin/DAL?oid={oid}",
            json=body,
            headers=self._csrf_headers(),
            timeout=self.timeout,
        )
        return self._track_sessionkey(self._decrypt_response(resp))

    def _dal_put(self, oid: str, obj: dict[str, Any]) -> dict[str, Any]:
        return self._dal_write("PUT", oid, obj)

    def _dal_post(self, oid: str, obj: dict[str, Any]) -> dict[str, Any]:
        return self._dal_write("POST", oid, obj)

    def _dal_delete(self, oid: str, **params: Any) -> dict[str, Any]:
        """``DELETE`` on the DAL endpoint. Selectors (e.g. ``Index=3``) go in
        the query string — the web UI sends no body for deletes."""
        self._require_login()
        url = f"{self.host}/cgi-bin/DAL?oid={oid}"
        for key, value in params.items():
            url += f"&{key}={value}"
        resp = self._session.delete(
            url, headers=self._csrf_headers(), timeout=self.timeout
        )
        return self._track_sessionkey(self._decrypt_response(resp))

    def _require_login(self) -> None:
        if not self.logged_in:
            raise ZyxelError("call login() first")

    # -- context manager ---------------------------------------------------

    def __enter__(self) -> "ZyxelRouter":
        return self.login()

    def __exit__(self, *exc: object) -> None:
        self._session.close()
