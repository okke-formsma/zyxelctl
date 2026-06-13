# zyxelctl

A small Python client for the **Zyxel router web configurator** API.

Modern Zyxel routers (the single-page "Web-Based Configurator") encrypt their
API traffic: the browser fetches the router's RSA public key, generates a random
AES-256 session key, sends the login credentials AES-encrypted with that key
RSA-encrypted, and then reuses the AES key for every subsequent request and
response. `zyxelctl` replicates that handshake so you can script the router.

Right now it does two things: **log in** and **manage port-forward rules**
(list / add / update / enable / disable / reset / delete). It was built to work
around a Zyxel bug where a port-forward silently stops working until the rule is
toggled off and on again.

> Tested against a Zyxel gateway exposing `/getRSAPublickKey`, `/UserLogin` and
> `/cgi-bin/DAL?oid=nat`. Other models using the same web UI should work; YMMV.

## Install

Not on PyPI — install from GitHub:

```bash
pip install git+https://github.com/okke-formsma/zyxelctl
```

Or clone and install in editable mode for development:

```bash
git clone https://github.com/okke-formsma/zyxelctl
cd zyxelctl
pip install -e .
```

## Library usage

```python
from zyxelctl import ZyxelRouter

with ZyxelRouter("http://192.168.1.1", "admin", "password") as router:
    # List all port-forward rules
    for rule in router.get_port_forwards():
        print(rule["Index"], rule["Description"], rule["Enable"])

    # Add a new rule (the router assigns its Index; protocol is TCP/UDP/ALL)
    router.add_port_forward(
        description="web", internal_client="192.168.1.10",
        external_port=80, protocol="TCP",
    )

    # Modify fields of an existing rule (raw rule keys, as returned by list)
    router.update_port_forward({"InternalClient": "192.168.1.20"}, description="web")

    # Toggle a rule off then on (the workaround for Zyxel dropping the forward)
    router.reset_port_forward(description="web")

    # Or set state directly
    router.set_port_forward_enabled(False, index=3)
    router.set_port_forward_enabled(True, index=3)

    # Delete a rule
    router.delete_port_forward(description="web")
```

Rules can be matched by `index`, `description`, and/or `internal_client` (the
LAN IP the rule forwards to). At least one is required; if several rules match,
narrow it (e.g. add `index=`).

## Command line

```bash
# Credentials via flags or the ZYXEL_HOST / ZYXEL_USER / ZYXEL_PASSWORD env vars
export ZYXEL_HOST=http://192.168.1.1
export ZYXEL_USER=admin
export ZYXEL_PASSWORD=secret

zyxelctl list
zyxelctl add --description web --client 192.168.1.10 --external-port 80 --protocol TCP
zyxelctl update --description web --set InternalClient=192.168.1.20
zyxelctl reset --description web
zyxelctl disable --index 3
zyxelctl enable  --index 3
zyxelctl delete --description web
```

`add` takes `--internal-port` (defaults to the external port), `--external-port-end`
/ `--internal-port-end` for ranges, `--interface` (defaults to the WAN interface
of existing rules), and `--disabled` to create it switched off. `update` selects a
rule the same way the other commands do (`--index` / `--description` / `--client`)
and overwrites the `--set KEY=VALUE` fields — keys are the raw rule keys shown by
`list` (values are coerced to int / bool / str).

### Hourly reset with cron

```cron
17 * * * * ZYXEL_PASSWORD=secret /usr/bin/zyxelctl reset --description web >> /var/log/zyxelctl.log 2>&1
```

## How it works

| Step | Detail |
|------|--------|
| Public key | `GET /getRSAPublickKey` → PEM RSA public key |
| Login | `POST /UserLogin` with `{iv, key, content}`: `content` = AES-256-CBC/PKCS7 of the creds JSON; `key` = RSA-PKCS1v15 of **base64(aes_key)**; password is base64-encoded inside the creds |
| Session | Response is AES-encrypted `{content, iv}`, decrypted with the same key → `sessionkey` + `Session` cookie |
| Data access | `GET/PUT /cgi-bin/DAL?oid=nat` reuse the session AES key (fresh IV, `{content, iv}` body). Writes send the rotating `sessionkey` as the `CSRFToken` header |

## Disclaimer

Not affiliated with or endorsed by Zyxel. Use at your own risk, on equipment you
own. The API was reverse-engineered from the router's own web UI.

## License

MIT — see [LICENSE](LICENSE).
