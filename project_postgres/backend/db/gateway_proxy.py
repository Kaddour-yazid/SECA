import asyncio
import fnmatch
import json
import os
import time
from urllib import request as urlrequest
from urllib.error import URLError


LISTEN_HOST = os.environ.get("SECA_PROXY_LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("SECA_PROXY_LISTEN_PORT", "3128"))
SECA_API_BASE = os.environ.get("SECA_PROXY_API_BASE", "http://127.0.0.1:8000").rstrip("/")
LOG_URL = f"{SECA_API_BASE}/gateway/log"
BLOCKLIST_URL = f"{SECA_API_BASE}/gateway/blocklist/effective"
GATEWAY_TOKEN = os.environ.get("SECA_GATEWAY_INGEST_TOKEN", "").strip()
BLOCKLIST_REFRESH_SECONDS = int(os.environ.get("SECA_PROXY_BLOCKLIST_REFRESH_SECONDS", "10"))

_BLOCKLIST_CACHE = []
_BLOCKLIST_LAST_FETCH = 0.0

PROXY_BLOCKLIST_SHORTCUTS = {
    "yt": "youtube",
    "youtube": "youtube",
    "fb": "facebook",
    "facebook": "facebook",
    "ig": "instagram",
    "insta": "instagram",
    "instagram": "instagram",
    "wa": "whatsapp",
    "whatsapp": "whatsapp",
    "tw": "twitter",
    "twitter": "twitter",
    "x": "twitter",
}

PROXY_SERVICE_BLOCK_BUNDLES = {
    "youtube": ["*youtube*", "*ytimg*", "*googlevideo*", "*youtu.be*", "*yt3*"],
    "facebook": ["*facebook*", "*fbcdn*", "*fbsbx*", "*messenger*"],
    "instagram": ["*instagram*", "*cdninstagram*"],
    "twitter": ["*twitter*", "*twimg*", "*x.com*"],
    "whatsapp": ["*whatsapp*", "*whatsapp.net*", "*wa.me*"],
}

PROXY_SERVICE_DOMAIN_HINTS = {
    "youtube": ("youtube", "youtu.be", "ytimg", "googlevideo", "yt3"),
    "facebook": ("facebook", "fbcdn", "fbsbx", "messenger"),
    "instagram": ("instagram", "cdninstagram"),
    "twitter": ("twitter", "twimg", "x.com"),
    "whatsapp": ("whatsapp", "whatsapp.net", "wa.me"),
}


def _headers() -> dict:
    headers = {"Content-Type": "application/json"}
    if GATEWAY_TOKEN:
        headers["X-Gateway-Token"] = GATEWAY_TOKEN
    return headers


def _post_json_sync(url: str, payload: dict) -> None:
    data = json.dumps(payload).encode("utf-8")
    req = urlrequest.Request(url, data=data, headers=_headers(), method="POST")
    with urlrequest.urlopen(req, timeout=1.5):
        return


def _get_json_sync(url: str) -> dict:
    req = urlrequest.Request(url, headers=_headers(), method="GET")
    with urlrequest.urlopen(req, timeout=2.5) as resp:
        return json.loads(resp.read().decode("utf-8"))


async def get_blocklist_patterns() -> list[str]:
    global _BLOCKLIST_CACHE, _BLOCKLIST_LAST_FETCH

    now = time.time()
    if now - _BLOCKLIST_LAST_FETCH < BLOCKLIST_REFRESH_SECONDS:
        return _BLOCKLIST_CACHE

    try:
        data = await asyncio.to_thread(_get_json_sync, BLOCKLIST_URL)
        patterns = data.get("patterns") or []
        _BLOCKLIST_CACHE = [str(p).lower().strip() for p in patterns if str(p).strip()]
        _BLOCKLIST_LAST_FETCH = now
    except Exception:
        # Keep last known cache on backend/API outages.
        pass

    return _BLOCKLIST_CACHE


def _proxy_service_key_from_value(value: str) -> str | None:
    candidate = str(value or "").lower().strip().strip(".")
    if not candidate:
        return None

    shortcut = PROXY_BLOCKLIST_SHORTCUTS.get(candidate)
    if shortcut:
        return shortcut

    trimmed = candidate.lstrip("*.").replace("*", "").strip().strip(".")
    if not trimmed:
        return None

    for service_key, hints in PROXY_SERVICE_DOMAIN_HINTS.items():
        if trimmed == service_key:
            return service_key
        for hint in hints:
            normalized_hint = hint.lower().strip().strip(".")
            if (
                trimmed == normalized_hint
                or trimmed.endswith(f".{normalized_hint}")
                or normalized_hint in trimmed
            ):
                return service_key
    return None


def _pattern_variants(pattern: str) -> list[str]:
    candidate = str(pattern or "").lower().strip().strip(".")
    if not candidate:
        return []

    variants: list[str] = [candidate]
    trimmed = candidate.lstrip("*.").strip()
    if trimmed and trimmed != candidate:
        variants.append(trimmed)

    service_key = _proxy_service_key_from_value(candidate)
    if service_key:
        variants.extend(PROXY_SERVICE_BLOCK_BUNDLES.get(service_key, []))

    deduped: list[str] = []
    seen: set[str] = set()
    for item in variants:
        normalized = str(item).lower().strip().strip(".")
        if not normalized or normalized in seen:
            continue
        deduped.append(normalized)
        seen.add(normalized)
    return deduped


async def is_blocked(host: str) -> bool:
    host = (host or "").lower().strip().strip(".")
    if not host:
        return False
    patterns = await get_blocklist_patterns()
    for pat in patterns:
        for variant in _pattern_variants(pat):
            if fnmatch.fnmatch(host, variant) or fnmatch.fnmatch(host, variant.lstrip("*.")):
                return True
            legacy = variant.lstrip("*.").replace("*", "").strip()
            if legacy and "." not in legacy and legacy in host:
                return True
    return False


def send_log(evt: dict) -> None:
    evt.setdefault("device", "PC-CLIENT")
    evt.setdefault("audit", "realtime")
    evt.setdefault("company_mode", True)
    try:
        _post_json_sync(LOG_URL, evt)
    except Exception:
        pass


async def tunnel(c_reader, c_writer, u_reader, u_writer):
    async def pump(src, dst, peer_close=None):
        try:
            while True:
                data = await src.read(65536)
                if not data:
                    break
                dst.write(data)
                await dst.drain()
        except Exception:
            pass
        finally:
            try:
                dst.close()
            except Exception:
                pass
            if peer_close is not None:
                try:
                    peer_close.close()
                except Exception:
                    pass

    t1 = asyncio.create_task(pump(c_reader, u_writer, c_writer))
    t2 = asyncio.create_task(pump(u_reader, c_writer, u_writer))
    await asyncio.wait([t1, t2], return_when=asyncio.FIRST_COMPLETED)


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info("peername")
    client_ip = peer[0] if peer else "unknown"

    try:
        head = await reader.readuntil(b"\r\n\r\n")
    except Exception:
        writer.close()
        return

    try:
        lines = head.split(b"\r\n")
        first = lines[0].decode("utf-8", "ignore")
        method, target, _version = first.split(" ", 2)
    except Exception:
        writer.close()
        return

    method_u = method.upper()

    if method_u == "CONNECT":
        if ":" in target:
            host, p = target.split(":", 1)
            port = int(p)
        else:
            host, port = target, 443

        blocked = await is_blocked(host)
        asyncio.create_task(asyncio.to_thread(send_log, {
            "type": "proxy",
            "client_ip": client_ip,
            "method": "CONNECT",
            "host": host,
            "port": port,
            "blocked": blocked,
        }))

        if blocked:
            writer.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            await writer.drain()
            writer.close()
            return

        try:
            u_reader, u_writer = await asyncio.open_connection(host, port)
        except Exception:
            writer.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            await writer.drain()
            writer.close()
            return

        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()
        await tunnel(reader, writer, u_reader, u_writer)
        return

    headers = {}
    for ln in lines[1:]:
        if b":" in ln:
            k, v = ln.split(b":", 1)
            headers[k.decode("utf-8", "ignore").strip().lower()] = v.decode("utf-8", "ignore").strip()

    host = headers.get("host", "")
    port = 80
    if ":" in host:
        host, p = host.split(":", 1)
        try:
            port = int(p)
        except ValueError:
            port = 80

    blocked = await is_blocked(host)
    asyncio.create_task(asyncio.to_thread(send_log, {
        "type": "proxy",
        "client_ip": client_ip,
        "method": method_u,
        "host": host,
        "port": port,
        "target": target,
        "blocked": blocked,
    }))

    if blocked:
        body = b"Blocked by SECA gateway proxy\r\n"
        writer.write(
            b"HTTP/1.1 403 Forbidden\r\n"
            + f"Content-Length: {len(body)}\r\n".encode("ascii")
            + b"Content-Type: text/plain\r\n\r\n"
            + body
        )
        await writer.drain()
        writer.close()
        return

    try:
        u_reader, u_writer = await asyncio.open_connection(host, port)
    except Exception:
        writer.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
        await writer.drain()
        writer.close()
        return

    u_writer.write(head)
    await u_writer.drain()
    await tunnel(reader, writer, u_reader, u_writer)


async def main():
    server = await asyncio.start_server(handle_client, LISTEN_HOST, LISTEN_PORT)
    addrs = ", ".join(str(sock.getsockname()) for sock in (server.sockets or []))
    print(f"SECA gateway proxy listening on {addrs}")
    print(f"SECA API base: {SECA_API_BASE}")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
