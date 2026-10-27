"""TLS certificates of https services: who issued them, for which names, and when they expire."""
from __future__ import annotations

import datetime as dt
import hashlib
import socket
import ssl
from urllib.parse import urlsplit

from labdex.plugins.base import Plugin as Base


def _now():
    return dt.datetime.now(dt.UTC)


def fetch(host: str, port: int, sni: str, timeout: float) -> dict:
    """The leaf certificate (even an invalid one) and whether it verifies against the system CAs."""
    from cryptography import x509
    from cryptography.x509.oid import ExtensionOID, NameOID
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname=sni or None) as tls:
            der = tls.getpeercert(binary_form=True)
    cert = x509.load_der_x509_certificate(der)
    try:
        sans = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []
    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    icn = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
    io = cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
    out = {"subject": cn[0].value if cn else cert.subject.rfc4514_string(), "sans": sans,
           "issuer": (icn[0].value if icn else "") + (f" ({io[0].value})" if io else ""),
           "not_before": cert.not_valid_before_utc.isoformat(), "not_after": cert.not_valid_after_utc.isoformat(),
           "self_signed": cert.issuer == cert.subject, "sha256": hashlib.sha256(der).hexdigest()}
    # does it verify (chain and name), the way a browser would?
    vctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with vctx.wrap_socket(raw, server_hostname=sni or host):
                pass
        out["trusted"], out["problem"] = True, ""
    except ssl.SSLCertVerificationError as exc:
        out["trusted"], out["problem"] = False, exc.verify_message or str(exc)
    except (ssl.SSLError, OSError) as exc:
        out["trusted"], out["problem"] = False, str(exc)
    return out


class Plugin(Base):
    def _targets(self) -> list[dict]:
        """Every https service (by its link, or its addresses) plus the extra endpoints."""
        from labdex import store
        from labdex.models import Host, db
        out, seen = [], set()
        for h in db.session.scalars(db.select(Host).where(Host.status != "offline").order_by(Host.name)):
            for s in h.services:
                if s.scheme != "https":
                    continue
                url = store.service_url(h, s)
                u = urlsplit(url) if url else None
                if u and u.hostname:
                    host, port, sni = u.hostname, u.port or 443, u.hostname if not _is_ip(u.hostname) else ""
                else:
                    addrs = store.service_addresses(h, s)
                    if not addrs:
                        continue
                    host, port, sni = addrs[0], s.port or 443, ""
                key = f"{host}:{port}"
                if key not in seen:
                    seen.add(key)
                    out.append({"key": key, "host": host, "port": port, "sni": sni, "inv_host": h.name, "service": s.name})
        for e in self.settings.get("extra") or []:
            u = urlsplit(e if "://" in e else f"https://{e}")
            if not u.hostname:
                continue
            key = f"{u.hostname}:{u.port or 443}"
            if key not in seen:
                seen.add(key)
                out.append({"key": key, "host": u.hostname, "port": u.port or 443, "sni": "" if _is_ip(u.hostname) else u.hostname,
                            "inv_host": self.ctx.match_host()(u.hostname) or "", "service": ""})
        return out

    def _level(self, days: float | None) -> str:
        if days is None:
            return "err"
        if days < int(self.settings.get("critical_days") or 7):
            return "err"
        if days < int(self.settings.get("warn_days") or 21):
            return "warn"
        return "ok"

    def run_check(self, params):
        timeout = float(self.settings.get("timeout") or 5)
        old = self.ctx.state.get("certs", {})
        certs, problems = {}, 0
        for t in self._targets():
            entry = {k: t[k] for k in ("host", "port", "sni", "inv_host", "service")} | {"checked_at": _now().isoformat()}
            try:
                entry |= fetch(t["host"], t["port"], t["sni"], timeout)
                left = (dt.datetime.fromisoformat(entry["not_after"]) - _now()).total_seconds() / 86400
                entry["days_left"] = round(left, 1)
                entry["error"] = ""
            except Exception as exc:  # unreachable, not TLS, …
                entry |= {"error": _why(exc), "days_left": None}
                problems += 1
            level = self._level(entry["days_left"]) if not entry["error"] else "err"
            entry["level"] = level
            # notify once per certificate and level
            prev = old.get(t["key"], {})
            if not entry["error"] and level in ("warn", "err") and (prev.get("notified") != level or prev.get("sha256") != entry.get("sha256")):
                who = entry["inv_host"] or t["host"]
                self.ctx.notify("expiring", f"Certificate of {t['key']} expires in {int(entry['days_left'])} days",
                                f"{entry['subject']} on {who}, issued by {entry['issuer']}, valid until {entry['not_after'][:10]}",
                                f"/integrations/{self.ctx.name}?tab=certificates", {"endpoint": t["key"], "days_left": entry["days_left"]})
                entry["notified"] = level
            elif not entry["error"] and level == "ok":
                entry["notified"] = ""
            else:
                entry["notified"] = prev.get("notified", "")
            certs[t["key"]] = entry
            self.log(f"{t['key']}: " + (entry["error"] or f"{entry['subject']}, {entry['days_left']} days left" + ("" if entry["trusted"] else f" ({entry['problem']})")))
        self.ctx.set_state("certs", certs)
        expiring = sum(1 for c in certs.values() if c["level"] != "ok" and not c["error"])
        return {"checked": len(certs), "expiring": expiring, "unreachable": problems}

    # --------------------------------------------------------------- views
    def _rows(self, host: str | None = None):
        rows = sorted(self.ctx.state.get("certs", {}).items(), key=lambda kv: (kv[1].get("days_left") is None, kv[1].get("days_left") or 0))
        return [(k, c) for k, c in rows if host is None or c.get("inv_host") == host]

    def page_certificates(self, args):
        rows = self._rows()
        ok = sum(1 for _, c in rows if c.get("level") == "ok")
        return {"summary": [{"label": "certificates", "value": len(rows)},
                            {"label": "expiring", "value": sum(1 for _, c in rows if c.get("level") == "warn"), "tone": "warn"},
                            {"label": "critical or unreachable", "value": sum(1 for _, c in rows if c.get("level") == "err"), "tone": "err"},
                            {"label": "fine", "value": ok, "tone": "ok"}],
                "sections": [{"title": "Certificates", "type": "table",
                              "columns": [{"key": "endpoint", "label": "Endpoint"}, {"key": "host", "label": "Host"},
                                          {"key": "subject", "label": "For"}, {"key": "issuer", "label": "Issuer"},
                                          {"key": "expires", "label": "Expires"}, {"key": "left", "label": "Days left"},
                                          {"key": "trust", "label": "Trusted"}],
                              "rows": [{"endpoint": k, "host": c.get("inv_host") or "", "subject": c.get("subject") or c.get("error", ""),
                                        "issuer": c.get("issuer", ""), "expires": (c.get("not_after") or "")[:10],
                                        "left": "" if c.get("days_left") is None else int(c["days_left"]),
                                        "trust": "" if c.get("error") else "yes" if c.get("trusted") else (c.get("problem") or "no"),
                                        "_tone": {"ok": "", "warn": "warn", "err": "err"}[c.get("level", "err")]} for k, c in rows],
                              "empty": "Nothing checked yet: run “Check certificates”."}],
                "note": "Every https service of the inventory, plus the endpoints in the settings."}

    def widget_expiring(self, host):
        rows = self._rows()
        if not rows:
            return {"kind": "list", "items": [], "sub": "not checked yet", "link": f"/integrations/{self.ctx.name}?tab=certificates"}
        items = [{"label": k, "value": c["error"][:40] if c.get("error") else f"{int(c['days_left'])} d",
                  "tone": {"ok": "ok", "warn": "warn", "err": "err"}[c.get("level", "err")],
                  "link": f"/hosts/{c['inv_host']}" if c.get("inv_host") else ""} for k, c in rows[:8]]
        bad = sum(1 for _, c in rows if c.get("level") != "ok")
        return {"kind": "list", "items": items, "link": f"/integrations/{self.ctx.name}?tab=certificates",
                "sub": f"{len(rows)} checked, {bad} need attention" if bad else f"{len(rows)} checked, all fine"}

    def widget_host(self, host):
        rows = self._rows(host["name"])
        items = [{"label": f"{c.get('service') or k}", "value": c["error"][:40] if c.get("error") else f"{c.get('subject')} · {int(c['days_left'])} d",
                  "tone": {"ok": "ok", "warn": "warn", "err": "err"}[c.get("level", "err")]} for k, c in rows]
        return {"kind": "list", "items": items, "sub": "" if items else "no https service checked on this host"}


def _is_ip(s: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def _why(exc: Exception) -> str:
    if isinstance(exc, socket.gaierror):
        return "the name doesn't resolve"
    if isinstance(exc, ConnectionRefusedError):
        return "connection refused"
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return "no answer"
    if isinstance(exc, ssl.SSLError):
        return f"no TLS: {exc.reason or exc}"[:200]
    return f"{type(exc).__name__}: {exc}"[:200]
