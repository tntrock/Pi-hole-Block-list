#!/usr/bin/env python3
"""匯總多份 Pi-hole 封鎖清單成單一檔案。

流程：下載來源 → 解析出網域 → 正規化 → 去重 → 套用白名單 → 輸出。
另外會：
  * 略過「太久沒更新」的來源（MAX_SOURCE_AGE_DAYS）
  * 下載失敗時改用上次快取（最多 STALE_CACHE_DAYS 天），避免單次網路問題讓清單縮水
  * 若總數相較上次驟減超過 MAX_SHRINK，直接失敗不發佈（保護你的 Pi-hole）
  * 產生 report.md 說明每個來源的狀態、貢獻數量、白名單命中情形

只用 Python 標準函式庫，不需安裝任何套件。
"""
from __future__ import annotations

import concurrent.futures as cf
import csv
import datetime as dt
import hashlib
import io
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = Path(os.environ.get("OUT_DIR", ROOT / "out"))
CACHE = Path(os.environ.get("CACHE_DIR", ROOT / ".cache"))
PREV_STATE = Path(os.environ.get("PREV_STATE", OUT / "state.json"))

MAX_SOURCE_AGE_DAYS = int(os.environ.get("MAX_SOURCE_AGE_DAYS", "365"))
STALE_CACHE_DAYS = int(os.environ.get("STALE_CACHE_DAYS", "7"))
MAX_SHRINK = float(os.environ.get("MAX_SHRINK", "0.30"))
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
UA = "Mozilla/5.0 (compatible; pihole-blocklist-aggregator)"

NOW = dt.datetime.now(dt.timezone.utc)
TW = dt.timezone(dt.timedelta(hours=8))

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+"
    r"(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$"
)
IP_RE = re.compile(r"^(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f:]*:[0-9a-f:]*)$")
HOSTS_IPS = {"0.0.0.0", "127.0.0.1", "::", "::1", "0", "255.255.255.255"}
JUNK = {
    "localhost", "localhost.localdomain", "local", "broadcasthost", "ip6-localhost",
    "ip6-loopback", "ip6-localnet", "ip6-mcastprefix", "ip6-allnodes",
    "ip6-allrouters", "ip6-allhosts", "0.0.0.0",
}
ABP_RE = re.compile(r"^(@@)?\|\|([^\^/$|]+)\^(\$(.*))?$")


# ───────────────────────────── 解析 ─────────────────────────────

def normalize(d: str) -> str | None:
    d = d.strip().strip(".").lower()
    if not d or d in JUNK or IP_RE.match(d):
        return None
    if not d.isascii():
        try:
            d = d.encode("idna").decode("ascii")
        except UnicodeError:
            return None
    return d if DOMAIN_RE.match(d) else None


def parse_block(text: str, fmt: str | None) -> set[str]:
    """把來源內容解析成網域集合（精確比對語意，跟 Pi-hole 一致）。"""
    out: set[str] = set()
    if fmt and fmt.startswith("csv:"):
        col = int(fmt[4:]) - 1
        rows = csv.reader(io.StringIO(text.lstrip("﻿")))
        next(rows, None)  # 標題列
        for row in rows:
            if len(row) > col:
                cell = row[col].strip()
                # 欄位可能是完整網址
                if "://" in cell:
                    cell = urllib.parse.urlsplit(cell).hostname or ""
                cell = cell.split("/")[0].split(":")[0]
                if (d := normalize(cell)):
                    out.add(d)
        return out

    for line in text.splitlines():
        line = line.strip()
        if not line or line[0] in "#![":
            continue
        m = ABP_RE.match(line)
        if m:
            if m.group(1):  # @@ 例外規則，不是封鎖
                continue
            opts = m.group(4)
            if opts and opts not in ("important", "all", "document"):
                continue  # 帶限定條件的規則，DNS 層無法對應
            if "*" in m.group(2):
                continue
            if (d := normalize(m.group(2))):
                out.add(d)
            continue
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if parts[0] in HOSTS_IPS or IP_RE.match(parts[0]):
            parts = parts[1:]
        elif len(parts) > 1:
            continue  # 不認得的格式，寧可略過也不要亂擋
        for p in parts:
            if "*" in p or "/" in p:
                continue
            if (d := normalize(p)):
                out.add(d)
    return out


@dataclass
class Allow:
    exact: set[str] = field(default_factory=set)
    suffix: set[str] = field(default_factory=set)  # 網域本身 + 所有子網域
    globs: list[str] = field(default_factory=list)

    def add_line(self, raw: str) -> None:
        line = raw.split("#", 1)[0].strip() if not raw.lstrip().startswith("@@") else raw.strip()
        if not line or line[0] in "![":
            return
        m = ABP_RE.match(line)
        if m:
            pat = m.group(2).lower()
            if pat.startswith("*."):
                pat = pat[2:]
            if "*" in pat:
                self.globs.append(pat)
            elif (d := normalize(pat)):
                self.suffix.add(d)
            return
        tok = line.split()[-1].lower()  # 容許 hosts 格式
        if tok.startswith("*."):
            if (d := normalize(tok[2:])):
                self.suffix.add(d)
        elif "*" in tok:
            self.globs.append(tok)
        elif (d := normalize(tok)):
            self.exact.add(d)

    def compile(self):
        self._globs = [(g, re.compile(re.escape(g).replace(r"\*", "[^.]*") + "$")) for g in self.globs]

    def match(self, d: str) -> str | None:
        """回傳命中的白名單規則（供報告用），沒命中回傳 None。"""
        if d in self.exact:
            return d
        if d in self.suffix:
            return "*." + d
        i = d.find(".")
        while i != -1:
            parent = d[i + 1:]
            if parent in self.suffix:
                return "*." + parent
            i = d.find(".", i + 1)
        for g, rx in self._globs:
            if rx.match(d):
                return g
        return None


# ───────────────────────────── 下載 ─────────────────────────────

@dataclass
class Source:
    url: str
    fmt: str | None
    kind: str  # block / allow
    status: str = ""
    note: str = ""
    updated: dt.datetime | None = None
    domains: set[str] = field(default_factory=set)
    unique: int = 0
    used: bool = False


def read_list_file(path: Path, kind: str) -> list[Source]:
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        out.append(Source(parts[0], parts[1] if len(parts) > 1 else None, kind))
    return out


def http_get(url: str, timeout: int = 120) -> tuple[bytes, dict]:
    headers = {"User-Agent": UA}
    if GITHUB_TOKEN and "api.github.com" in url:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read(), dict(r.headers)


def upstream_updated(src: Source, headers: dict) -> dt.datetime | None:
    """推估來源最後更新時間：GitHub/GitLab 用 commit 時間，其他用 Last-Modified。"""
    u = urllib.parse.urlsplit(src.url)
    try:
        if u.hostname == "raw.githubusercontent.com":
            owner, repo, _ref, *path = u.path.lstrip("/").split("/")
            api = (f"https://api.github.com/repos/{owner}/{repo}/commits?per_page=1&path="
                   + urllib.parse.quote(urllib.parse.unquote("/".join(path))))
            data = json.loads(http_get(api, 30)[0])
            if data:
                return dt.datetime.fromisoformat(data[0]["commit"]["committer"]["date"].replace("Z", "+00:00"))
        if u.hostname == "gitlab.com" and "/raw/" in u.path:
            proj, rest = u.path.lstrip("/").split("/raw/", 1)
            ref, path = rest.split("/", 1)
            api = (f"https://gitlab.com/api/v4/projects/{urllib.parse.quote(proj, safe='')}"
                   f"/repository/commits?per_page=1&ref_name={ref}&path={urllib.parse.quote(path)}")
            data = json.loads(http_get(api, 30)[0])
            if data:
                return dt.datetime.fromisoformat(data[0]["committed_date"])
    except Exception:
        pass
    lm = headers.get("Last-Modified")
    if lm:
        try:
            from email.utils import parsedate_to_datetime
            return parsedate_to_datetime(lm)
        except Exception:
            pass
    return None


def cache_path(url: str) -> Path:
    return CACHE / (hashlib.sha256(url.encode()).hexdigest()[:24] + ".txt")


def fetch(src: Source, prev: dict) -> Source:
    body = None
    for attempt in range(3):
        try:
            body, headers = http_get(src.url)
            break
        except urllib.error.HTTPError as e:
            err = f"HTTP {e.code}"
            if e.code in (404, 410):
                break
        except Exception as e:  # noqa: BLE001
            err = type(e).__name__
        time.sleep(5 * (attempt + 1))

    cp = cache_path(src.url)
    if body is None:
        if cp.exists():
            age = (time.time() - cp.stat().st_mtime) / 86400
            if age <= STALE_CACHE_DAYS:
                src.status, src.note = "cached", f"下載失敗（{err}），沿用 {age:.1f} 天前的快取"
                src.domains = parse_block(cp.read_text(encoding="utf-8", errors="replace"), src.fmt) \
                    if src.kind == "block" else set()
                src._raw = cp.read_text(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
                return src
        src.status, src.note = "failed", f"下載失敗（{err}）"
        return src

    text = body.decode("utf-8", errors="replace")
    CACHE.mkdir(parents=True, exist_ok=True)
    cp.write_text(text, encoding="utf-8")
    src._raw = text  # type: ignore[attr-defined]
    src.status = "ok"
    src.updated = upstream_updated(src, headers)

    # 沒有可靠時間資訊時，用「內容雜湊多久沒變」推估
    digest = hashlib.sha256(body).hexdigest()
    p = prev.get(src.url, {})
    if p.get("sha256") == digest and p.get("since"):
        since = dt.datetime.fromisoformat(p["since"])
    else:
        since = NOW
    src._sha, src._since = digest, since  # type: ignore[attr-defined]
    if src.updated is None and since < NOW:
        src.updated = since
    if src.kind == "block":
        src.domains = parse_block(text, src.fmt)
    return src


# ───────────────────────────── 主程式 ─────────────────────────────

def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    prev_state = {}
    if PREV_STATE.exists():
        try:
            prev_state = json.loads(PREV_STATE.read_text(encoding="utf-8"))
        except ValueError:
            pass
    prev_sources = prev_state.get("sources", {})

    blocks = read_list_file(ROOT / "sources.txt", "block")
    allows = read_list_file(ROOT / "allowlist-sources.txt", "allow")

    with cf.ThreadPoolExecutor(12) as ex:
        list(ex.map(lambda s: fetch(s, prev_sources), blocks + allows))

    # 過時來源
    for s in blocks:
        if s.status in ("ok", "cached") and s.updated:
            age = (NOW - s.updated).days
            if age > MAX_SOURCE_AGE_DAYS:
                s.status, s.note = "stale", f"已 {age} 天未更新，自動略過"
                s.domains = set()
        if s.status in ("ok", "cached") and not s.domains:
            s.status, s.note = "empty", "解析不到任何網域"
        s.used = s.status in ("ok", "cached")

    # 白名單
    allow = Allow()
    for line in (ROOT / "allowlist.txt").read_text(encoding="utf-8").splitlines():
        allow.add_line(line)
    for s in allows:
        raw = getattr(s, "_raw", "")
        for line in raw.splitlines():
            allow.add_line(line)
    allow.compile()

    # 匯總 + 計算每個來源的「獨有」貢獻
    counts: dict[str, int] = {}
    for s in blocks:
        for d in s.domains:
            counts[d] = counts.get(d, 0) + 1
    raw_total = sum(len(s.domains) for s in blocks)
    for s in blocks:
        s.unique = sum(1 for d in s.domains if counts[d] == 1)

    allowed_hits: dict[str, int] = {}
    final = []
    for d in counts:
        rule = allow.match(d)
        if rule:
            allowed_hits[rule] = allowed_hits.get(rule, 0) + 1
        else:
            final.append(d)
    final.sort(key=lambda d: d[::-1])  # 依網域尾端排序，同網站的子網域會排在一起

    # 安全閥：避免某次建置壞掉卻覆蓋掉好的清單
    prev_total = prev_state.get("total")
    if prev_total and len(final) < prev_total * (1 - MAX_SHRINK) and not os.environ.get("FORCE"):
        print(f"::error::總數從 {prev_total:,} 掉到 {len(final):,}（降幅超過 {MAX_SHRINK:.0%}），"
              "疑似來源異常，本次不發佈。確認無誤可用 FORCE=1 重跑。")
        return 1
    if not any(s.used for s in blocks):
        print("::error::所有來源都失敗")
        return 1

    stamp = NOW.astimezone(TW).strftime("%Y-%m-%d %H:%M (UTC+8)")
    header = [
        "# Title: tntrock 匯總封鎖清單 (Pi-hole)",
        "# Homepage: https://github.com/tntrock/Pi-hole-Block-list",
        f"# Updated: {stamp}",
        f"# Domains: {len(final)}",
        f"# Sources: {sum(s.used for s in blocks)} / {len(blocks)}",
        "#",
    ]
    (OUT / "blocklist.txt").write_text("\n".join(header + final) + "\n", encoding="utf-8", newline="\n")

    # state：給下次建置判斷過時與縮水
    state = {
        "generated": NOW.isoformat(),
        "total": len(final),
        "sources": {
            s.url: {"sha256": getattr(s, "_sha", None),
                    "since": getattr(s, "_since", NOW).isoformat()}
            for s in blocks + allows if getattr(s, "_sha", None)
        },
    }
    # 失敗的來源保留上次的紀錄
    for url, v in prev_sources.items():
        state["sources"].setdefault(url, v)
    (OUT / "state.json").write_text(json.dumps(state, indent=1, ensure_ascii=False), encoding="utf-8")

    write_report(blocks, allows, allowed_hits, raw_total, len(counts), len(final), prev_total, stamp)
    print(f"完成：{len(final):,} 個網域（原始 {raw_total:,}，去重後 {len(counts):,}，"
          f"白名單移除 {len(counts) - len(final):,}）")
    return 0


def write_report(blocks, allows, allowed_hits, raw_total, dedup, final, prev_total, stamp):
    icon = {"ok": "✅", "cached": "♻️", "stale": "💤", "failed": "❌", "empty": "⚠️"}
    L = [
        f"# 建置報告 — {stamp}", "",
        "| 項目 | 數量 |", "|---|---:|",
        f"| 來源（使用中 / 全部） | {sum(s.used for s in blocks)} / {len(blocks)} |",
        f"| 原始網域總數（含重複） | {raw_total:,} |",
        f"| 去重後 | {dedup:,} |",
        f"| 白名單移除 | {dedup - final:,} |",
        f"| **最終輸出** | **{final:,}** |",
    ]
    if prev_total:
        L.append(f"| 與上次相比 | {final - prev_total:+,} |")
    problems = [s for s in blocks + allows if s.status not in ("ok",)]
    if problems:
        L += ["", "## ⚠️ 需要注意的來源", "", "| 狀態 | 來源 | 說明 |", "|---|---|---|"]
        for s in problems:
            L.append(f"| {icon.get(s.status, s.status)} {s.status} | {s.url} | {s.note} |")
    L += ["", "## 來源明細", "",
          "「獨有」= 只有這個來源有的網域數；長期為 0 代表這份清單完全被其他來源涵蓋，可以考慮拿掉。", "",
          "| 狀態 | 網域數 | 獨有 | 最後更新 | 來源 |", "|---|---:|---:|---|---|"]
    for s in sorted(blocks, key=lambda s: -len(s.domains)):
        upd = s.updated.astimezone(TW).strftime("%Y-%m-%d") if s.updated else "?"
        L.append(f"| {icon.get(s.status, s.status)} | {len(s.domains):,} | {s.unique:,} | {upd} | {s.url} |")
    L += ["", "## 白名單命中（前 40 名）", "", "| 規則 | 移除數 |", "|---|---:|"]
    for rule, n in sorted(allowed_hits.items(), key=lambda kv: -kv[1])[:40]:
        L.append(f"| `{rule}` | {n:,} |")
    (OUT / "report.md").write_text("\n".join(L) + "\n", encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main())
