"""Qilan 节点全量抓取脚本（登录态）。

站点逆向结论（已实测确认）：
- 节点数据：GET /api/nodes?page=N&limit=L，返回 {"data":[...], "total":N, ...}，
  响应里没有 hasMore 字段，用「本页条数 < limit」作终止条件。
- 鉴权 = same-origin 的 `session` cookie。访客（无 session）只能拿第 1 页且
  limit 被锁 50；page>=2 直接 403。持有 session 后：role='user'，total=924
  （比访客多 42 条 member 专属节点），limit 可用到 200，深度翻页正常。
- GET 请求只需 `session` cookie，不需要 csrf_token 头（csrf 仅作用于变更类请求）。
- 登录端点 POST /admin/login 带 Cloudflare Turnstile 后端校验，无法纯 API 直登；
  但只要你已在浏览器登录、拿到了 session cookie，本脚本可直接复用它，无需再登录。

两种用法（推荐第一种）：
  用法一（最简，推荐）：直接给 session cookie
    1) 在浏览器登录 qilan.de，从 DevTools -> Application -> Cookies 复制
       www.qilan.de 下的 `session` 值（一长串十六进制）。
    2) 设环境变量后运行：
         set QILAN_SESSION=<session值>     (Windows cmd)
         $env:QILAN_SESSION="<session值>"  (PowerShell)
         export QILAN_SESSION=<session值>  (bash)
       python qilan_scraper.py
    或把值直接填进本文件顶部的 SESSION 变量。
  用法二（无 cookie 时兜底）：Playwright 自动登录
    1) pip install playwright httpx  &&  playwright install chromium
    2) 填好 USERNAME/PASSWORD，python qilan_scraper.py
       （首次会用浏览器过 Turnstile 并保存 cookies.json，之后复用）

通用：
- PROXY：你浏览器走 127.0.0.1:7890；若脚本直连不通再填，否则保持 None。
- FILTERS：置空 {} = 所有节点；要复刻某次筛选就填，如
  {"status":"online","ip_type":"residential","sort":"speed_desc"}。
- 输出：nodes_all.json + nodes_all.csv。
- 注意 session cookie 会过期，失效后重新复制即可。
"""

from __future__ import annotations

import csv
import json
import os
import time
from pathlib import Path
from typing import Any

import httpx

# --------------------------------------------------------------------------- #
# 配置区
# --------------------------------------------------------------------------- #
BASE_URL = "https://www.qilan.de"
USERNAME = "null"          # 仅「用法二」自动登录需要
PASSWORD = "Aa456123"      # 仅「用法二」自动登录需要

# 用法一：session cookie 读取顺序 = 环境变量 QILAN_SESSION → session.txt（非版本控制，推荐）
# → cookies.json（Playwright 登录产物）→ Playwright 自动登录。
# 推荐把 session 值单独放 session.txt 并加入 .gitignore，避免密钥进仓库。
SESSION: str | None = os.getenv("QILAN_SESSION") or None
SESSION_FILE = Path(__file__).with_name("session.txt")

# 你浏览器抓到的请求走了本地代理 127.0.0.1:7890；若直连不通才填，否则保持 None
PROXY: str | None = None  # 例： "http://127.0.0.1:7890"

# 单页大小：登录态下单页至少可用 200（访客被锁 50）
LIMIT = 200

# 筛选条件。置空 {} = 所有节点 / 状态 / IP 类型。
FILTERS: dict[str, str] = {}

COOKIE_FILE = Path(__file__).with_name("cookies.json")
OUT_JSON = Path(__file__).with_name("nodes_all.json")
OUT_CSV = Path(__file__).with_name("nodes_all.csv")


# --------------------------------------------------------------------------- #
# 取 cookie：优先 SESSION 变量/环境变量，其次 cookies.json，最后 Playwright 登录
# --------------------------------------------------------------------------- #
def load_cookies() -> list[dict[str, Any]] | None:
    """按优先级解析可用的 cookie 列表；都没有则返回 None（需登录）。

    优先级：环境变量 QILAN_SESSION → session.txt（非版本控制）→ cookies.json → 无。
    session.txt 只存一行 session cookie 值，已被 .gitignore 排除，密钥不会进仓库。
    """
    if SESSION:
        print("[cookie] 使用环境变量 QILAN_SESSION 中的 session cookie")
        return [{"name": "session", "value": SESSION,
                 "domain": "www.qilan.de", "path": "/"}]
    if SESSION_FILE.exists():
        value = SESSION_FILE.read_text(encoding="utf-8").strip()
        if value:
            print(f"[cookie] 使用 session.txt: {SESSION_FILE}")
            return [{"name": "session", "value": value,
                     "domain": "www.qilan.de", "path": "/"}]
    if COOKIE_FILE.exists():
        print(f"[cookie] 复用已有 cookies.json: {COOKIE_FILE}")
        return json.loads(COOKIE_FILE.read_text(encoding="utf-8"))
    return None


def login_via_playwright() -> list[dict[str, Any]]:
    """兜底：用 Playwright 过 Turnstile 登录，返回浏览器上下文全部 cookie。"""
    from playwright.sync_api import sync_playwright  # 仅在需要时导入

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False)
        ctx_kwargs: dict[str, Any] = {
            "viewport": {"width": 1280, "height": 800},
            "user_agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
            ),
        }
        if PROXY:
            ctx_kwargs["proxy"] = {"server": PROXY}
        ctx = browser.new_context(**ctx_kwargs)
        page = ctx.new_page()

        print("[login] 打开登录页 ...")
        page.goto(f"{BASE_URL}/admin/login", wait_until="networkidle")
        page.fill("#username", USERNAME)
        page.fill("#password", PASSWORD)

        print("[login] 尝试触发 Turnstile 验证 ...")
        triggered = False
        for frame in page.frames:
            try:
                box = frame.locator(".cf-challenge-box, .checkbox, input[type=checkbox]")
                if box.count() and box.first.is_visible():
                    box.first.click(timeout=5000)
                    triggered = True
                    break
            except Exception:
                continue
        if not triggered:
            print("[login] 未找到可点击验证框，等待自动验证 ...")

        try:
            page.wait_for_url("**/profile", timeout=90_000)
        except Exception:
            try:
                page.wait_for_url("**/admin", timeout=10_000)
            except Exception:
                browser.close()
                raise RuntimeError(
                    "登录未在预期时间内跳转，可能 Turnstile 未通过。"
                    "请改用有头模式并在弹出浏览器里手动完成验证后重试。"
                )

        print("[login] 登录成功，保存 cookie ...")
        cookies = ctx.cookies()
        browser.close()
        COOKIE_FILE.write_text(json.dumps(cookies, indent=2, ensure_ascii=False))
        return cookies


# --------------------------------------------------------------------------- #
# 翻页：持 session cookie 调 /api/nodes，直到某页返回不足一页
# --------------------------------------------------------------------------- #
def fetch_all_nodes(cookies: list[dict[str, Any]]) -> list[dict[str, Any]]:
    jar = httpx.Cookies()
    for c in cookies:
        jar.set(c["name"], c["value"], domain=c.get("domain"), path=c.get("path", "/"))

    client_kwargs: dict[str, Any] = {
        "base_url": BASE_URL,
        "cookies": jar,
        "headers": {"Accept": "application/json"},
        "timeout": 30.0,
        "follow_redirects": True,
    }
    if PROXY:
        client_kwargs["proxy"] = PROXY

    all_nodes: list[dict[str, Any]] = []
    page_no = 1
    with httpx.Client(**client_kwargs) as client:
        while True:
            params: dict[str, Any] = {"page": page_no, "limit": LIMIT, **FILTERS}
            resp = client.get("/api/nodes", params=params)
            if resp.status_code == 403:
                print("[fetch] 收到 403 —— session 无效或已过期，请更新 SESSION cookie。")
                break
            resp.raise_for_status()
            payload = resp.json()
            batch = payload.get("data", []) or []
            total = payload.get("total")
            all_nodes.extend(batch)
            print(f"[fetch] page {page_no}: +{len(batch)} 条，累计 {len(all_nodes)}/{total}")
            if len(batch) < LIMIT:
                break
            page_no += 1
            time.sleep(0.3)  # 礼貌限速，避免被风控
    return all_nodes


# --------------------------------------------------------------------------- #
# 落盘
# --------------------------------------------------------------------------- #
def save_outputs(nodes: list[dict[str, Any]]) -> None:
    OUT_JSON.write_text(json.dumps(nodes, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[out] 已写 JSON: {OUT_JSON} ({len(nodes)} 条)")

    if nodes:
        fields = list(nodes[0].keys())
        with OUT_CSV.open("w", newline="", encoding="utf-8-sig") as f:
            w = csv.DictWriter(f, fieldnames=fields)
            w.writeheader()
            w.writerows(nodes)
        print(f"[out] 已写 CSV : {OUT_CSV} ({len(nodes)} 条)")
    else:
        print("[out] 未抓到任何节点。")


# --------------------------------------------------------------------------- #
# 入口
# --------------------------------------------------------------------------- #
def main() -> None:
    cookies = load_cookies()
    if cookies is None:
        print("[init] 无可用 cookie，启动 Playwright 登录 ...")
        cookies = login_via_playwright()

    nodes = fetch_all_nodes(cookies)
    save_outputs(nodes)
    print("[done] 完成。")


if __name__ == "__main__":
    main()
