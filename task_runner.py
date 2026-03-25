#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ExaFree Exa 账号独立注册脚本（单文件版）
仅保留 Mailfree 邮箱后端与 Exa 自动化流程。

环境变量：
  EXA_PROXY=http://ip:port
  COUPON=coupon-code
  EXA_COUNT=1
  EXA_OUTPUT_DIR=exak
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

try:
    sys.stdout.reconfigure(errors="replace")
except Exception:
    pass
try:
    sys.stderr.reconfigure(errors="replace")
except Exception:
    pass

try:
    from playwright.sync_api import sync_playwright  # type: ignore
except Exception:
    sync_playwright = None

try:
    from playwright_stealth import stealth_sync  # type: ignore
except Exception:
    stealth_sync = None

try:
    from curl_cffi import requests  # type: ignore
    HAS_CURL_CFFI = True
except ImportError:
    import requests  # type: ignore
    HAS_CURL_CFFI = False


UUID_RE = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
    flags=re.IGNORECASE,
)
CODE_REGEX = re.compile(r"(?<!\d)(\d{6})(?!\d)")

DEFAULT_WORKER_URL = os.getenv("MF_WORKER_URL", "").strip()
DEFAULT_MF_USER = os.getenv("MF_USER", "").strip()
DEFAULT_MF_PASS = os.getenv("MF_PASS", "").strip()

_OTP_KEYWORDS_ENV = os.getenv("OTP_KEYWORDS", "exa").strip()
OTP_KEYWORDS: List[str] = [k.strip().lower() for k in _OTP_KEYWORDS_ENV.split(",") if k.strip()]


def _log(level: str, message: str) -> None:
    timestamp = datetime.now().strftime("%H:%M:%S")
    if level == "info":
        print(f"[{timestamp}] [INFO] {message}")
    elif level == "error":
        print(f"[{timestamp}] [ERROR] {message}")
    elif level == "warning":
        print(f"[{timestamp}] [WARN] {message}")
    elif level == "success":
        print(f"[{timestamp}] [SUCCESS] {message}")
    else:
        print(f"[{timestamp}] [DEBUG] {message}")


def _parse_bool_env(key: str, default: bool) -> bool:
    raw = (os.getenv(key, "") or "").strip().lower()
    if raw in ("1", "true", "yes", "y", "on"):
        return True
    if raw in ("0", "false", "no", "n", "off"):
        return False
    return default


def _parse_blocked_resource_types() -> set[str]:
    raw = (os.getenv("EXA_BLOCK_RESOURCE_TYPES", "image,media,font") or "").strip()
    if not raw:
        return set()
    return {item.strip().lower() for item in raw.split(",") if item.strip()}


def _build_playwright_proxy(proxy_url: str) -> Optional[Dict[str, str]]:
    proxy_url = (proxy_url or "").strip()
    if not proxy_url:
        return None
    if "://" not in proxy_url:
        proxy_url = f"http://{proxy_url}"

    try:
        p = urlparse(proxy_url)
    except Exception:
        return {"server": proxy_url}

    if not (p.scheme and p.hostname):
        return {"server": proxy_url}

    scheme = "socks5" if p.scheme == "socks5h" else p.scheme
    server = f"{scheme}://{p.hostname}"
    if p.port:
        server += f":{p.port}"

    out: Dict[str, str] = {"server": server}
    if p.username:
        out["username"] = urllib.parse.unquote(p.username)
    if p.password:
        out["password"] = urllib.parse.unquote(p.password)
    return out


def extract_verification_code(content: str) -> Optional[str]:
    if not content:
        return None
    m = CODE_REGEX.search(content)
    return m.group(1) if m else None


def _match_keywords(sender: str, subject: str, content: str) -> bool:
    if not OTP_KEYWORDS:
        return True
    blob = "\n".join([sender or "", subject or "", content or ""]).lower()
    return any(k in blob for k in OTP_KEYWORDS)


def _normalize_proxy(proxy: str) -> str:
    proxy = (proxy or "").strip()
    if not proxy:
        return ""
    if "://" in proxy:
        return proxy
    if proxy.endswith(":1080"):
        return f"socks5h://{proxy}"
    return f"http://{proxy}"


def _new_http_session(proxies: Optional[Dict[str, str]] = None):
    if HAS_CURL_CFFI:
        return requests.Session(proxies=proxies, impersonate="chrome")
    s = requests.Session()
    if proxies:
        s.proxies.update(proxies)
    return s


def _mailfree_login(base_url: str, username: str, password: str, proxies: Optional[Dict[str, str]] = None):
    s = _new_http_session(proxies)
    resp = s.post(
        f"{base_url.rstrip('/')}/api/login",
        json={"username": username, "password": password},
        timeout=15,
    )
    if resp.status_code != 200:
        raise RuntimeError(f"Mailfree 登录失败: HTTP {resp.status_code} {resp.text[:200]}")
    return s


def get_mailfree_email(
    proxies: Optional[Dict[str, str]] = None,
    base_url: str = DEFAULT_WORKER_URL,
    mf_user: str = DEFAULT_MF_USER,
    mf_pass: str = DEFAULT_MF_PASS,
) -> Tuple[str, Any]:
    if not base_url or not mf_user or not mf_pass:
        raise RuntimeError("Mailfree 环境变量未配置完整：需要 MF_WORKER_URL / MF_USER / MF_PASS")

    s = _mailfree_login(base_url, mf_user, mf_pass, proxies)
    resp = s.get(f"{base_url.rstrip('/')}/api/generate", timeout=15)
    if resp.status_code != 200:
        raise RuntimeError(f"Mailfree generate 失败: HTTP {resp.status_code} {resp.text[:200]}")

    data = resp.json()
    if not isinstance(data, dict):
        raise RuntimeError(f"Mailfree generate 响应格式异常: {resp.text[:200]}")

    email_addr = (data.get("address") or data.get("email") or "").strip()
    if not email_addr:
        raise RuntimeError(f"Mailfree generate 未返回 address/email: {resp.text[:200]}")
    return email_addr, s


def get_exa_code_mailfree(
    email_addr: str,
    mf_session: Any,
    proxies: Optional[Dict[str, str]] = None,
    base_url: str = DEFAULT_WORKER_URL,
    mf_user: str = DEFAULT_MF_USER,
    mf_pass: str = DEFAULT_MF_PASS,
    *,
    poll_times: int = 50,
    interval_sec: float = 3.0,
) -> str:
    s = mf_session or _mailfree_login(base_url, mf_user, mf_pass, proxies)
    seen_ids: set[str] = set()
    _log("info", f"正在等待 Mailfree 邮箱 {email_addr} 的验证码...")

    for _ in range(max(1, int(poll_times))):
        try:
            resp = s.get(
                f"{base_url.rstrip('/')}/api/emails",
                params={"mailbox": email_addr, "limit": 20},
                timeout=15,
            )
            if resp.status_code != 200:
                time.sleep(interval_sec)
                continue

            messages = resp.json()
            if isinstance(messages, dict):
                messages = messages.get("list") or messages.get("data") or messages.get("emails") or []
            if not isinstance(messages, list):
                messages = []

            for msg in messages:
                if not isinstance(msg, dict):
                    continue
                msg_id = str(msg.get("id") or msg.get("_id") or "").strip()
                if not msg_id or msg_id in seen_ids:
                    continue
                seen_ids.add(msg_id)

                detail_resp = s.get(f"{base_url.rstrip('/')}/api/email/{msg_id}", timeout=15)
                if detail_resp.status_code != 200:
                    continue

                mail_raw = detail_resp.json()
                mail_data = mail_raw.get("data") if (isinstance(mail_raw, dict) and "data" in mail_raw) else mail_raw
                if not isinstance(mail_data, dict):
                    continue

                sender = str(mail_data.get("from") or mail_data.get("sender") or "").lower()
                subject = str(mail_data.get("subject") or "")
                text = str(
                    mail_data.get("text")
                    or mail_data.get("body")
                    or mail_data.get("content")
                    or mail_data.get("body_text")
                    or ""
                )
                html = str(mail_data.get("html") or mail_data.get("body_html") or "")
                content = "\n".join([text, html])

                if not _match_keywords(sender, subject, content):
                    continue

                code = extract_verification_code("\n".join([subject, content]))
                if code:
                    _log("success", f"找到验证码: {code}")
                    return code
        except Exception:
            pass

        time.sleep(interval_sec)

    _log("error", "Mailfree 超时，未收到验证码")
    return ""


class ExaAutomation:
    """Exa 自动化流程封装（同步）"""

    def __init__(
        self,
        proxy: str = "",
        timeout_ms: int = 90_000,
        *,
        headed: bool = False,
        slow_mo_ms: int = 0,
        pause_onboarding: bool = False,
    ) -> None:
        self.proxy = (proxy or "").strip()
        self.timeout_ms = timeout_ms
        self.headed = headed
        self.slow_mo_ms = max(0, int(slow_mo_ms or 0))
        self.pause_onboarding = bool(pause_onboarding)

    def register_and_setup(
        self,
        email: str,
        code_getter_func,
        coupon_code: str = "",
        redeem_coupon: bool = False,
    ) -> Dict[str, Any]:
        if sync_playwright is None:
            return {
                "success": False,
                "error": "playwright 未安装，请执行: pip install playwright && playwright install chromium",
            }

        _log("info", f"打开 Exa 登录页: {email}")

        try:
            with sync_playwright() as p:
                enable_stealth = _parse_bool_env("EXA_STEALTH", True)
                launch_args = ["--no-sandbox", "--disable-dev-shm-usage"]
                if enable_stealth:
                    launch_args.append("--disable-blink-features=AutomationControlled")

                launch_kwargs: Dict[str, Any] = {
                    "headless": (not self.headed),
                    "args": launch_args,
                }
                if self.slow_mo_ms:
                    launch_kwargs["slow_mo"] = self.slow_mo_ms

                browser = p.chromium.launch(**launch_kwargs)

                proxy_cfg = None
                if self.proxy:
                    proxy_cfg = _build_playwright_proxy(self.proxy) or {"server": self.proxy}
                    _log(
                        "info",
                        f"Playwright 代理: server={proxy_cfg.get('server','')} user={proxy_cfg.get('username','') or '(none)'}",
                    )

                default_ua = os.getenv(
                    "EXA_USER_AGENT",
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
                )
                context_kwargs: Dict[str, Any] = {
                    "locale": os.getenv("EXA_LOCALE", "en-US"),
                    "timezone_id": os.getenv("EXA_TIMEZONE", "America/Los_Angeles"),
                    "user_agent": default_ua,
                    "viewport": {"width": 1366, "height": 768},
                }
                if proxy_cfg:
                    context_kwargs["proxy"] = proxy_cfg

                context = browser.new_context(**context_kwargs)
                page = context.new_page()

                blocked_resource_types = _parse_blocked_resource_types()
                if blocked_resource_types:
                    def _route_handler(route):
                        try:
                            resource_type = (route.request.resource_type or "").lower()
                        except Exception:
                            resource_type = ""
                        if resource_type in blocked_resource_types:
                            route.abort()
                            return
                        route.continue_()

                    page.route("**/*", _route_handler)
                    _log("info", f"已拦截资源类型: {', '.join(sorted(blocked_resource_types))}")

                if enable_stealth and stealth_sync is not None:
                    try:
                        stealth_sync(page)
                        _log("info", "已启用 playwright-stealth")
                    except Exception as e:
                        _log("warning", f"启用 playwright-stealth 失败（将继续执行）: {e}")

                try:
                    self._login_with_otp(page, email, code_getter_func)
                    onboarding_key = self._complete_onboarding(page)
                    if "onboarding" in (page.url or "") and not onboarding_key:
                        raise RuntimeError(f"onboarding 未完成，仍停留在: {page.url}")

                    balance = None
                    coupon_status = "not_attempted"
                    if redeem_coupon:
                        balance, coupon_status = self._redeem_coupon(page, coupon_code)

                    created_api_key = onboarding_key
                    if not created_api_key:
                        raise RuntimeError("未能在 onboarding 阶段提取到 API key")

                    account_config = self._build_account_config(
                        email=email,
                        api_key=created_api_key,
                        coupon_status=coupon_status,
                        balance=balance,
                    )
                    return {
                        "success": True,
                        "config": account_config,
                        "created_api_key": created_api_key,
                        "onboarding_api_key": onboarding_key,
                        "coupon_status": coupon_status,
                        "balance": balance,
                    }
                finally:
                    try:
                        context.close()
                    except Exception:
                        pass
                    try:
                        browser.close()
                    except Exception:
                        pass
        except Exception as exc:
            _log("error", f"Exa 自动化失败: {exc}")
            return {"success": False, "error": str(exc)}

    def _login_with_otp(self, page, email: str, code_getter_func) -> None:
        auth_url = "https://auth.exa.ai/?callbackUrl=https%3A%2F%2Fdashboard.exa.ai%2F"
        page.goto(auth_url, wait_until="domcontentloaded", timeout=self.timeout_ms)

        def _page_diag() -> str:
            try:
                title = page.title() or ""
            except Exception:
                title = ""
            try:
                body = (page.inner_text("body") or "")[:1000].replace("\n", " ")
            except Exception:
                body = ""
            try:
                email_visible = bool(page.locator('input[placeholder="Email"]').first.is_visible())
            except Exception:
                email_visible = False
            try:
                otp_visible = bool(page.locator('input[placeholder="Enter verification code"]').first.is_visible())
            except Exception:
                otp_visible = False
            try:
                submit_visible = bool(page.locator('form:has(input[placeholder="Email"]) button[type="submit"]').first.is_visible())
            except Exception:
                submit_visible = False
            return (
                f"url={page.url} | title={title[:120]} | email_input={email_visible} | "
                f"otp_input={otp_visible} | submit_btn={submit_visible} | body={body[:600]}"
            )

        page.wait_for_selector('input[placeholder="Email"]', timeout=60_000)
        page.fill('input[placeholder="Email"]', email)
        page.locator('form:has(input[placeholder="Email"]) button[type="submit"]').first.click()

        otp_ready = False
        entered_dashboard = False
        deadline = time.time() + 60.0
        otp_markers = [
            "verify your email",
            "verification code",
            "enter verification code",
            "check your inbox",
            "enter code",
        ]

        while time.time() < deadline:
            current_url = page.url or ""
            current_host = urlparse(current_url).hostname or ""
            if current_host == "dashboard.exa.ai":
                entered_dashboard = True
                break
            if "dashboard.exa.ai/onboarding" in current_url or "onboarding" in current_url:
                entered_dashboard = True
                break

            try:
                otp_input = page.locator('input[placeholder="Enter verification code"]').first
                if otp_input.count() and otp_input.is_visible():
                    otp_ready = True
                    break
            except Exception:
                pass

            try:
                body_text = (page.inner_text("body") or "").lower()
            except Exception:
                body_text = ""
            if any(marker in body_text for marker in otp_markers):
                otp_ready = True
                break

            try:
                page.wait_for_load_state("domcontentloaded", timeout=1200)
            except Exception:
                pass
            page.wait_for_timeout(300)

        if not otp_ready and not entered_dashboard:
            raise RuntimeError("提交邮箱后未进入验证码页。" + _page_diag())

        if entered_dashboard:
            _log("success", f"提交邮箱后已直接进入: {page.url}")
            return

        _log("info", "等待验证码邮件...")
        code = code_getter_func()
        if not code:
            raise RuntimeError("未收到 Exa OTP 验证码")
        _log("success", f"收到 OTP: {code}")

        otp_input = page.locator('input[placeholder="Enter verification code"]').first
        otp_input.fill(code)
        page.locator('button:has-text("VERIFY CODE")').first.click()

        entered_dashboard = False
        page.wait_for_timeout(700)
        deadline = time.time() + 22.0
        while time.time() < deadline:
            current_url = page.url
            if urlparse(current_url).hostname == "dashboard.exa.ai":
                entered_dashboard = True
                break
            try:
                page.wait_for_load_state("domcontentloaded", timeout=1200)
            except Exception:
                pass
            page.wait_for_timeout(300)

        if not entered_dashboard:
            self._safe_goto(page, "https://dashboard.exa.ai/", timeout=self.timeout_ms)

        _log("success", f"OTP 验证成功，已进入: {page.url}")

    def _complete_onboarding(self, page) -> Optional[str]:
        onboarding_key = None
        self._safe_goto(page, "https://dashboard.exa.ai/onboarding", timeout=self.timeout_ms, retries=2)
        page.wait_for_timeout(1200)

        if self.pause_onboarding:
            try:
                _log("warning", "已开启 pause_onboarding：将暂停在 onboarding 页面，手动完成后继续执行")
                page.pause()
            except Exception:
                pass

        if "onboarding" not in page.url:
            return None

        next_selectors = [
            'button:has-text("Next")',
            '[role="button"]:has-text("Next")',
            'button:has-text("Continue")',
            '[role="button"]:has-text("Continue")',
            'button:has-text("Proceed")',
            '[role="button"]:has-text("Proceed")',
        ]
        step1_choice_groups = [
            ["Codex", "Cursor", "Claude", "Devin", "Other"],
            ["Python", "OpenAI SDK", "JavaScript", "cURL", "MCP", "Other"],
            ["Web search tool", "Coding agent", "Coding Agent", "News monitoring", "Other"],
        ]

        def _ensure_textarea_filled() -> None:
            try:
                ta = page.locator("textarea").first
                if ta.count() and ta.is_visible():
                    try:
                        current = (ta.input_value() or "").strip()
                    except Exception:
                        current = ""
                    if not current:
                        ta.fill("websearch setup")
                        page.wait_for_timeout(150)
            except Exception:
                return

        step1_deadline = time.time() + 15.0
        while time.time() < step1_deadline:
            for labels in step1_choice_groups:
                for label in labels:
                    selectors = [
                        f'button:has-text("{label}")',
                        f'[role="button"]:has-text("{label}")',
                    ]
                    if self._click_any_visible(page, selectors):
                        page.wait_for_timeout(250)
                        break

            _ensure_textarea_filled()
            next_btn = self._first_visible_locator(page, next_selectors)
            if next_btn is not None and next_btn.is_enabled():
                next_btn.click()
                page.wait_for_timeout(1200)
                break
            page.wait_for_timeout(350)

        generate_selectors = [
            'button:has-text("Generate Code")',
            'button:has-text("Generate")',
            'button:has-text("Generate API Key")',
            '[role="button"]:has-text("Generate")',
        ]
        sign_in_selectors = [
            'button:has-text("Sign in for API key")',
            'a:has-text("Sign in for API key")',
            '[role="button"]:has-text("Sign in for API key")',
            'button:has-text("Go to Dashboard")',
            'a:has-text("Go to Dashboard")',
        ]

        generate_deadline = time.time() + 18.0
        while time.time() < generate_deadline and onboarding_key is None and "onboarding" in page.url:
            if self._click_any_visible(page, generate_selectors):
                page.wait_for_timeout(2200)

            onboarding_key = self._extract_onboarding_api_key(page)
            if onboarding_key:
                _log("success", f"在 onboarding 页面直接提取到 API key: {onboarding_key[:6]}...{onboarding_key[-4:]}")
                return onboarding_key

            if self._click_any_visible(page, sign_in_selectors):
                page.wait_for_timeout(1500)
                if "onboarding" not in (page.url or ""):
                    return onboarding_key

            onboarding_key = self._extract_first_uuid(page.inner_text("body"))
            if onboarding_key:
                break
            page.wait_for_timeout(400)

        if "onboarding" in (page.url or ""):
            if self._click_any_visible(page, sign_in_selectors):
                page.wait_for_timeout(1500)
        return onboarding_key

    def _extract_onboarding_api_key(self, page) -> Optional[str]:
        try:
            body_text = page.inner_text("body") or ""
        except Exception:
            body_text = ""

        direct = self._extract_first_uuid(body_text)
        if direct:
            return direct

        selectors = [
            'input[readonly]',
            'textarea[readonly]',
            'input[value*="-"]',
            '[data-testid*="api"] input',
            '[aria-label*="api key" i] input',
        ]
        for sel in selectors:
            try:
                loc = page.locator(sel).first
                if loc.count() and loc.is_visible():
                    try:
                        value = (loc.input_value() or "").strip()
                    except Exception:
                        value = (loc.text_content() or "").strip()
                    if UUID_RE.fullmatch(value):
                        return value
                    guessed = self._extract_first_uuid(value)
                    if guessed:
                        return guessed
            except Exception:
                pass

        copy_button_selectors = [
            'button[aria-label*="copy" i]',
            'button[title*="copy" i]',
            'button:has-text("Copy API")',
            'button:has-text("Copy")',
            '[role="button"][aria-label*="copy" i]',
        ]
        for sel in copy_button_selectors:
            try:
                loc = page.locator(sel).first
                if not loc.count() or not loc.is_visible():
                    continue
                loc.click()
                page.wait_for_timeout(200)
                try:
                    clip = (page.evaluate("navigator.clipboard.readText()") or "").strip()
                except Exception:
                    clip = ""
                if UUID_RE.fullmatch(clip):
                    return clip
                guessed = self._extract_first_uuid(clip)
                if guessed:
                    return guessed
            except Exception:
                pass
        return None

    def _redeem_coupon(self, page, coupon_code: str) -> Tuple[Optional[str], str]:
        self._safe_goto(page, "https://dashboard.exa.ai/billing", timeout=self.timeout_ms, retries=1)
        page.wait_for_timeout(1200)
        coupon_status = "not_attempted"
        balance_before = self._read_balance(page)
        coupon_expand_selectors = [
            'button:has-text("Have a coupon")',
            'button:has-text("Add coupon")',
        ]
        self._click_any_visible(page, coupon_expand_selectors)
        page.wait_for_timeout(300)

        coupon_input = None
        for selector in ['input[placeholder*="coupon" i]', 'input[placeholder*="promo" i]', 'input[type="text"]']:
            loc = page.locator(selector).first
            if loc.count() and loc.is_visible():
                coupon_input = loc
                break

        if coupon_input:
            coupon_input.fill(coupon_code)
            page.wait_for_timeout(250)
            redeem_btn_selectors = [
                'button:has-text("Redeem")',
                'button:has-text("Apply")',
            ]
            redeem_btn = self._first_visible_locator(page, redeem_btn_selectors)
            if redeem_btn and redeem_btn.is_enabled():
                redeem_btn.click()
                coupon_status = "submitted"
                page.wait_for_timeout(3400)

        balance = self._read_balance(page) or balance_before
        _log("success", f"优惠码状态: {coupon_status}, 余额: {balance}")
        return balance, coupon_status

    def _build_account_config(self, email: str, api_key: str, coupon_status: str, balance: Optional[str]) -> Dict[str, Any]:
        return {
            "id": email,
            "exa_api_key": api_key,
            "coupon_status": coupon_status,
            "balance": balance,
            "secure_c_ses": api_key,
            "host_c_oses": "",
            "csesidx": "exa",
            "config_id": "exa",
            "expires_at": None,
            "disabled": False,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

    @staticmethod
    def _extract_first_uuid(text: str) -> Optional[str]:
        m = UUID_RE.search(text or "")
        return m.group(0) if m else None

    @staticmethod
    def _read_balance(page) -> Optional[str]:
        text = page.inner_text("body")
        m = re.search(r"Remaining Balance\s*\$([0-9][0-9,]*(?:\.[0-9]{2})?)", text, flags=re.I)
        return m.group(1) if m else None

    @staticmethod
    def _click_if_visible(page, selector: str) -> bool:
        loc = page.locator(selector).first
        if loc.count() and loc.is_visible():
            try:
                loc.click()
                return True
            except Exception:
                return False
        return False

    @staticmethod
    def _click_any_visible(page, selectors) -> bool:
        for selector in selectors:
            if ExaAutomation._click_if_visible(page, selector):
                return True
        return False

    @staticmethod
    def _first_visible_locator(page, selectors):
        for selector in selectors:
            loc = page.locator(selector).first
            if loc.count() and loc.is_visible():
                return loc
        return None

    def _safe_goto(self, page, url: str, timeout: Optional[int] = None, retries: int = 1) -> None:
        effective_timeout = timeout or self.timeout_ms
        for attempt in range(retries + 1):
            try:
                page.goto(url, wait_until="domcontentloaded", timeout=effective_timeout)
                return
            except Exception:
                if attempt >= retries:
                    raise
                _log("warning", f"页面跳转被中止，重试 {attempt + 1}/{retries}")
                page.wait_for_timeout(500 + attempt * 300)


def normalize_success_config(config: Dict[str, Any]) -> Dict[str, Any]:
    exa_api_key = str(config.get("exa_api_key") or config.get("secure_c_ses") or "").strip()
    account_id = str(config.get("id") or "").strip()
    if not account_id or not exa_api_key:
        return {}
    return {
        "id": account_id,
        "exa_api_key": exa_api_key,
        "coupon_status": config.get("coupon_status", "not_attempted"),
        "balance": config.get("balance"),
        "secure_c_ses": str(config.get("secure_c_ses") or exa_api_key),
        "host_c_oses": config.get("host_c_oses", ""),
        "csesidx": config.get("csesidx", "exa"),
        "config_id": config.get("config_id", "exa"),
        "expires_at": config.get("expires_at"),
        "disabled": bool(config.get("disabled", False)),
        "created_at": config.get("created_at"),
    }


def create_mail_email(proxies: Any = None) -> Tuple[str, Any]:
    return get_mailfree_email(proxies=proxies)


def create_code_getter(email: str, token_or_session: Any, proxies: Any = None):
    return lambda: get_exa_code_mailfree(email, token_or_session, proxies=proxies)


def main() -> None:
    parser = argparse.ArgumentParser(description="ExaFree Exa 账号独立注册脚本（Mailfree 单文件版）")
    parser.add_argument("--coupon", default="", help="优惠码")
    parser.add_argument("--proxy", default="", help="代理地址，如 http://127.0.0.1:7890")
    parser.add_argument("--output-dir", default="exak", help="输出目录，默认 exak")
    parser.add_argument("--count", type=int, default=1, help="注册次数")
    parser.add_argument("--output", default="", help="聚合输出文件路径（.json 或 .jsonl）")
    parser.add_argument("--jsonl", action="store_true", help="聚合输出 JSONL")
    parser.add_argument("--save-each", action="store_true", help="每个账号单独保存一份 json")
    parser.add_argument("--headed", action="store_true", help="使用有头浏览器")
    parser.add_argument("--slowmo", type=int, default=0, help="每步操作延迟毫秒数（调试用）")
    parser.add_argument("--pause-onboarding", action="store_true", help="在 onboarding 页面暂停（调试用）")
    args = parser.parse_args()

    coupon = (os.getenv("COUPON", "") or args.coupon).strip()
    proxy = _normalize_proxy(os.getenv("EXA_PROXY", "") or args.proxy)
    count = max(1, int(os.getenv("EXA_COUNT", "") or args.count or 1))

    out_dir = (os.getenv("EXA_OUTPUT_DIR", "") or args.output_dir).strip() or "exak"
    base_dir = (os.getenv("GITHUB_WORKSPACE", "") or os.getcwd()).strip() or os.getcwd()
    if not os.path.isabs(out_dir):
        out_dir = os.path.normpath(os.path.join(base_dir, out_dir))
    os.makedirs(out_dir, exist_ok=True)

    if not DEFAULT_WORKER_URL or not DEFAULT_MF_USER or not DEFAULT_MF_PASS:
        raise SystemExit("缺少 Mailfree 配置，请在环境变量/Secrets 中设置 MF_WORKER_URL / MF_USER / MF_PASS")

    proxies = {"http": proxy, "https": proxy} if proxy else None
    output_path = (args.output or "").strip()
    if not output_path and count > 1:
        suffix = "jsonl" if args.jsonl else "json"
        output_path = os.path.join(out_dir, f"exa_accounts_{int(time.time())}.{suffix}")
    elif output_path and not os.path.isabs(output_path):
        output_path = os.path.join(out_dir, output_path) if os.path.dirname(output_path) == "" else os.path.normpath(os.path.join(base_dir, output_path))

    _log("info", "========== Exa Mailfree 注册工具 ==========")
    _log("info", f"代理: {proxy or '无'}")
    _log("info", f"优惠码: {coupon or '不使用'}")
    _log("info", f"输出目录: {out_dir}")
    _log("info", f"循环次数: {count}")

    automation = ExaAutomation(
        proxy=proxy,
        timeout_ms=120_000,
        headed=bool(args.headed),
        slow_mo_ms=int(args.slowmo or 0),
        pause_onboarding=bool(args.pause_onboarding),
    )

    all_configs: List[Dict[str, Any]] = []

    for i in range(count):
        _log("info", f"\n========== 第 {i + 1}/{count} 次注册 ==========")
        email = ""
        try:
            email, token_or_session = create_mail_email(proxies)
            _log("success", f"Mailfree 邮箱创建成功: {email}")
            get_code = create_code_getter(email, token_or_session, proxies)

            result = automation.register_and_setup(
                email=email,
                code_getter_func=get_code,
                coupon_code=coupon,
                redeem_coupon=bool(coupon),
            )

            if result.get("success"):
                config = normalize_success_config(result.get("config") or {})
                if config:
                    all_configs.append(config)
                    _log("success", f"注册成功: {email}")
                    _log("success", f"API Key: {result.get('created_api_key')}")
                else:
                    _log("error", "注册成功但未生成有效配置")
            else:
                _log("error", f"注册失败: {result.get('error', '未知错误')}")

            if (count == 1 or bool(args.save_each)) and result.get("success"):
                payload = [normalize_success_config(result.get("config") or {})]
                payload = [item for item in payload if item]
                out_file = os.path.join(out_dir, f"exa_account_{email.split('@')[0]}_{int(time.time())}.json")
                with open(out_file, "w", encoding="utf-8") as f:
                    json.dump(payload, f, ensure_ascii=False, indent=2)
                    f.write("\n")
                _log("success", f"账户信息已保存到: {out_file}")
        except Exception as exc:
            _log("error", f"处理 {email or 'mailfree'} 失败: {exc}")

    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            if bool(args.jsonl) or output_path.lower().endswith(".jsonl"):
                for row in all_configs:
                    f.write(json.dumps(row, ensure_ascii=False))
                    f.write("\n")
            else:
                json.dump(all_configs, f, ensure_ascii=False, indent=2)
                f.write("\n")
        _log("success", f"聚合结果已保存到: {output_path}")
    elif count > 1:
        fallback = os.path.join(out_dir, f"exa_accounts_{int(time.time())}.json")
        with open(fallback, "w", encoding="utf-8") as f:
            json.dump(all_configs, f, ensure_ascii=False, indent=2)
            f.write("\n")
        _log("success", f"聚合结果已保存到: {fallback}")


if __name__ == "__main__":
    main()
