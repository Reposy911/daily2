#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
集成了所有邮箱验证码获取逻辑，支持多个邮箱提供商
使用方法：
   python standalone_exa_register_unified.py [--provider duckmail] [--coupon CODE]
环境变量：
   EXA_PROXY=http://ip:port
   COUPON=coupon-code
   MAIL_PROVIDER=duckmail|dropmail|1secmail|tempmailfree|mailtm|mailgw|imap
"""

import json
import os
import re
import sys
import time
import uuid
import random
import string
import secrets
import hashlib
import base64
import threading
import argparse
import imaplib
import email as email_lib
import urllib.parse
import urllib.request
import urllib.error
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Optional, List, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, quote
from dataclasses import dataclass

# 配置编码支持，避免 Windows 终端编码问题
try:
    sys.stdout.reconfigure(errors="replace")
except Exception:
    pass
try:
    sys.stderr.reconfigure(errors="replace")
except Exception:
    pass

try:
    from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
    from playwright.sync_api import sync_playwright
except Exception:
    sync_playwright = None
    PlaywrightTimeoutError = Exception

# playwright-stealth（可选，用于降低 headless/CI 环境下的自动化检测概率）
try:
    from playwright_stealth import stealth_sync
except Exception:
    stealth_sync = None

try:
    from curl_cffi import requests
    HAS_CURL_CFFI = True
except ImportError:
    import requests
    HAS_CURL_CFFI = False


# ==========================================
# 正则表达式和常量
# ==========================================

UUID_RE = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
    flags=re.IGNORECASE,
)

# 验证码正则
CODE_REGEX = r"(?<!\d)(\d{6})(?!\d)"
MAILTM_BASE = "https://api.mail.tm"
TEMPMAILFREE_BASE = "https://api.temp-mail.solutions"

# 某些临时邮箱域名可能在目标站点不可用/收不到信，可在这里禁用
# 也可用环境变量追加禁用：set MAIL_DOMAIN_BLOCKLIST=foo.com,bar.com
_MAIL_DOMAIN_BLOCKLIST_ENV = os.getenv("MAIL_DOMAIN_BLOCKLIST", "").strip()
MAIL_DOMAIN_BLOCKLIST: set[str] = {
    "dollicons.com",
}
if _MAIL_DOMAIN_BLOCKLIST_ENV:
    for _d in _MAIL_DOMAIN_BLOCKLIST_ENV.split(","):
        _dd = (_d or "").strip().lower()
        if _dd:
            MAIL_DOMAIN_BLOCKLIST.add(_dd)

# Exa 邮件 OTP 的发件人/内容关键词（可用环境变量覆盖）
# 例如：set OTP_KEYWORDS=exa,verification
_OTP_KEYWORDS_ENV = os.getenv("OTP_KEYWORDS", "exa").strip()
OTP_KEYWORDS: List[str] = [k.strip().lower() for k in _OTP_KEYWORDS_ENV.split(",") if k.strip()]


# ==========================================
# 日志和工具函数
# ==========================================

def _log(level: str, message: str) -> None:
    """打印日志"""
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
    """把形如 http://user:pass@host:port 的代理串解析为 Playwright proxy dict。

    Playwright 更稳定的写法是：
      {server: "http://host:port", username: "user", password: "pass"}
    而不是把 user/pass 拼进 server。
    """
    proxy_url = (proxy_url or "").strip()
    if not proxy_url:
        return None

    # 补齐协议
    if "://" not in proxy_url:
        proxy_url = f"http://{proxy_url}"

    try:
        p = urlparse(proxy_url)
    except Exception:
        return {"server": proxy_url}

    if not (p.scheme and p.hostname):
        return {"server": proxy_url}

    scheme = p.scheme
    # Playwright 使用 socks5（不识别 socks5h）
    if scheme == "socks5h":
        scheme = "socks5"

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
    """从邮件内容中提取验证码"""
    if not content:
        return None
    m = re.search(CODE_REGEX, content or "")
    return m.group(1) if m else None


def _match_keywords(sender: str, content: str, keywords: Optional[List[str]] = None) -> bool:
    """用于过滤目标邮件（默认匹配 OTP_KEYWORDS）。keywords 为空则不做过滤。"""
    keys = OTP_KEYWORDS if keywords is None else keywords
    if not keys:
        return True
    blob = (sender or "") + "\n" + (content or "")
    blob = blob.lower()
    return any(k in blob for k in keys)


def request_with_proxy_fallback(func, *args, proxies=None, **kwargs):
    """使用代理发送请求，失败时回退到无代理"""
    try:
        return func(*args, proxies=proxies, **kwargs)
    except Exception as e:
        if proxies:
            _log("warning", f"代理请求失败，尝试无代理: {e}")
            try:
                return func(*args, proxies=None, **kwargs)
            except Exception as e2:
                raise e2
        raise


# ==========================================
# Mail.tm / Mail.gw API 实现
# ==========================================

def _mailtm_headers(*, token: str = "", use_json: bool = False) -> Dict[str, str]:
    headers = {"Accept": "application/json"}
    if use_json:
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _mailtm_domains(proxies: Any = None, base_url: str = MAILTM_BASE) -> list:
    """获取 Mail.tm 可用域名"""
    try:
        if HAS_CURL_CFFI:
            resp = requests.get(
                f"{base_url}/domains",
                headers=_mailtm_headers(),
                proxies=proxies,
                impersonate="chrome",
                timeout=15,
            )
        else:
            resp = requests.get(
                f"{base_url}/domains",
                headers=_mailtm_headers(),
                proxies=proxies,
                timeout=15,
            )
        
        if resp.status_code != 200:
            return []

        data = resp.json()
        domains = []
        if isinstance(data, list):
            items = data
        elif isinstance(data, dict):
            items = data.get("hydra:member") or data.get("items") or []
        else:
            items = []

        for item in items:
            if not isinstance(item, dict):
                continue
            domain = str(item.get("domain") or "").strip()
            is_active = item.get("isActive", True)
            is_private = item.get("isPrivate", False)
            if domain and is_active and not is_private:
                if domain.lower() in MAIL_DOMAIN_BLOCKLIST:
                    continue
                domains.append(domain)

        return domains
    except Exception as e:
        _log("error", f"获取 Mail.tm 域名失败: {e}")
        return []


def get_email_and_token_mailtm(proxies: Any = None, base_url: str = MAILTM_BASE) -> Tuple[str, str]:
    """创建 Mail.tm / Mail.gw 邮箱并获取 Bearer Token（正确流程：/accounts 后再 /token）。"""
    domains = _mailtm_domains(proxies, base_url)
    if not domains:
        _log("error", f"{base_url} 没有可用域名")
        return "", ""

    domain = random.choice(domains)
    names = [
        "james", "mary", "john", "patricia", "robert", "jennifer", "michael", "linda",
        "william", "elizabeth", "david", "barbara", "richard", "susan", "joseph", "jessica",
        "thomas", "sarah", "charles", "karen", "christopher", "nancy", "daniel", "lisa",
        "matthew", "betty", "anthony", "margaret", "mark", "sandra", "donald", "ashley",
        "steven", "kimberly", "paul", "emily", "andrew", "donna", "joshua", "michelle",
        "alex", "chris", "katie", "brian", "kevin", "ryan", "eric", "jason", "justin",
    ]

    for _ in range(5):
        local = f"{random.choice(names)}{secrets.token_hex(2)}"
        email_addr = f"{local}@{domain}"
        password = secrets.token_urlsafe(18)

        try:
            if HAS_CURL_CFFI:
                create_resp = requests.post(
                    f"{base_url}/accounts",
                    headers=_mailtm_headers(use_json=True),
                    json={"address": email_addr, "password": password},
                    proxies=proxies,
                    impersonate="chrome",
                    timeout=15,
                )
            else:
                create_resp = requests.post(
                    f"{base_url}/accounts",
                    headers=_mailtm_headers(use_json=True),
                    json={"address": email_addr, "password": password},
                    proxies=proxies,
                    timeout=15,
                )
            if create_resp.status_code not in (200, 201):
                continue

            if HAS_CURL_CFFI:
                token_resp = requests.post(
                    f"{base_url}/token",
                    headers=_mailtm_headers(use_json=True),
                    json={"address": email_addr, "password": password},
                    proxies=proxies,
                    impersonate="chrome",
                    timeout=15,
                )
            else:
                token_resp = requests.post(
                    f"{base_url}/token",
                    headers=_mailtm_headers(use_json=True),
                    json={"address": email_addr, "password": password},
                    proxies=proxies,
                    timeout=15,
                )

            if token_resp.status_code == 200:
                token = str((token_resp.json() or {}).get("token") or "").strip()
                if token:
                    _log("success", f"Mail(tm/gw) 邮箱创建成功: {email_addr}")
                    return email_addr, token
        except Exception as e:
            _log("warning", f"Mail(tm/gw) 创建邮箱尝试失败: {e}")

    _log("error", f"{base_url} 邮箱创建成功但获取 Token 失败")
    return "", ""


def get_oai_code_mailtm(email: str, token: str, proxies: Any = None, base_url: str = MAILTM_BASE) -> str:
    """轮询邮箱验证码（Mail.tm / Mail.gw）。

    注意：这里用于 Exa OTP，不再硬编码过滤 "openai"，改为按 OTP_KEYWORDS 过滤（默认: exa）。
    """
    url_list = f"{base_url}/messages"
    seen_ids: set[str] = set()
    _log("info", f"正在等待邮箱 {email} 的验证码...")

    for attempt in range(40):
        try:
            if HAS_CURL_CFFI:
                resp = requests.get(
                    url_list,
                    headers=_mailtm_headers(token=token),
                    proxies=proxies,
                    impersonate="chrome",
                    timeout=15,
                )
            else:
                resp = requests.get(
                    url_list,
                    headers=_mailtm_headers(token=token),
                    proxies=proxies,
                    timeout=15,
                )

            if resp.status_code != 200:
                time.sleep(3)
                continue

            data = resp.json()
            if isinstance(data, list):
                messages = data
            elif isinstance(data, dict):
                messages = data.get("hydra:member") or data.get("messages") or []
            else:
                messages = []

            for msg in messages:
                if not isinstance(msg, dict):
                    continue
                msg_id = str(msg.get("id") or "").strip()
                if not msg_id or msg_id in seen_ids:
                    continue
                seen_ids.add(msg_id)

                # 读详情
                if HAS_CURL_CFFI:
                    read_resp = requests.get(
                        f"{base_url}/messages/{msg_id}",
                        headers=_mailtm_headers(token=token),
                        proxies=proxies,
                        impersonate="chrome",
                        timeout=15,
                    )
                else:
                    read_resp = requests.get(
                        f"{base_url}/messages/{msg_id}",
                        headers=_mailtm_headers(token=token),
                        proxies=proxies,
                        timeout=15,
                    )
                if read_resp.status_code != 200:
                    continue

                mail_data = read_resp.json() or {}
                sender = str(((mail_data.get("from") or {}).get("address") or "")).lower()
                subject = str(mail_data.get("subject") or "")
                intro = str(mail_data.get("intro") or "")
                text = str(mail_data.get("text") or "")
                html = mail_data.get("html") or ""
                if isinstance(html, list):
                    html = "\n".join(str(x) for x in html)

                content = "\n".join([subject, intro, text, str(html)])
                if not _match_keywords(sender, content):
                    continue

                code = extract_verification_code(content)
                if code:
                    _log("success", f"找到验证码: {code}")
                    return code
        except Exception as e:
            _log("warning", f"轮询邮件失败 (尝试 {attempt + 1}/40): {e}")

        if attempt < 39:
            time.sleep(3)

    _log("error", "超时，未收到验证码")
    return ""


# ==========================================
# Dropmail.me GraphQL API
# ==========================================

def get_email_dropmail(proxies: Any = None) -> Tuple[str, str]:
    """生成 Dropmail.me 邮箱，返回 (email, session_id)"""
    pwd = secrets.token_hex(8)
    query = """
    mutation {
        introduceSession {
            id,
            expiresAt,
            addresses {
                address
            }
        }
    }
    """
    for _ in range(15):
        try:
            if HAS_CURL_CFFI:
                resp = requests.post(
                    "https://dropmail.me/api/graphql/web-test-wgq6m5i",
                    json={"query": query},
                    impersonate="chrome",
                    timeout=15,
                )
            else:
                resp = requests.post(
                    "https://dropmail.me/api/graphql/web-test-wgq6m5i",
                    json={"query": query},
                    timeout=15,
                )
            
            if resp.status_code == 200:
                data = resp.json().get("data", {}).get("introduceSession", {})
                session_id = data.get("id")
                addresses = data.get("addresses", [])
                if session_id and addresses:
                    address = addresses[0]["address"]
                    whitelist = ["mimimail.me", "pickmemail.com", "mailtowin.com", "maximail.vip", "maximail.fyi"]
                    if not any(good in address for good in whitelist):
                        continue
                    _log("success", f"Dropmail 邮箱创建成功: {address}")
                    return address, session_id
        except Exception as e:
            _log("warning", f"Dropmail 创建邮箱失败: {e}")
            time.sleep(2)
    
    return "", ""


def get_oai_code_dropmail(session_id: str, email: str, proxies: Any = None) -> str:
    """使用 Dropmail Session 获取 OpenAI 验证码"""
    query = """
    query ($id: ID!) {
        session(id: $id) {
            mails {
                rawSize
                fromAddr
                toAddr
                downloadUrl
                text
                headerSubject
            }
        }
    }
    """
    _log("info", f"正在等待 Dropmail 邮箱 {email} 的验证码...", )

    for _ in range(4):
        try:
            if HAS_CURL_CFFI:
                resp = requests.post(
                    "https://dropmail.me/api/graphql/web-test-wgq6m5i",
                    json={"query": query, "variables": {"id": session_id}},
                    impersonate="chrome",
                    timeout=15,
                )
            else:
                resp = requests.post(
                    "https://dropmail.me/api/graphql/web-test-wgq6m5i",
                    json={"query": query, "variables": {"id": session_id}},
                    timeout=15,
                )
            
            if resp.status_code == 200:
                data = resp.json().get("data", {}).get("session", {})
                if not data:
                    time.sleep(3)
                    continue
                
                mails = data.get("mails", [])
                for mail in mails:
                    sender = str(mail.get("fromAddr") or "").lower()
                    subject = str(mail.get("headerSubject") or "")
                    text = str(mail.get("text") or "")
                    
                    content = "\n".join([subject, text])

                    if not _match_keywords(sender, content):
                        continue

                    code = extract_verification_code(content)
                    if code:
                        _log("success", f"找到验证码: {code}")
                        return code
        except Exception as e:
            _log("warning", f"Dropmail 轮询失败: {e}")

        time.sleep(3)

    _log("error", "Dropmail 超时，未收到验证码")
    return ""


# ==========================================
# 1secmail 临时邮箱 API
# ==========================================

def _1secmail_domains(proxies: Any = None) -> list:
    try:
        if HAS_CURL_CFFI:
            resp = requests.get(
                "https://www.1secmail.com/api/v1/?action=getDomainList",
                proxies=proxies,
                impersonate="chrome",
                timeout=15,
            )
        else:
            resp = requests.get(
                "https://www.1secmail.com/api/v1/?action=getDomainList",
                proxies=proxies,
                timeout=15,
            )
        
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    return ["1secmail.com", "1secmail.org", "1secmail.net", "kzccv.com", "qiott.com", "wukong.com", "icznn.com"]


def get_email_1secmail(proxies: Any = None) -> Tuple[str, str]:
    """生成 1secmail 邮箱"""
    domains = _1secmail_domains(proxies)
    if not domains:
        _log("error", "未获取到 1secmail 域名")
        return "", ""
    domain = random.choice(domains)

    names = [
        "james", "mary", "john", "patricia", "robert", "jennifer", "michael", "linda",
        "william", "elizabeth", "david", "barbara", "richard", "susan", "joseph", "jessica",
    ]
    name = random.choice(names)
    local = f"{name}{secrets.token_hex(2)}"
    email = f"{local}@{domain}"
    
    _log("success", f"1secmail 邮箱创建成功: {email}")
    return email, "1secmail"


def get_oai_code_1secmail(email: str, proxies: Any = None) -> str:
    """使用 1secmail 邮箱轮询获取 OpenAI 验证码"""
    login, domain = email.split("@")
    url_list = f"https://www.1secmail.com/api/v1/?action=getMessages&login={login}&domain={domain}"
    seen_ids = set()

    _log("info", f"正在等待 1secmail 邮箱 {email} 的验证码...", )

    for attempt in range(40):
        try:
            if HAS_CURL_CFFI:
                resp = requests.get(
                    url_list,
                    proxies=proxies,
                    impersonate="chrome",
                    timeout=15,
                )
            else:
                resp = requests.get(
                    url_list,
                    proxies=proxies,
                    timeout=15,
                )
            
            if resp.status_code != 200:
                time.sleep(3)
                continue

            messages = resp.json()

            for msg in messages:
                if not isinstance(msg, dict):
                    continue
                msg_id = str(msg.get("id"))
                if not msg_id or msg_id in seen_ids:
                    continue
                seen_ids.add(msg_id)

                read_url = f"https://www.1secmail.com/api/v1/?action=readMessage&login={login}&domain={domain}&id={msg_id}"
                try:
                    if HAS_CURL_CFFI:
                        read_resp = requests.get(
                            read_url,
                            proxies=proxies,
                            impersonate="chrome",
                            timeout=15,
                        )
                    else:
                        read_resp = requests.get(
                            read_url,
                            proxies=proxies,
                            timeout=15,
                        )
                except Exception:
                    continue
                
                if read_resp.status_code != 200:
                    continue

                mail_data = read_resp.json()
                sender = str(mail_data.get("from") or "").lower()
                subject = str(mail_data.get("subject") or "")
                text = str(mail_data.get("textBody") or "")
                html = str(mail_data.get("htmlBody") or "")
                
                content = "\n".join([subject, text, html])

                if not _match_keywords(sender, content):
                    continue

                code = extract_verification_code(content)
                if code:
                    _log("success", f"找到验证码: {code}")
                    return code
        except Exception as e:
            _log("warning", f"1secmail 轮询失败 (尝试 {attempt+1}/40): {e}")

        if attempt < 39:
            time.sleep(3)

    _log("error", "1secmail 超时，未收到验证码")
    return ""


# ==========================================
# Temp-Mailfree API
# ==========================================

def get_email_temp_mailfree(proxies: Any = None) -> Tuple[str, str]:
    """使用 Temp-Mailfree 生成随机邮箱"""
    try:
        url = f"{TEMPMAILFREE_BASE}/api/accounts/random"
        
        if proxies:
            proxy_url = proxies.get("https") or proxies.get("http")
            if proxy_url:
                proxy_handler = urllib.request.ProxyHandler({'https': proxy_url, 'http': proxy_url})
                opener = urllib.request.build_opener(proxy_handler)
                urllib.request.install_opener(opener)
        
        req = urllib.request.Request(url)
        req.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
        
        with urllib.request.urlopen(req, timeout=15) as response:
            data = json.loads(response.read().decode('utf-8'))
            email = data.get("email", "")
            token = data.get("token", "")
            if email and token:
                _log("success", f"Temp-Mailfree 邮箱创建成功: {email}")
                return email, token
    except Exception as e:
        _log("error", f"Temp-Mailfree 创建邮箱失败: {e}")
    return "", ""


def get_oai_code_temp_mailfree(email: str, token: str, proxies: Any = None) -> str:
    """使用 Temp-Mailfree 获取 OpenAI 验证码"""
    _log("info", f"正在等待 Temp-Mailfree 邮箱 {email} 的验证码...", )

    if proxies:
        proxy_url = proxies.get("https") or proxies.get("http")
        if proxy_url:
            proxy_handler = urllib.request.ProxyHandler({'https': proxy_url, 'http': proxy_url})
            opener = urllib.request.build_opener(proxy_handler)
            urllib.request.install_opener(opener)

    for attempt in range(40):
        try:
            url = f"{TEMPMAILFREE_BASE}/api/messages/{token}"
            req = urllib.request.Request(url)
            req.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
            
            with urllib.request.urlopen(req, timeout=15) as response:
                messages = json.loads(response.read().decode('utf-8'))
                
                if isinstance(messages, list):
                    for msg in messages:
                        if not isinstance(msg, dict):
                            continue
                        
                        sender = str(msg.get("from_name", "") or msg.get("from", "")).lower()
                        subject = str(msg.get("subject", ""))
                        text = str(msg.get("body_text", ""))
                        html = str(msg.get("body_html", ""))
                        
                        content = "\n".join([subject, text, html])
                        
                        if not _match_keywords(sender, content):
                            continue
                        
                        code = extract_verification_code(content)
                        if code:
                            _log("success", f"找到验证码: {code}")
                            return code
        except Exception as e:
            _log("warning", f"Temp-Mailfree 轮询失败 (尝试 {attempt+1}/40): {e}")

        if attempt < 39:
            time.sleep(3)

    _log("error", "Temp-Mailfree 超时，未收到验证码")
    return ""


# ==========================================
# IMAP Catch-All 自建邮箱
# ==========================================

def get_email_imap(domain: str) -> Tuple[str, str]:
    """生成自建域名邮箱"""
    names = [
        "james", "mary", "john", "patricia", "robert", "jennifer", "michael", "linda",
    ]
    name = random.choice(names)
    local = f"{name}{secrets.token_hex(2)}"
    email = f"{local}@{domain}"
    _log("success", f"IMAP 邮箱生成成功: {email}")
    return email, "imap"


def get_oai_code_imap(
    email: str,
    imap_host: str,
    imap_port: int = 993,
    imap_user: str = "",
    imap_password: str = ""
) -> str:
    """通过 IMAP 获取验证码"""
    if not imap_user:
        imap_user = email
    
    _log("info", f"正在通过 IMAP 连接 {imap_host} 获取验证码...")

    try:
        imap = imaplib.IMAP4_SSL(imap_host, imap_port, timeout=15)
        imap.login(imap_user, imap_password)
        imap.select("INBOX")
        
        _, message_ids = imap.search(None, "ALL")
        msg_ids = message_ids[0].split()
        
        # 按倒序（最新的邮件在前）查看邮件
        for msg_id in reversed(msg_ids[-20:]):
            try:
                _, data = imap.fetch(msg_id, "(RFC822)")
                msg = email_lib.message_from_bytes(data[0][1])
                
                sender = str(msg.get("From", "")).lower()
                subject = str(msg.get("Subject", ""))
                
                # 提取邮件正文
                body = ""
                for part in msg.walk():
                    if part.get_content_type() == "text/plain":
                        body = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                        break
                
                content = f"{subject}\n{body}"
                
                if not _match_keywords(sender, content):
                    continue
                
                code = extract_verification_code(content)
                if code:
                    _log("success", f"找到验证码: {code}")
                    imap.close()
                    imap.logout()
                    return code
            except Exception:
                pass
        
        imap.close()
        imap.logout()
    except Exception as e:
        _log("error", f"IMAP 连接失败: {e}")
    
    _log("error", "IMAP 超时，未收到验证码")
    return ""


# ==========================================
# Exa 自动化流程
# ==========================================

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
        """执行 Exa 登录 + 初始化流程"""
        if sync_playwright is None:
            return {
                "success": False,
                "error": "playwright 未安装，请执行: pip install playwright && playwright install chromium",
            }

        start_time = datetime.now()
        _log("info", f"打开 Exa 登录页: {email}")

        try:
            with sync_playwright() as p:
                enable_stealth = _parse_bool_env("EXA_STEALTH", True)

                launch_args = [
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                ]
                # 轻量反自动化参数（与 stealth 组合更有效）
                if enable_stealth:
                    launch_args.append("--disable-blink-features=AutomationControlled")

                launch_kwargs = {
                    "headless": (not self.headed),
                    "args": launch_args,
                }

                if self.slow_mo_ms:
                    launch_kwargs["slow_mo"] = self.slow_mo_ms

                browser = p.chromium.launch(**launch_kwargs)

                # 代理：优先在 context 上设置（对带账号密码的 https proxy 更稳）
                proxy_cfg = None
                if self.proxy:
                    proxy_cfg = _build_playwright_proxy(self.proxy) or {"server": self.proxy}
                    try:
                        _log(
                            "info",
                            f"Playwright 代理: server={proxy_cfg.get('server','')} user={proxy_cfg.get('username','') or '(none)'}",
                        )
                    except Exception:
                        pass

                # 尽量模拟真实桌面环境指纹（对 CI/Linux 更友好）
                default_ua = os.getenv(
                    "EXA_USER_AGENT",
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
                )

                context_kwargs = {
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
                    self._login_with_otp(page, email, code_getter_func, start_time)
                    onboarding_key = self._complete_onboarding(page)

                    # 若仍停留在 onboarding 且没有拿到 key，说明未完成引导
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

    def _login_with_otp(self, page, email: str, code_getter_func, start_time: datetime) -> None:
        """使用验证码登录"""
        auth_url = "https://auth.exa.ai/?callbackUrl=https%3A%2F%2Fdashboard.exa.ai%2F"
        page.goto(auth_url, wait_until="domcontentloaded", timeout=self.timeout_ms)

        page.wait_for_selector('input[placeholder="Email"]', timeout=60_000)
        page.fill('input[placeholder="Email"]', email)
        page.locator('form:has(input[placeholder="Email"]) button[type="submit"]').first.click()

        page.wait_for_selector('text="Verify your email"', timeout=60_000)
        _log("info", "等待验证码邮件...")
        
        code = code_getter_func()
        if not code:
            raise RuntimeError("未收到 Exa OTP 验证码")
        _log("success", f"收到 OTP: {code}")

        page.fill('input[placeholder="Enter verification code"]', code)
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
        """完成新手引导"""
        onboarding_key = None
        self._safe_goto(page, "https://dashboard.exa.ai/onboarding", timeout=self.timeout_ms, retries=2)
        page.wait_for_timeout(1200)

        # 调试/人工介入：卡在 onboarding 时可启用 Playwright Inspector 手动点选
        # 用法：运行脚本时加 --headed --pause-onboarding
        if self.pause_onboarding:
            try:
                _log("warning", "已开启 pause_onboarding：将暂停在 onboarding 页面，手动完成后在 Inspector 中继续执行")
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

        # 按你的实际流程优先顺序：Codex -> Python -> Web search tool
        step1_choice_groups = [
            ["Codex", "Cursor", "Claude", "Devin", "Other"],
            ["Python", "OpenAI SDK", "JavaScript", "cURL", "MCP", "Other"],
            ["Web search tool", "Coding agent", "Coding Agent", "News monitoring", "Other"],
        ]

        # 某些版本 Next 需要 textarea 非空（保险起见，自动填一句）
        def _ensure_textarea_filled() -> None:
            try:
                ta = page.locator("textarea").first
                if ta.count() and ta.is_visible():
                    try:
                        current = (ta.input_value() or "").strip()
                    except Exception:
                        current = ""
                    if not current:
                        ta.fill("CTF setup")
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

        # Step 2: 生成 key
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

            # 生成后常见会进入 "You're all set!" 页，需要点 "Sign in for API key" 才会离开 onboarding
            if self._click_any_visible(page, sign_in_selectors):
                page.wait_for_timeout(1500)
                if "onboarding" not in (page.url or ""):
                    return onboarding_key

            onboarding_key = self._extract_first_uuid(page.inner_text("body"))
            if onboarding_key:
                break

            page.wait_for_timeout(400)

        # 兜底点一次 Sign in / Go to Dashboard
        if "onboarding" in (page.url or ""):
            if self._click_any_visible(page, sign_in_selectors):
                page.wait_for_timeout(1500)

        return onboarding_key

    def _extract_onboarding_api_key(self, page) -> Optional[str]:
        """在 onboarding 的 You're all set 页面直接提取 API key。"""
        body_text = ""
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
        """兑换优惠券"""
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

    def _create_api_key(self, page) -> str:
        """创建 API Key"""
        self._safe_goto(page, "https://dashboard.exa.ai/api-keys", timeout=self.timeout_ms, retries=1)
        page.wait_for_timeout(1200)

        # 有时会被重定向到登录/升级页面，先做兜底检查
        current_url = page.url
        if "auth.exa.ai" in current_url:
            raise RuntimeError(f"API Keys 页面跳转到了登录页: {current_url}")

        # Exa 前端可能改文案/按钮，增加多个选择器并给页面一些加载时间
        create_selectors = [
            'button:has-text("Create Key")',
            'button:has-text("Create API Key")',
            'button:has-text("New Key")',
            'button:has-text("New API Key")',
            'button:has-text("Create")',
            '[role="button"]:has-text("Create Key")',
            '[role="button"]:has-text("Create")',
        ]

        create_btn = None
        deadline = time.time() + 12.0
        while time.time() < deadline and create_btn is None:
            for sel in create_selectors:
                loc = page.locator(sel).first
                if loc.count() and loc.is_visible():
                    try:
                        if loc.is_enabled():
                            create_btn = loc
                            break
                    except Exception:
                        # 某些 locator 上 is_enabled 可能抛错，忽略
                        create_btn = loc
                        break
            if create_btn is None:
                try:
                    page.wait_for_load_state("domcontentloaded", timeout=1200)
                except Exception:
                    pass
                page.wait_for_timeout(350)

        if create_btn is None:
            body = (page.inner_text("body") or "")
            hint = body[:1200].replace("\n", " ")
            raise RuntimeError(f"未找到 Create Key 按钮（URL={page.url}）。页面内容前1200字: {hint}")

        create_btn.click()
        page.wait_for_timeout(700)

        # 名称输入框也可能改 placeholder，做兼容
        name_input_selectors = [
            'input[placeholder="Project name"]',
            'input[placeholder*="name" i]',
            'input[name*="name" i]',
            'input[id*="name" i]',
            'input[type="text"]',
        ]
        name_input = None
        for sel in name_input_selectors:
            loc = page.locator(sel).first
            if loc.count() and loc.is_visible():
                name_input = loc
                break
        if name_input is None:
            raise RuntimeError("未找到 API key 名称输入框")
        name_input.fill(f"pool-{int(time.time())}-{random.randint(100, 999)}")
        page.wait_for_timeout(250)

        confirm_selectors = [
            'button:has-text("Create a Key")',
            'button:has-text("Create Key")',
            'button:has-text("Create")',
            '[role="button"]:has-text("Create")',
        ]
        confirm_btn = None
        for sel in confirm_selectors:
            loc = page.locator(sel).first
            if loc.count() and loc.is_visible():
                confirm_btn = loc
                break
        if confirm_btn is None:
            raise RuntimeError("未找到确认创建 Key 的按钮")
        try:
            if confirm_btn.is_enabled():
                confirm_btn.click()
            else:
                raise RuntimeError("创建 Key 按钮不可用")
        except Exception:
            # 兜底：直接点击一次
            confirm_btn.click()

        # Key 展示方式可能是 readonly input / textarea / 或直接渲染在页面里
        page.wait_for_timeout(1200)
        key_value = ""
        try:
            key_loc = page.locator("input[readonly], textarea[readonly]").first
            if key_loc.count() and key_loc.is_visible():
                try:
                    key_value = (key_loc.input_value() or "").strip()
                except Exception:
                    pass
        except Exception:
            pass

        if not key_value:
            # 从页面文本里直接抓 UUID（更稳）
            extracted = self._extract_first_uuid(page.inner_text("body"))
            key_value = extracted or ""

        if not key_value or not UUID_RE.fullmatch(key_value):
            body = (page.inner_text("body") or "")
            hint = body[:1200].replace("\n", " ")
            raise RuntimeError(f"创建后未提取到有效的 API key（URL={page.url}）。页面内容前1200字: {hint}")

        self._click_if_visible(page, 'button:has-text("Done")') or \
            self._click_if_visible(page, 'button:has-text("Close")')
        page.wait_for_timeout(300)

        _log("success", f"已提取 API key: {key_value[:6]}...{key_value[-4:]}")
        return key_value

    def _build_account_config(
        self,
        email: str,
        api_key: str,
        coupon_status: str,
        balance: Optional[str],
    ) -> Dict[str, Any]:
        return {
            "id": email,
            "exa_api_key": api_key,
            "coupon_status": coupon_status,
            "balance": balance,
            "secure_c_ses": api_key,
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
        """安全的页面跳转"""
        effective_timeout = timeout or self.timeout_ms
        for attempt in range(retries + 1):
            try:
                page.goto(url, wait_until="domcontentloaded", timeout=effective_timeout)
                return
            except Exception as exc:
                if attempt >= retries:
                    raise
                _log("warning", f"页面跳转被中止，重试 {attempt + 1}/{retries}")
                page.wait_for_timeout(500 + attempt * 300)


# ==========================================
# 主函数
# ==========================================

def create_mail_email(provider: str, proxies: Any = None, mail_domain: Optional[str] = None) -> Tuple[str, str]:
    """创建邮箱并返回 (email, token_or_session)"""
    # 仅使用 dropmail（按你的要求固定 provider，避免其它邮箱域名不稳定影响流程）
    return get_email_dropmail(proxies)


def create_code_getter(provider: str, email: str, token_or_session: str, proxies: Any = None) -> callable:
    """为指定的邮箱提供商创建验证码获取函数"""
    # 仅使用 dropmail
    return lambda: get_oai_code_dropmail(token_or_session, email, proxies)


def main():
    parser = argparse.ArgumentParser(description="ExaFree Exa 账号独立注册脚本（单文件版本）")
    parser.add_argument("--coupon", default="", help="优惠码")
    parser.add_argument("--proxy", default="", help="代理地址，如 http://127.0.0.1:7890")
    parser.add_argument("--mail-domain", default="", help="邮箱域名（某些提供商适用）")
    parser.add_argument(
        "--output-dir", default="exak", help="Token 输出目录，默认 exak 目录（也可用环境变量 EXA_OUTPUT_DIR）"
    )

    # 循环次数与输出
    parser.add_argument("--count", type=int, default=1, help="循环注册次数（也可用环境变量 EXA_COUNT）")
    parser.add_argument("--output", default="", help="聚合输出文件路径（.json 或 .jsonl）。默认写入 output-dir 目录")
    parser.add_argument("--jsonl", action="store_true", help="聚合输出为 JSON Lines（每行一个 JSON 对象）")
    parser.add_argument("--save-each", action="store_true", help="每个账号单独再保存一份 json（兼容旧行为）")

    # 关闭可视化（按你的要求固定 headless），仍保留 slowmo/pause 仅用于必要时临时排障
    parser.add_argument("--slowmo", type=int, default=0, help="每步操作延迟毫秒数（调试用）")
    parser.add_argument("--pause-onboarding", action="store_true", help="在 onboarding 页面暂停，手动点选完成后继续（调试用）")
    args = parser.parse_args()

    # 固定只使用 dropmail
    provider = "dropmail"
    coupon = (os.getenv("COUPON", "") or args.coupon).strip()
    proxy = (os.getenv("EXA_PROXY", "") or args.proxy).strip()
    mail_domain = (os.getenv("MAIL_DOMAIN", "") or args.mail_domain).strip() or None

    # 输出目录：
    # - 默认相对路径 exak（方便在 GitHub Actions 里用 artifacts 直接抓 exak/）
    # - 若在 GitHub Actions 中无论从哪个子目录运行脚本，都强制基于 $GITHUB_WORKSPACE 解析
    output_dir = (os.getenv("EXA_OUTPUT_DIR", "") or args.output_dir).strip() or "exak"
    base_dir = (os.getenv("GITHUB_WORKSPACE", "") or os.getcwd()).strip() or os.getcwd()
    if os.path.isabs(output_dir):
        out_dir = os.path.normpath(output_dir)
    else:
        out_dir = os.path.normpath(os.path.join(base_dir, output_dir))

    def _display_path(path: str) -> str:
        try:
            # 能相对 workspace 展示就相对展示，避免日志里出现很长的 /home/runner/work/... 路径
            rel = os.path.relpath(path, start=base_dir)
            # relpath 可能生成 ".."，这种就直接回退到原路径
            if rel.startswith(".."):
                return path
            return rel
        except Exception:
            return path

    # 循环次数优先取环境变量，便于 GitHub Actions 设置
    try:
        count = int((os.getenv("EXA_COUNT", "") or "").strip() or int(args.count or 1))
    except Exception:
        count = int(args.count or 1)
    count = max(1, count)

    # 检查 proxy 协议
    if proxy and "://" not in proxy:
        if proxy.endswith(":1080"):
            proxy = f"socks5h://{proxy}"
        else:
            proxy = f"http://{proxy}"

    _log("info", f"========== Exa 单文件注册工具 v2.2 ==========")
    _log("info", f"邮箱提供商: {provider}")
    _log("info", f"代理: {proxy or '无'}")
    _log("info", f"优惠码: {coupon or '不使用'}")
    _log("info", f"输出目录: {_display_path(out_dir)}")
    _log("info", f"循环次数: {count}")
    if mail_domain:
        _log("info", f"邮箱域名: {mail_domain}")

    proxies = {"http": proxy, "https": proxy} if proxy else None

    # 输出目录与聚合文件路径
    os.makedirs(out_dir, exist_ok=True)

    output_path = (args.output or "").strip()
    if not output_path and count > 1:
        suffix = "jsonl" if args.jsonl else "json"
        output_path = os.path.join(out_dir, f"exa_accounts_{int(time.time())}.{suffix}")
    elif output_path and not os.path.isabs(output_path):
        # 相对路径统一基于 base_dir（GitHub Actions: $GITHUB_WORKSPACE；本地：cwd）
        if os.path.dirname(output_path) == "":
            # 仅文件名 -> 放到 output-dir
            output_path = os.path.join(out_dir, output_path)
        else:
            # 带目录 -> 相对 base_dir
            output_path = os.path.normpath(os.path.join(base_dir, output_path))

    def _save_aggregate(records: List[Dict[str, Any]], path: str, *, jsonl: bool) -> None:
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            if jsonl:
                for row in records:
                    f.write(json.dumps(row, ensure_ascii=False))
                    f.write("\n")
            else:
                json.dump(records, f, indent=2, ensure_ascii=False)

    def _extract_success_config_from_record(record: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not isinstance(record, dict) or not record.get("success"):
            return None
        raw = record.get("raw") if isinstance(record.get("raw"), dict) else {}
        config = raw.get("config") if isinstance(raw, dict) else None
        if isinstance(config, dict):
            return dict(config)
        return None

    def _extract_success_config(result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not isinstance(result, dict):
            return None
        config = result.get("config")
        if not result.get("success") or not isinstance(config, dict):
            return None
        return dict(config)

    all_records: List[Dict[str, Any]] = []

    # 复用 automation（减少反复初始化配置），但每次仍会启动新的 browser
    automation = ExaAutomation(
        proxy=proxy,
        timeout_ms=120_000,
        headed=False,
        slow_mo_ms=int(args.slowmo or 0),
        pause_onboarding=bool(args.pause_onboarding),
    )

    for i in range(count):
        _log("info", f"\n========== 第 {i + 1}/{count} 次注册 ==========")

        # 创建邮箱
        _log("info", f"正在使用 {provider.upper()} 创建邮箱...")
        email, token_or_session = create_mail_email(provider, proxies, mail_domain)

        if not email:
            _log("error", f"{provider.upper()} 邮箱创建失败")
            record = {
                "index": i + 1,
                "success": False,
                "error": f"{provider.upper()} 邮箱创建失败",
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
            all_records.append(record)
            continue

        _log("success", f"邮箱创建成功: {email}")

        # 创建验证码获取函数
        get_code = create_code_getter(provider, email, token_or_session, proxies)

        # 执行 Exa 注册
        _log("info", "开始 Exa 自动化注册...")
        result = automation.register_and_setup(
            email=email,
            code_getter_func=get_code,
            coupon_code=coupon,
            redeem_coupon=bool(coupon),
        )

        raw_result: Dict[str, Any] = dict(result) if isinstance(result, dict) else {}
        if not raw_result.get("success"):
            raw_result.pop("config", None)
            raw_result.pop("created_api_key", None)
            raw_result.pop("onboarding_api_key", None)
            raw_result.pop("balance", None)
            raw_result.pop("coupon_status", None)

        record: Dict[str, Any] = {
            "index": i + 1,
            "email": email,
            "success": bool(raw_result.get("success")),
            "created_api_key": raw_result.get("created_api_key") if raw_result.get("success") else None,
            "onboarding_api_key": raw_result.get("onboarding_api_key") if raw_result.get("success") else None,
            "coupon_status": raw_result.get("coupon_status") if raw_result.get("success") else None,
            "balance": raw_result.get("balance") if raw_result.get("success") else None,
            "error": raw_result.get("error"),
            "raw": raw_result,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        all_records.append(record)

        if result.get("success"):
            _log("success", "注册成功")
            _log("success", f"API Key: {result.get('created_api_key')}")
        else:
            _log("error", "注册失败")
            _log("error", f"错误: {result.get('error', '未知错误')}")

        # 兼容旧行为：单次时默认保存单账号 json；多次时仅在 --save-each 时保存
        if (count == 1) or bool(args.save_each):
            output_file = os.path.join(out_dir, f"exa_account_{email.split('@')[0]}_{int(time.time())}.json")
            try:
                single_output = _extract_success_config(raw_result) or raw_result
                with open(output_file, "w", encoding="utf-8") as f:
                    json.dump(single_output, f, indent=2, ensure_ascii=False)
                _log("success", f"账户信息已保存到: {output_file}")
            except Exception as e:
                _log("warning", f"保存单账号 JSON 失败: {e}")

    # 写入聚合文件（count>1 默认输出；count==1 仅在显式指定 --output 或 --jsonl 时输出）
    if output_path:
        try:
            # 聚合输出必须是 Exa2api 可识别的账号配置数组（即 config 对象数组）
            success_configs: List[Dict[str, Any]] = []
            for row in all_records:
                cfg = _extract_success_config_from_record(row)
                if cfg:
                    success_configs.append(cfg)
            _save_aggregate(success_configs, output_path, jsonl=bool(args.jsonl) or output_path.lower().endswith(".jsonl"))
            _log("success", f"\n聚合结果已保存到: {_display_path(output_path)}")
        except Exception as e:
            _log("error", f"聚合结果保存失败: {e}")
    elif count > 1:
        # 理论上不会走到这里（count>1 会自动生成 output_path），兜底
        fallback = os.path.join(out_dir, f"exa_accounts_{int(time.time())}.json")
        try:
            success_configs: List[Dict[str, Any]] = []
            for row in all_records:
                cfg = _extract_success_config_from_record(row)
                if cfg:
                    success_configs.append(cfg)
            _save_aggregate(success_configs, fallback, jsonl=False)
            _log("success", f"\n聚合结果已保存到: {_display_path(fallback)}")
        except Exception as e:
            _log("error", f"聚合结果保存失败: {e}")


if __name__ == "__main__":
    main()
