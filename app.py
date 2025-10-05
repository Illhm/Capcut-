"""CapCut account creator backend rewritten in Python.

This module replicates the behaviour of the original Node.js implementation
(app.js) using the Python standard library and third party packages.
"""
from __future__ import annotations

import json
import logging
import os
import random
import re
import string
import threading
import time
from collections import Counter
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import requests
from bs4 import BeautifulSoup
from faker import Faker

try:
    from dotenv import load_dotenv
except Exception:  # pragma: no cover - optional dependency
    load_dotenv = None


# ---------------------------------------------------------------------------
# Konfigurasi dasar dan utilitas global
# ---------------------------------------------------------------------------
if load_dotenv is not None:
    load_dotenv()

LOGGER = logging.getLogger("capcut-python")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)

ROOT = Path(__file__).resolve().parent
CONFIG_PATH = ROOT / "config.json"
USAGE_DIR = ROOT / "logs"
USAGE_FILE = USAGE_DIR / "usage.json"

faker = Faker()

with CONFIG_PATH.open("r", encoding="utf-8") as config_file:
    CONFIG = json.load(config_file)

PROXY_LIST: Dict[str, str] = CONFIG.get("proxies", {
    "SG": "username__cr.sg:password@gw.dataimpulse.com:823",
})
DEFAULT_COUNTRY = CONFIG.get("default_country", "SG")
API_CONFIG = {
    "aid": "348188",
    "account_sdk_source": "web",
    "language": "en",
    "verifyFp": "verify_mbdaqk11_drZniKX9_gJP3_4mPC_91ao_aWYAyvFlKVWh",
    "check_region": "1",
}

# Domain rotation storage
domain_lock = threading.Lock()
DOMAINS: List[str] = []
domain_index = 0

# Usage tracking lock
usage_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Helper dataclasses
# ---------------------------------------------------------------------------
@dataclass
class AccountResult:
    success: bool
    ip: str
    country: str
    domain: str
    email: str
    password: Optional[str] = None


# ---------------------------------------------------------------------------
# Fungsi utilitas umum
# ---------------------------------------------------------------------------
def encrypt_to_target_hex(value: str) -> str:
    return "".join(f"{(ord(char) ^ 0x05):02x}" for char in value)


def _proxy_dict(proxy_url: str) -> Dict[str, str]:
    proxy_address = f"http://{proxy_url}"
    return {"http": proxy_address, "https": proxy_address}


def get_proxy_for_country(selected_country: str, account_index: int) -> Dict[str, str]:
    if selected_country == "ALL":
        countries = list(PROXY_LIST.keys())
        rotated_country = countries[account_index % len(countries)]
        return {
            "country": rotated_country,
            "proxy": PROXY_LIST[rotated_country],
        }
    return {"country": selected_country, "proxy": PROXY_LIST[selected_country]}


def generate_email() -> str:
    global domain_index

    with domain_lock:
        if not DOMAINS:
            raise RuntimeError("Tidak ada domain yang tersedia")
        selected_domain = DOMAINS[domain_index]
        domain_index = (domain_index + 1) % len(DOMAINS)

    name = re.sub(r"[^a-z]", "", faker.first_name().lower())
    num_length = random.randint(1, 5)
    random_numbers = "".join(random.choices(string.digits, k=num_length))
    random_letter = random.choice(string.ascii_lowercase)
    username = f"{name}{random_numbers}{random_letter}"
    return f"{username}@{selected_domain}"


def get_current_time() -> str:
    now = datetime.now()
    return f"[{now.hour:02d}:{now.minute:02d}]"


def fetch_domains_once() -> List[str]:
    url = "https://generator.email/inbox/"
    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")
        paragraphs = soup.select("#newselect p")
        extracted: List[str] = []
        for paragraph in paragraphs:
            domain = (paragraph.get_text() or "").strip()
            if not domain or "@" in domain or any(ch.isdigit() for ch in domain) or "." not in domain:
                continue
            parts = domain.split(".")
            if len(parts) >= 2 and len(parts[0]) <= 13:
                extracted.append(domain)
        return extracted
    except Exception as exc:
        LOGGER.error("%s [ERROR] Gagal mengambil domain: %s", get_current_time(), exc)
        return []


def fetch_domains_parallel() -> List[str]:
    LOGGER.info("%s [INFO] Mengambil daftar domain terbaru dengan 5 threads parallel", get_current_time())
    combined: List[str] = []

    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(fetch_domains_once) for _ in range(5)]
        for index, future in enumerate(futures, start=1):
            try:
                domains = future.result()
                LOGGER.info("%s [INFO] Thread %s berhasil mendapat %s domain", get_current_time(), index, len(domains))
                combined.extend(domains)
            except Exception as exc:  # pragma: no cover - defensive branch
                LOGGER.error("%s [ERROR] Thread %s gagal: %s", get_current_time(), index, exc)

    unique_domains = sorted(set(combined))
    LOGGER.info(
        "%s [INFO] Berhasil get total %s domain dari 5 threads paralel.",
        get_current_time(),
        len(unique_domains),
    )
    return unique_domains


def get_real_ip(proxies: Dict[str, str]) -> str:
    for url in ("https://api.ipify.org?format=json", "https://httpbin.org/ip"):
        try:
            response = requests.get(url, proxies=proxies, timeout=10)
            response.raise_for_status()
            data = response.json()
            if "ip" in data:
                return data["ip"]
            if "origin" in data:
                return data["origin"].split(",")[0].strip()
        except Exception:
            continue
    return "Unknown"


def get_otp_code(email: str) -> str:
    username, domain = email.split("@", 1)
    url = "https://generator.email/inbox/"
    headers = {
        "Host": "generator.email",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/117.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "id,en-US;q=0.7,en;q=0.3",
        "Accept-Encoding": "gzip, deflate",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-User": "?1",
        "Cookie": f"surl={domain}/{username}",
    }

    max_attempts = 15
    delay_seconds = 5
    LOGGER.info("%s Menunggu OTP untuk %s", get_current_time(), email)

    for attempt in range(1, max_attempts + 1):
        try:
            response = requests.get(url, headers=headers, timeout=15)
            response.raise_for_status()
            match = re.search(r"verification code is (\d{6})", response.text)
            if match:
                return match.group(1)
        except Exception:
            pass
        if attempt < max_attempts:
            time.sleep(delay_seconds)
    raise RuntimeError("Pengambilan OTP gagal setelah percobaan maksimum")


def regist_send_request(encrypted_email: str, encrypted_password: str, proxies: Dict[str, str]) -> Dict[str, object]:
    params = API_CONFIG.copy()
    data = {
        "mix_mode": "1",
        "email": encrypted_email,
        "password": encrypted_password,
        "type": "34",
        "fixed_mix_mode": "1",
    }
    response = requests.post(
        "https://www.capcut.com/passport/web/email/send_code/",
        params=params,
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        proxies=proxies,
        timeout=20,
    )
    response.raise_for_status()
    return response.json()


def verify_send_request(
    encrypted_email: str,
    encrypted_password: str,
    encrypted_code: str,
    proxies: Dict[str, str],
) -> Dict[str, object]:
    params = API_CONFIG.copy()
    data = {
        "mix_mode": "1",
        "email": encrypted_email,
        "code": encrypted_code,
        "password": encrypted_password,
        "type": "34",
        "birthday": faker.date_between(
            date(1990, 1, 1),
            date(2005, 12, 31),
        ).isoformat(),
        "force_user_region": "ID",
        "biz_param": "%7B%7D",
        "check_region": "1",
        "fixed_mix_mode": "1",
    }
    response = requests.post(
        "https://www.capcut.com/passport/web/email/register_verify_login/",
        params=params,
        data=data,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        },
        proxies=proxies,
        timeout=20,
    )
    response.raise_for_status()
    return response.json()


def create_single_account(
    selected_country: str,
    account_index: int,
    total_accounts: int,
    password_override: Optional[str],
) -> AccountResult:
    current_email = "Unknown"
    current_domain = "Unknown"
    current_ip = "Unknown"
    current_country = "Unknown"

    try:
        proxy_info = get_proxy_for_country(selected_country, account_index)
        proxies = _proxy_dict(proxy_info["proxy"])
        current_country = proxy_info["country"]

        LOGGER.info(
            "%s [%s/%s] Memeriksa alamat IP",
            get_current_time(),
            account_index + 1,
            total_accounts,
        )
        current_ip = get_real_ip(proxies)
        LOGGER.info("%s Menggunakan IP: %s (%s)", get_current_time(), current_ip, current_country)

        current_email = generate_email()
        current_domain = current_email.split("@", 1)[1]
        LOGGER.info("%s Email Dibuat: %s", get_current_time(), current_email)
        LOGGER.info("%s Menggunakan Domain: %s", get_current_time(), current_domain)

        password = password_override or CONFIG.get("password", "")
        encrypted_email = encrypt_to_target_hex(current_email)
        encrypted_password = encrypt_to_target_hex(password)

        LOGGER.info("%s Mengirim permintaan pendaftaran", get_current_time())
        reg_response = regist_send_request(encrypted_email, encrypted_password, proxies)

        if reg_response.get("message") == "success":
            LOGGER.info("%s Permintaan pendaftaran berhasil!", get_current_time())
            otp_code = get_otp_code(current_email)
            LOGGER.info("%s OTP Diterima: %s", get_current_time(), otp_code)
            LOGGER.info("%s Memverifikasi akun", get_current_time())
            encrypted_code = encrypt_to_target_hex(otp_code)
            verify_response = verify_send_request(
                encrypted_email,
                encrypted_password,
                encrypted_code,
                proxies,
            )
            if verify_response.get("message") == "success":
                LOGGER.info("%s ✅ Akun Berhasil Dibuat!", get_current_time())
                return AccountResult(
                    success=True,
                    ip=current_ip,
                    country=current_country,
                    domain=current_domain,
                    email=current_email,
                    password=password,
                )
            LOGGER.error(
                "%s ❌ Verifikasi gagal: %s",
                get_current_time(),
                verify_response.get("message") or "Error tidak diketahui",
            )
            return AccountResult(False, current_ip, current_country, current_domain, current_email)

        LOGGER.error(
            "%s ❌ Pendaftaran gagal: %s",
            get_current_time(),
            reg_response.get("message") or "Error tidak diketahui",
        )
        return AccountResult(False, current_ip, current_country, current_domain, current_email)

    except Exception as exc:
        LOGGER.error("%s ❌ Error saat membuat akun: %s", get_current_time(), exc)
        return AccountResult(False, current_ip, current_country, current_domain, current_email)


def run_create_batch(
    *,
    country: Optional[str],
    total: Optional[int],
    threads: Optional[int],
    password: Optional[str],
) -> Dict[str, object]:
    global DOMAINS

    fetched_domains = fetch_domains_parallel()
    if not fetched_domains:
        raise RuntimeError("Tidak ada domain yang tersedia dari generator.email")

    with domain_lock:
        DOMAINS = fetched_domains
        globals()["domain_index"] = 0

    selected_country = (country or DEFAULT_COUNTRY or "SG").upper()
    total_accounts = 1 if not total or total < 1 else total
    thread_count = 1 if not threads or threads < 1 else min(threads, 20)

    success_count = 0
    fail_count = 0
    successes: List[Dict[str, str]] = []
    ip_set: set[str] = set()
    domain_counts: Counter[str] = Counter()
    country_counts: Counter[str] = Counter()
    results: List[AccountResult] = []

    limit = thread_count
    attempts = 0
    max_attempts = max(total_accounts * 10, total_accounts)
    start_time = time.time()
    index_counter = 0

    with ThreadPoolExecutor(max_workers=limit) as executor:
        futures = set()
        while success_count < total_accounts and attempts < max_attempts:
            needed = max(0, total_accounts - success_count - len(futures))
            while (
                needed > 0
                and len(futures) < limit
                and (attempts + len(futures)) < max_attempts
            ):
                futures.add(
                    executor.submit(
                        create_single_account,
                        selected_country,
                        index_counter,
                        total_accounts,
                        password,
                    )
                )
                index_counter += 1
                needed -= 1

            if not futures:
                break

            done, futures = wait(futures, return_when=FIRST_COMPLETED)
            for future in done:
                result = future.result()
                attempts += 1
                results.append(result)

                if result.success:
                    success_count += 1
                    successes.append(
                        {
                            "email": result.email,
                            "password": password or CONFIG.get("password", ""),
                            "country": result.country,
                        }
                    )
                else:
                    fail_count += 1

                if result.ip != "Unknown":
                    ip_set.add(f"{result.ip}:{result.country}")
                if result.domain != "Unknown":
                    domain_counts[result.domain] += 1
                if result.country != "Unknown":
                    country_counts[result.country] += 1

                if success_count >= total_accounts or attempts >= max_attempts:
                    break

        for future in futures:
            future.cancel()

    total_time = int(time.time() - start_time)

    return {
        "selectedCountry": selected_country,
        "totalAccounts": total_accounts,
        "threadCount": limit,
        "successCount": success_count,
        "failCount": fail_count,
        "totalTimeSeconds": total_time,
        "successes": successes,
        "exhaustedRetries": success_count < total_accounts,
        "ipSet": sorted(ip_set),
        "domainCounts": dict(domain_counts),
        "countryCounts": dict(country_counts),
        "results": [result.__dict__ for result in results],
    }


# ---------------------------------------------------------------------------
# Rate limiting dan penyimpanan sederhana
# ---------------------------------------------------------------------------
PORT = int(os.environ.get("PORT", "8080"))
MAX_GLOBAL_PER_DAY = int(os.environ.get("MAX_GLOBAL_PER_DAY", "300"))
MAX_PER_IP_PER_DAY = int(os.environ.get("MAX_PER_IP_PER_DAY", "25"))
LOCAL_ONLY = os.environ.get("LOCAL_ONLY", "true").lower() == "true"


def today_str() -> str:
    now = datetime.now(timezone.utc)
    return now.strftime("%Y-%m-%d")


def load_usage() -> Dict[str, object]:
    if not USAGE_FILE.exists():
        return {"date": today_str(), "global_count": 0, "per_ip": {}}
    try:
        with USAGE_FILE.open("r", encoding="utf-8") as file:
            data = json.load(file)
    except Exception:
        return {"date": today_str(), "global_count": 0, "per_ip": {}}
    if data.get("date") != today_str():
        return {"date": today_str(), "global_count": 0, "per_ip": {}}
    if not isinstance(data.get("per_ip"), dict):
        data["per_ip"] = {}
    if not isinstance(data.get("global_count"), int):
        data["global_count"] = int(data.get("global_count", 0) or 0)
    return data


def save_usage(data: Dict[str, object]) -> None:
    USAGE_DIR.mkdir(parents=True, exist_ok=True)
    tmp_path = USAGE_FILE.with_suffix(".tmp")
    with tmp_path.open("w", encoding="utf-8") as temp_file:
        json.dump(data, temp_file)
    tmp_path.replace(USAGE_FILE)


def get_client_ip(headers: Dict[str, str], remote_address: Tuple[str, int]) -> str:
    x_forwarded_for = headers.get("x-forwarded-for")
    if isinstance(x_forwarded_for, str) and x_forwarded_for:
        return x_forwarded_for.split(",")[0].strip()
    x_real_ip = headers.get("x-real-ip")
    if isinstance(x_real_ip, str) and x_real_ip:
        return x_real_ip.strip()
    ip = remote_address[0] if remote_address else "127.0.0.1"
    return "127.0.0.1" if ip in {"::1", "::ffff:127.0.0.1"} else ip


def is_local_ip(ip: str) -> bool:
    return ip in {"127.0.0.1", "::1", "::ffff:127.0.0.1"}


# ---------------------------------------------------------------------------
# HTTP server (BaseHTTPRequestHandler)
# ---------------------------------------------------------------------------
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse


def send_json(handler: BaseHTTPRequestHandler, status: int, payload: Dict[str, object]) -> None:
    data = json.dumps(payload).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(data)))
    handler.end_headers()
    handler.wfile.write(data)


class CapcutRequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args) -> None:  # pragma: no cover - silence default logging
        LOGGER.debug("Server: " + format, *args)

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        parsed = urlparse(self.path)
        headers = {k.lower(): v for k, v in self.headers.items()}
        client_ip = get_client_ip(headers, self.client_address)

        if LOCAL_ONLY and not is_local_ip(client_ip):
            send_json(self, HTTPStatus.FORBIDDEN, {"error": "Forbidden: local access only", "ip": client_ip})
            return

        if parsed.path == "/health":
            send_json(self, HTTPStatus.OK, {"status": "ok", "time": datetime.utcnow().isoformat()})
            return
        if parsed.path == "/countries":
            send_json(
                self,
                HTTPStatus.OK,
                {
                    "availableCountries": list(PROXY_LIST.keys()),
                    "defaultCountry": DEFAULT_COUNTRY,
                    "info": "Tambah/ubah kode negara di config.json -> proxies",
                    "reference": "https://www.ssl.com/id/kode-negara-a/",
                },
            )
            return

        send_json(self, HTTPStatus.NOT_FOUND, {"error": "Not Found"})

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        parsed = urlparse(self.path)
        headers = {k.lower(): v for k, v in self.headers.items()}
        client_ip = get_client_ip(headers, self.client_address)

        if LOCAL_ONLY and not is_local_ip(client_ip):
            send_json(self, HTTPStatus.FORBIDDEN, {"error": "Forbidden: local access only", "ip": client_ip})
            return

        if parsed.path != "/create":
            send_json(self, HTTPStatus.NOT_FOUND, {"error": "Not Found"})
            return

        length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(length).decode("utf-8") if length else ""

        try:
            body = json.loads(raw_body) if raw_body else {}
        except json.JSONDecodeError:
            send_json(self, HTTPStatus.BAD_REQUEST, {"error": "Invalid JSON body"})
            return

        requested_country = body.get("country")
        country = "ALL" if requested_country == "ALL" else (requested_country or DEFAULT_COUNTRY)
        country = country.upper() if isinstance(country, str) else DEFAULT_COUNTRY

        if country != "ALL" and country not in PROXY_LIST:
            send_json(
                self,
                HTTPStatus.BAD_REQUEST,
                {
                    "error": f"Proxy untuk negara {country} tidak ditemukan. Atur di config.json -> proxies.",
                    "availableCountries": list(PROXY_LIST.keys()),
                },
            )
            return

        total = body.get("total")
        threads = body.get("threads")
        password = body.get("password")

        try:
            total_int = int(total) if total is not None else 1
        except (TypeError, ValueError):
            total_int = 1

        try:
            threads_int = int(threads) if threads is not None else 1
        except (TypeError, ValueError):
            threads_int = 1

        threads_int = max(1, min(threads_int, 2))
        password_str = password if isinstance(password, str) and password else None

        with usage_lock:
            usage = load_usage()
            per_ip = usage.setdefault("per_ip", {})
            ip_count = int(per_ip.get(client_ip, 0) or 0)
            if int(usage.get("global_count", 0)) >= MAX_GLOBAL_PER_DAY:
                send_json(self, HTTPStatus.TOO_MANY_REQUESTS, {"error": "Daily global limit reached", "limit": MAX_GLOBAL_PER_DAY})
                return
            if ip_count >= MAX_PER_IP_PER_DAY:
                send_json(
                    self,
                    HTTPStatus.TOO_MANY_REQUESTS,
                    {"error": "Daily per-IP limit reached", "limit": MAX_PER_IP_PER_DAY, "ip": client_ip},
                )
                return

        LOGGER.info(
            "\n🚀 Memulai batch create via API | country=%s total=%s threads=%s",
            country,
            total_int,
            threads_int,
        )

        try:
            summary = run_create_batch(
                country=country,
                total=total_int,
                threads=threads_int,
                password=password_str,
            )
        except Exception as exc:
            LOGGER.error("API Error: %s", exc)
            send_json(self, HTTPStatus.INTERNAL_SERVER_ERROR, {"error": str(exc)})
            return

        to_add = int(summary.get("successCount", 0) or 0)
        if to_add > 0:
            with usage_lock:
                updated = load_usage()
                updated["global_count"] = int(updated.get("global_count", 0) or 0) + to_add
                per_ip = updated.setdefault("per_ip", {})
                per_ip[client_ip] = int(per_ip.get(client_ip, 0) or 0) + to_add
                save_usage(updated)

        send_json(self, HTTPStatus.OK, summary)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main() -> None:
    server = ThreadingHTTPServer(("", PORT), CapcutRequestHandler)
    try:
        LOGGER.info("🚀 Backend berjalan di http://localhost:%s", PORT)
        server.serve_forever()
    except KeyboardInterrupt:  # pragma: no cover - manual stop
        LOGGER.info("Server dihentikan oleh pengguna")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
