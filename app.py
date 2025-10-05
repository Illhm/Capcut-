"""Interactive CapCut account generator in Python.

This script replaces the previous HTTP backend with a local, interactive
account generator.  Users can choose whether the generator should use a proxy
connection or connect directly, and all configuration is provided through
``input`` prompts instead of command line flags or HTTP requests.
"""
from __future__ import annotations

import json
import logging
import random
import re
import string
import sys
import time
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Dict, Iterable, List, Optional

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

faker = Faker()

with CONFIG_PATH.open("r", encoding="utf-8") as config_file:
    CONFIG = json.load(config_file)

PROXY_LIST: Dict[str, str] = CONFIG.get("proxies", {})
DEFAULT_COUNTRY = (CONFIG.get("default_country") or "SG").upper()
API_CONFIG = {
    "aid": "348188",
    "account_sdk_source": "web",
    "language": "en",
    "verifyFp": "verify_mbdaqk11_drZniKX9_gJP3_4mPC_91ao_aWYAyvFlKVWh",
    "check_region": "1",
}

DOMAINS: List[str] = []
domain_index = 0


# ---------------------------------------------------------------------------
# Helper dataclass
# ---------------------------------------------------------------------------
@dataclass
class AccountResult:
    success: bool
    ip: str
    country: str
    domain: str
    email: str
    password: Optional[str] = None
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Fungsi utilitas umum
# ---------------------------------------------------------------------------
def encrypt_to_target_hex(value: str) -> str:
    return "".join(f"{(ord(char) ^ 0x05):02x}" for char in value)


def _proxy_dict(proxy_url: Optional[str]) -> Optional[Dict[str, str]]:
    if not proxy_url:
        return None
    proxy_address = f"http://{proxy_url}" if not proxy_url.startswith("http") else proxy_url
    return {"http": proxy_address, "https": proxy_address}


def generate_email() -> str:
    global domain_index

    if not DOMAINS:
        raise RuntimeError("Tidak ada domain yang tersedia. Jalankan fetch domain terlebih dahulu.")

    selected_domain = DOMAINS[domain_index % len(DOMAINS)]
    domain_index += 1

    name = re.sub(r"[^a-z]", "", faker.first_name().lower())
    num_length = random.randint(1, 5)
    random_numbers = "".join(random.choices(string.digits, k=num_length))
    random_letter = random.choice(string.ascii_lowercase)
    username = f"{name}{random_numbers}{random_letter}"
    return f"{username}@{selected_domain}"


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
        LOGGER.error("[ERROR] Gagal mengambil domain: %s", exc)
        return []


def fetch_domains_parallel(attempts: int = 5) -> List[str]:
    from concurrent.futures import ThreadPoolExecutor

    LOGGER.info("Mengambil daftar domain terbaru dengan %s percobaan paralel", attempts)
    combined: List[str] = []

    with ThreadPoolExecutor(max_workers=attempts) as executor:
        futures = [executor.submit(fetch_domains_once) for _ in range(attempts)]
        for index, future in enumerate(futures, start=1):
            try:
                domains = future.result()
                LOGGER.info("Thread %s mendapatkan %s domain", index, len(domains))
                combined.extend(domains)
            except Exception as exc:  # pragma: no cover - defensive branch
                LOGGER.error("Thread %s gagal: %s", index, exc)

    unique_domains = sorted(set(combined))
    LOGGER.info("Total domain unik yang diperoleh: %s", len(unique_domains))
    return unique_domains


def get_real_ip(proxies: Optional[Dict[str, str]]) -> str:
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
    LOGGER.info("Menunggu OTP untuk %s", email)

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


def regist_send_request(encrypted_email: str, encrypted_password: str, proxies: Optional[Dict[str, str]]) -> Dict[str, object]:
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
    proxies: Optional[Dict[str, str]],
) -> Dict[str, object]:
    params = API_CONFIG.copy()
    data = {
        "mix_mode": "1",
        "email": encrypted_email,
        "code": encrypted_code,
        "password": encrypted_password,
        "type": "34",
        "birthday": faker.date_between(date(1990, 1, 1), date(2005, 12, 31)).isoformat(),
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


# ---------------------------------------------------------------------------
# Inti pembuatan akun
# ---------------------------------------------------------------------------
def create_single_account(
    proxy_country: str,
    proxy_value: Optional[str],
    account_index: int,
    total_accounts: int,
    password_override: Optional[str],
) -> AccountResult:
    current_email = "Unknown"
    current_domain = "Unknown"
    current_ip = "Unknown"
    current_country = proxy_country or "Unknown"
    password_value = password_override or CONFIG.get("password", "")

    try:
        proxies = _proxy_dict(proxy_value)

        LOGGER.info("[%s/%s] Memeriksa alamat IP", account_index + 1, total_accounts)
        current_ip = get_real_ip(proxies)
        LOGGER.info("Menggunakan IP: %s (%s)", current_ip, current_country)

        current_email = generate_email()
        current_domain = current_email.split("@", 1)[1]
        LOGGER.info("Email Dibuat: %s", current_email)
        LOGGER.info("Menggunakan Domain: %s", current_domain)

        encrypted_email = encrypt_to_target_hex(current_email)
        encrypted_password = encrypt_to_target_hex(password_value)

        LOGGER.info("Mengirim permintaan pendaftaran")
        reg_response = regist_send_request(encrypted_email, encrypted_password, proxies)

        if reg_response.get("message") == "success":
            LOGGER.info("Permintaan pendaftaran berhasil, menunggu OTP")
            otp_code = get_otp_code(current_email)
            LOGGER.info("OTP Diterima: %s", otp_code)
            LOGGER.info("Memverifikasi akun")
            encrypted_code = encrypt_to_target_hex(otp_code)
            verify_response = verify_send_request(
                encrypted_email,
                encrypted_password,
                encrypted_code,
                proxies,
            )
            if verify_response.get("message") == "success":
                LOGGER.info("✅ Akun Berhasil Dibuat!")
                return AccountResult(
                    success=True,
                    ip=current_ip,
                    country=current_country,
                    domain=current_domain,
                    email=current_email,
                    password=password_value,
                )
            LOGGER.error("❌ Verifikasi gagal: %s", verify_response.get("message") or "Error tidak diketahui")
            return AccountResult(
                False,
                current_ip,
                current_country,
                current_domain,
                current_email,
                password_value,
                "Verifikasi gagal",
            )

        error_message = reg_response.get("message") or "Error tidak diketahui"
        LOGGER.error("❌ Pendaftaran gagal: %s", error_message)
        return AccountResult(
            False,
            current_ip,
            current_country,
            current_domain,
            current_email,
            password_value,
            error_message,
        )

    except Exception as exc:
        LOGGER.error("❌ Error saat membuat akun: %s", exc)
        return AccountResult(
            False,
            current_ip,
            current_country,
            current_domain,
            current_email,
            password_value,
            str(exc),
        )


def cycle_proxy_values(selection: Dict[str, object]) -> Iterable[Dict[str, Optional[str]]]:
    mode = selection.get("mode", "direct")

    if mode == "direct":
        while True:
            yield {"country": "DIRECT", "proxy": None}

    if mode == "custom":
        proxy_value = selection.get("proxy")
        label = selection.get("label", "CUSTOM")
        while True:
            yield {"country": label, "proxy": proxy_value}

    if mode == "all":
        countries: List[str] = selection.get("countries", [])
        if not countries:
            raise ValueError("Daftar negara kosong untuk mode ALL")
        index = 0
        while True:
            country = countries[index % len(countries)]
            index += 1
            yield {"country": country, "proxy": PROXY_LIST.get(country)}

    country = selection.get("country") or DEFAULT_COUNTRY
    proxy_value = PROXY_LIST.get(country)
    if proxy_value is None:
        raise ValueError(f"Proxy untuk negara {country} tidak ditemukan. Periksa config.json")
    while True:
        yield {"country": country, "proxy": proxy_value}


def run_create_batch(
    *,
    total: int,
    password: Optional[str],
    proxy_selection: Dict[str, object],
) -> Dict[str, object]:
    global DOMAINS, domain_index

    fetched_domains = fetch_domains_parallel()
    if not fetched_domains:
        raise RuntimeError("Tidak ada domain yang tersedia dari generator.email")

    DOMAINS = fetched_domains
    domain_index = 0

    proxy_cycle = cycle_proxy_values(proxy_selection)

    success_count = 0
    fail_count = 0
    results: List[AccountResult] = []
    start_time = time.time()

    for index in range(total):
        proxy_info = next(proxy_cycle)
        result = create_single_account(
            proxy_info.get("country", "Unknown"),
            proxy_info.get("proxy"),
            index,
            total,
            password,
        )
        results.append(result)
        if result.success:
            success_count += 1
        else:
            fail_count += 1

    total_time = int(time.time() - start_time)

    successes = [
        {
            "email": result.email,
            "password": result.password,
            "country": result.country,
            "ip": result.ip,
            "domain": result.domain,
        }
        for result in results
        if result.success
    ]

    failures = [
        {
            "email": result.email,
            "country": result.country,
            "ip": result.ip,
            "domain": result.domain,
            "error": result.error,
        }
        for result in results
        if not result.success
    ]

    return {
        "totalAccounts": total,
        "successCount": success_count,
        "failCount": fail_count,
        "totalTimeSeconds": total_time,
        "successes": successes,
        "failures": failures,
    }


# ---------------------------------------------------------------------------
# Input helper
# ---------------------------------------------------------------------------
def prompt_yes_no(message: str) -> bool:
    while True:
        answer = input(f"{message} (y/n): ").strip().lower()
        if answer in {"y", "yes"}:
            return True
        if answer in {"n", "no"}:
            return False
        print("Masukkan 'y' atau 'n'.")


def prompt_int(message: str, default: int = 1) -> int:
    while True:
        value = input(f"{message} (default {default}): ").strip()
        if not value:
            return default
        if value.isdigit() and int(value) > 0:
            return int(value)
        print("Masukkan angka bulat positif.")


def prompt_password(default_password: str) -> Optional[str]:
    if not default_password:
        custom = input("Masukkan password untuk akun baru: ").strip()
        return custom or None
    use_default = prompt_yes_no(f"Gunakan password default dari config.json ({default_password})?")
    if use_default:
        return default_password
    custom = input("Masukkan password baru: ").strip()
    return custom or default_password


def prompt_proxy_selection() -> Dict[str, object]:
    if not PROXY_LIST:
        print("Tidak ada proxy di config.json. Masukkan proxy manual.")
        proxy_value = input("Proxy (format user:pass@host:port atau host:port): ").strip()
        if not proxy_value:
            raise ValueError("Proxy wajib diisi ketika memilih mode proxy.")
        return {"mode": "custom", "proxy": proxy_value, "label": "CUSTOM"}

    countries = sorted(PROXY_LIST.keys())
    print("Daftar proxy yang tersedia di config.json:")
    for code in countries:
        print(f" - {code}: {PROXY_LIST[code]}")
    if len(countries) > 1:
        print("Anda dapat mengetik ALL untuk rotasi otomatis antar proxy.")

    while True:
        choice = input(
            "Masukkan kode negara proxy (contoh SG) atau ALL / custom proxy manual: "
        ).strip()
        if not choice:
            continue
        upper_choice = choice.upper()
        if upper_choice == "ALL" and len(countries) > 1:
            return {"mode": "all", "countries": countries}
        if upper_choice in PROXY_LIST:
            return {"mode": "country", "country": upper_choice}
        if ":" in choice:
            return {"mode": "custom", "proxy": choice, "label": "CUSTOM"}
        print("Input tidak valid. Coba lagi.")


def print_summary(summary: Dict[str, object]) -> None:
    print("\n===== RANGKUMAN =====")
    print(f"Total akun diminta : {summary['totalAccounts']}")
    print(f"Berhasil          : {summary['successCount']}")
    print(f"Gagal             : {summary['failCount']}")
    print(f"Durasi (detik)    : {summary['totalTimeSeconds']}")

    if summary["successes"]:
        print("\nAkun berhasil:")
        for item in summary["successes"]:
            print(
                f" - {item['email']} | Password: {item['password']} | Negara: {item['country']} | IP: {item['ip']} | Domain: {item['domain']}"
            )
    if summary["failures"]:
        print("\nAkun gagal:")
        for item in summary["failures"]:
            print(
                f" - {item['email']} | Negara: {item['country']} | IP: {item['ip']} | Domain: {item['domain']} | Error: {item['error']}"
            )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def interactive_main() -> None:
    print("=== CapCut Account Generator ===")
    print("Semua konfigurasi diminta melalui input. Tekan Ctrl+C untuk keluar.\n")

    use_proxy = prompt_yes_no("Gunakan proxy?")
    if use_proxy:
        proxy_selection = prompt_proxy_selection()
    else:
        proxy_selection = {"mode": "direct"}

    total_accounts = prompt_int("Berapa akun yang ingin dibuat?", default=1)
    password = prompt_password(CONFIG.get("password", ""))

    try:
        summary = run_create_batch(
            total=total_accounts,
            password=password,
            proxy_selection=proxy_selection,
        )
    except KeyboardInterrupt:
        print("\nDibatalkan oleh pengguna.")
        sys.exit(1)
    except Exception as exc:  # pragma: no cover - defensive branch
        print(f"Terjadi kesalahan: {exc}")
        sys.exit(1)

    print_summary(summary)


if __name__ == "__main__":
    interactive_main()
