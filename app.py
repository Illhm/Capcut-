"""CapCut account creator backend rewritten in Python.

This module replicates the behaviour of the original Node.js implementation
(app.js) using the Python standard library and third party packages.
"""
from __future__ import annotations

import json
import logging
import random
import re
import string
import threading
import time
from collections import Counter
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

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


@dataclass
class ProxyChoice:
    country: str
    proxy: Optional[str]


# ---------------------------------------------------------------------------
# Fungsi utilitas umum
# ---------------------------------------------------------------------------
def encrypt_to_target_hex(value: str) -> str:
    return "".join(f"{(ord(char) ^ 0x05):02x}" for char in value)


def _proxy_dict(proxy_url: str) -> Dict[str, str]:
    proxy_address = f"http://{proxy_url}"
    return {"http": proxy_address, "https": proxy_address}


def make_proxy_selector(
    proxy_mode: str,
    *,
    selected_country: Optional[str] = None,
    proxies_map: Optional[Dict[str, str]] = None,
    manual_proxy: Optional[str] = None,
    manual_label: Optional[str] = None,
) -> Tuple[Callable[[int], ProxyChoice], str]:
    """Buat fungsi pemilih proxy berdasarkan mode yang dipilih pengguna."""

    proxies_map = dict(proxies_map or {})
    countries = list(proxies_map.keys())
    default_country = (selected_country or DEFAULT_COUNTRY or "SG").upper()

    if proxy_mode == "direct" or (proxy_mode != "manual" and not proxies_map):
        def selector(_: int) -> ProxyChoice:
            return ProxyChoice(country="DIRECT", proxy=None)

        return selector, "Direct (tanpa proxy)"

    if proxy_mode == "manual":
        if not manual_proxy:
            raise ValueError("Manual proxy string is required for manual mode")
        label = (manual_label or selected_country or "CUSTOM").upper()

        def selector(_: int) -> ProxyChoice:
            return ProxyChoice(country=label, proxy=manual_proxy.strip())

        return selector, f"Manual proxy ({label})"

    if proxy_mode == "rotate":
        if not countries:
            raise ValueError("Proxy configuration kosong untuk mode rotasi")

        def selector(account_index: int) -> ProxyChoice:
            rotated = countries[account_index % len(countries)]
            return ProxyChoice(country=rotated, proxy=proxies_map[rotated])

        return selector, "Rotasi semua proxy di config.json"

    if proxy_mode == "fixed":
        if default_country not in proxies_map:
            raise ValueError(
                f"Proxy untuk negara {default_country} tidak ditemukan di config.json"
            )

        def selector(_: int) -> ProxyChoice:
            return ProxyChoice(country=default_country, proxy=proxies_map[default_country])

        return selector, f"Proxy {default_country} (config.json)"

    raise ValueError(f"Mode proxy tidak dikenal: {proxy_mode}")


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
    proxy_selector: Callable[[int], ProxyChoice],
    account_index: int,
    total_accounts: int,
    password_override: Optional[str],
) -> AccountResult:
    current_email = "Unknown"
    current_domain = "Unknown"
    current_ip = "Unknown"
    current_country = "Unknown"

    try:
        proxy_choice = proxy_selector(account_index)
        current_country = proxy_choice.country

        if proxy_choice.proxy:
            LOGGER.info(
                "%s [%s/%s] Menggunakan proxy %s (%s)",
                get_current_time(),
                account_index + 1,
                total_accounts,
                proxy_choice.proxy,
                current_country,
            )
            proxies = _proxy_dict(proxy_choice.proxy)
        else:
            LOGGER.info(
                "%s [%s/%s] Menggunakan koneksi langsung (tanpa proxy)",
                get_current_time(),
                account_index + 1,
                total_accounts,
            )
            proxies = {}

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
    proxy_selector: Callable[[int], ProxyChoice],
    proxy_label: str,
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
                        proxy_selector,
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
        "selectedCountry": proxy_label,
        "proxyLabel": proxy_label,
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
# Utilitas input interaktif
# ---------------------------------------------------------------------------


def prompt_int(prompt: str, default: int, *, minimum: int = 1, maximum: Optional[int] = None) -> int:
    while True:
        suffix = f" [{default}]" if default is not None else ""
        raw_value = input(f"{prompt}{suffix}: ").strip()
        if not raw_value:
            return default
        try:
            value = int(raw_value)
            if value < minimum:
                print(f"Nilai minimal adalah {minimum}.")
                continue
            if maximum is not None and value > maximum:
                print(f"Nilai maksimal adalah {maximum}.")
                continue
            return value
        except ValueError:
            print("Masukkan angka yang valid.")


def prompt_yes_no(prompt: str, default: bool = True) -> bool:
    suffix = "Y/n" if default else "y/N"
    while True:
        raw_value = input(f"{prompt} [{suffix}]: ").strip().lower()
        if not raw_value:
            return default
        if raw_value in {"y", "ya", "yes"}:
            return True
        if raw_value in {"n", "no"}:
            return False
        print("Jawab dengan y atau n.")


def prompt_choice(prompt: str, options: Dict[str, str], default_key: str) -> str:
    valid_keys = set(options.keys())
    while True:
        raw_value = input(f"{prompt} [{default_key}]: ").strip()
        if not raw_value:
            return default_key
        if raw_value in valid_keys:
            return raw_value
        print(f"Pilih salah satu opsi: {', '.join(valid_keys)}")


def configure_proxy_via_input() -> Tuple[Callable[[int], ProxyChoice], str]:
    proxies_map = CONFIG.get("proxies", {})
    use_proxy = prompt_yes_no("Gunakan proxy?", bool(proxies_map))

    if not use_proxy:
        return make_proxy_selector("direct")

    available_countries = list(proxies_map.keys())
    option_map: Dict[str, str] = {}
    option_index = 1

    print("\nMode proxy yang tersedia:")
    if available_countries:
        option_map[str(option_index)] = "rotate"
        print(f"  {option_index}. Rotasi semua proxy dari config.json")
        option_index += 1

        option_map[str(option_index)] = "fixed"
        print(f"  {option_index}. Gunakan negara tertentu dari config.json")
        option_index += 1

    option_map[str(option_index)] = "manual"
    print(f"  {option_index}. Masukkan proxy manual")

    choice = prompt_choice("Pilih mode proxy", option_map, next(iter(option_map)))
    selected_mode = option_map[choice]

    if selected_mode == "rotate":
        return make_proxy_selector("rotate", proxies_map=proxies_map)

    if selected_mode == "fixed":
        default_country = (DEFAULT_COUNTRY or (available_countries[0] if available_countries else "SG")).upper()
        while True:
            country_input = input(
                f"Masukkan kode negara yang tersedia ({', '.join(available_countries)}) [{default_country}]: "
            ).strip()
            country_code = (country_input or default_country).upper()
            if country_code in proxies_map:
                return make_proxy_selector(
                    "fixed",
                    selected_country=country_code,
                    proxies_map=proxies_map,
                )
            print("Kode negara tidak ditemukan di config.json.")

    manual_proxy = ""
    while not manual_proxy:
        manual_proxy = input("Masukkan proxy manual (misal user:pass@host:port): ").strip()
        if not manual_proxy:
            print("Proxy tidak boleh kosong.")
    manual_label = input("Label/negara untuk proxy ini [CUSTOM]: ").strip() or "CUSTOM"
    return make_proxy_selector(
        "manual",
        selected_country=manual_label,
        manual_proxy=manual_proxy,
        manual_label=manual_label,
    )


def print_summary(summary: Dict[str, object]) -> None:
    print("\n=== Ringkasan ===")
    print(f"Mode proxy   : {summary.get('proxyLabel', 'N/A')}")
    print(f"Total akun   : {summary.get('totalAccounts')}")
    print(f"Sukses       : {summary.get('successCount')}")
    print(f"Gagal        : {summary.get('failCount')}")
    print(f"Waktu proses : {summary.get('totalTimeSeconds')} detik")

    successes = summary.get("successes") or []
    if successes:
        print("\nAkun berhasil (email | password | negara):")
        for index, account in enumerate(successes, start=1):
            print(
                f"  {index}. {account.get('email')} | {account.get('password')} | {account.get('country')}"
            )
    else:
        print("\nTidak ada akun yang berhasil dibuat pada batch ini.")

    country_counts = summary.get("countryCounts") or {}
    if country_counts:
        print("\nStatistik negara:")
        for country, count in sorted(country_counts.items()):
            print(f"  {country}: {count}")

    domain_counts = summary.get("domainCounts") or {}
    if domain_counts:
        print("\nDomain yang terpakai:")
        for domain, count in sorted(domain_counts.items(), key=lambda item: item[1], reverse=True):
            print(f"  {domain}: {count}")

    ip_set = summary.get("ipSet") or []
    if ip_set:
        print("\nIP yang digunakan:")
        for value in ip_set:
            print(f"  - {value}")


def main() -> None:
    print("=" * 60)
    print("CapCut Account Generator - Mode Lokal")
    print("=" * 60)

    total_accounts = prompt_int("Jumlah akun yang ingin dibuat", 1, minimum=1)
    thread_limit = prompt_int("Jumlah thread paralel (maks 20)", 1, minimum=1, maximum=20)
    total_threads = min(thread_limit, total_accounts)

    password_input = input("Password akun (kosong = gunakan dari config.json): ").strip()
    password_override = password_input or None

    proxy_selector, proxy_label = configure_proxy_via_input()

    print("\nKonfigurasi yang dipakai:")
    print(f"- Mode proxy    : {proxy_label}")
    print(f"- Total akun    : {total_accounts}")
    print(f"- Thread paralel: {total_threads}")
    print(
        "- Password      : "
        + ("(pakai default dari config.json)" if password_override is None else "(manual)")
    )

    if not prompt_yes_no("Lanjutkan pembuatan akun?", True):
        print("Dibatalkan oleh pengguna.")
        return

    try:
        summary = run_create_batch(
            proxy_selector=proxy_selector,
            proxy_label=proxy_label,
            total=total_accounts,
            threads=total_threads,
            password=password_override,
        )
    except Exception as exc:  # pragma: no cover - interaktif manual
        LOGGER.error("Gagal menjalankan batch: %s", exc)
        print(f"\n❌ Terjadi kesalahan: {exc}")
        return

    print_summary(summary)


if __name__ == "__main__":
    main()
