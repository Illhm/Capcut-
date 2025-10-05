import axios from 'axios';
import chalk from 'chalk';
import { faker } from '@faker-js/faker';
import { promises as fs, readFileSync } from 'fs';
import { HttpsProxyAgent } from 'https-proxy-agent';
import { JSDOM } from 'jsdom';
import pLimit from 'p-limit';
import fetch from 'node-fetch';
import http from 'http';

// --- Konfigurasi Proxy (bisa diatur lewat config.json) ---
// Struktur yang didukung di config.json:
// {
//   "password": "...",
//   "proxies": { "SG": "user__cr.sg:pass@gw.dataimpulse.com:823" },
//   "default_country": "SG"
// }

// --- Konfigurasi Domain ---
let DOMAINS = [];
let domainIndex = 0; // Variabel global untuk melacak indeks domain yang digunakan

// --- Konfigurasi API ---
const config = JSON.parse(readFileSync('./config.json', 'utf-8'));
const PROXY_LIST = (config && config.proxies) ? config.proxies : {
  SG: 'username__cr.sg:password@gw.dataimpulse.com:823'
};
const DEFAULT_COUNTRY = (config && config.default_country) ? config.default_country : 'SG';
const API_CONFIG = {
  aid: '348188',
  account_sdk_source: 'web',
  language: 'en',
  verifyFp: 'verify_mbdaqk11_drZniKX9_gJP3_4mPC_91ao_aWYAyvFlKVWh',
  check_region: '1'
};

// --- Fungsi Utilitas ---
function createProxyAgent(proxyUrl) {
  return new HttpsProxyAgent(`http://${proxyUrl}`);
}

function encryptToTargetHex(input) {
  return [...input].map(char => (char.charCodeAt(0) ^ 0x05).toString(16).padStart(2, '0')).join('');
}

// FUNGSI UNTUK MEMBUAT EMAIL (dengan pemilihan domain berurutan)
function generateEmail() {
  if (DOMAINS.length === 0) {
    throw new Error('Tidak ada domain yang tersedia');
  }

  // 1. Mengambil nama depan dari faker dan membersihkannya (lowercase, tanpa spasi/simbol)
  const name = faker.person.firstName().toLowerCase().replace(/[^a-z]/g, '');

  // 2. Menghasilkan 1 sampai 4 angka acak
  const numLength = Math.floor(Math.random() * 5) + 1; 
  let randomNumbers = '';
  for (let i = 0; i < numLength; i++) {
    randomNumbers += Math.floor(Math.random() * 10).toString();
  }

  // 3. Menghasilkan 1 huruf acak
  const chars = 'abcdefghijklmnopqrstuvwxyz';
  const randomLetter = chars.charAt(Math.floor(Math.random() * chars.length));

  // 4. Menggabungkan semua bagian menjadi username
  const username = `${name}${randomNumbers}${randomLetter}`;

  // 5. Memilih domain secara berurutan dan merotasi
  const selectedDomain = DOMAINS[domainIndex];
  domainIndex = (domainIndex + 1) % DOMAINS.length; // Rotasi indeks kembali ke 0 jika sudah mencapai akhir

  return `${username}@${selectedDomain}`;
}


function getCurrentTime() {
  const now = new Date();
  return `[${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}]`;
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// --- Fungsi Pengambilan IP ---
async function getRealIP(proxyAgent) {
  try {
    const response = await axios.get('https://api.ipify.org?format=json', {
      httpsAgent: proxyAgent,
      timeout: 10000
    });
    return response.data.ip;
  } catch {
    try {
      const response = await axios.get('https://httpbin.org/ip', {
        httpsAgent: proxyAgent,
        timeout: 10000
      });
      return response.data.origin.split(',')[0].trim();
    } catch {
      return 'Unknown';
    }
  }
}

// --- Fungsi Rotasi Proxy ---
function getProxyForCountry(selectedCountry, accountIndex) {
  if (selectedCountry === 'ALL') {
    const countries = Object.keys(PROXY_LIST);
    const rotatedCountry = countries[accountIndex % countries.length];
    return {
      country: rotatedCountry,
      proxy: PROXY_LIST[rotatedCountry]
    };
  }
  return {
    country: selectedCountry,
    proxy: PROXY_LIST[selectedCountry]
  };
}

// --- (Hapus) Fungsi Input Pengguna - tidak digunakan pada mode backend ---

// --- Fungsi Pengambilan Domain Satu Kali ---
async function fetchDomainsOnce() {
  const url = 'https://generator.email/inbox/';
  try {
    const response = await fetch(url);
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }
    const htmlString = await response.text();
    const dom = new JSDOM(htmlString);
    const doc = dom.window.document;
    const domainParagraphs = doc.querySelectorAll('#newselect p');
    const extractedDomains = [];
    domainParagraphs.forEach(p => {
      const domain = p.textContent.trim();
      if (
        domain.length > 0 &&
        !domain.includes('@') &&
        !/\d/.test(domain) &&
        domain.includes('.')
      ) {
        // Memisahkan nama domain dari TLD
        const domainParts = domain.split('.');
        if (domainParts.length >= 2) {
          const domainName = domainParts[0]; // Mengambil bagian sebelum TLD
          // Cek apakah nama domain tidak lebih dari 10 karakter
          if (domainName.length <= 13) {
            extractedDomains.push(domain);
          }
        }
      }
    });
    return extractedDomains;
  } catch (error) {
    console.error(chalk.red(`${getCurrentTime()} [ERROR] Gagal mengambil domain: ${error.message}`));
    return [];
  }
}

// --- Fungsi Pengambilan Domain Lima Kali dengan Parallel Threads ---
async function fetchDomainsFromGeneratorEmail() {
  console.log(chalk.blue(`${getCurrentTime()} [INFO] Mengambil daftar domain terbaru dengan 5 threads parallel`));
  const domainsSet = new Set();

  // Menjalankan 5 fetch secara parallel menggunakan Promise.all
  const fetchPromises = Array.from({ length: 5 }, (_, i) => {
    console.log(chalk.gray(`${getCurrentTime()} [INFO] Memulai fetch thread ${i + 1}/5`));
    return fetchDomainsOnce();
  });

  try {
    const allDomainsArrays = await Promise.all(fetchPromises);
    
    // Menggabungkan semua hasil tanpa duplikat
    allDomainsArrays.forEach((domainsArray, index) => {
      console.log(chalk.gray(`${getCurrentTime()} [INFO] Thread ${index + 1} berhasil mendapat ${domainsArray.length} domain`));
      domainsArray.forEach(d => domainsSet.add(d));
    });

    const combinedDomains = Array.from(domainsSet);
    console.log(chalk.green(`${getCurrentTime()} [INFO] Berhasil get total ${combinedDomains.length} domain dari 5 threads parallel.`));
    return combinedDomains;
  } catch (error) {
    console.error(chalk.red(`${getCurrentTime()} [ERROR] Error dalam parallel fetch: ${error.message}`));
    return [];
  }
}

// --- Fungsi Pengambilan OTP ---
async function getOTPCode(email) {
  const [username, domain] = email.split('@');
  const url = 'https://generator.email/inbox/';
  const headers = {
    Host: 'generator.email',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/117.0',
    Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'Accept-Language': 'id,en-US;q=0.7,en;q=0.3',
    'Accept-Encoding': 'gzip, deflate',
    'Upgrade-Insecure-Requests': '1',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'same-origin',
    'Sec-Fetch-User': '?1',
    Cookie: `surl=${domain}/${username}`
  };

  const MAX_ATTEMPTS = 15;
  const RETRY_DELAY = 5000;

  process.stdout.write(chalk.yellow(`${getCurrentTime()} Menunggu OTP untuk ${email}`));

  let otpCode = null;
  let attempts = 0;

  while (!otpCode && attempts < MAX_ATTEMPTS) {
    try {
      const response = await axios.get(url, {
        headers,
        timeout: 15000
      });
      const html = response.data;
      const dom = new JSDOM(html);
      const match = dom.window.document.body.innerHTML.match(/verification code is (\d{6})/);
      if (match && match[1]) {
        otpCode = match[1];
        break;
      }
    } catch {
      // Abaikan error untuk retry
    }
    await sleep(RETRY_DELAY);
    attempts++;
    process.stdout.write(chalk.gray('.'));
  }

  process.stdout.write('\n');
  if (!otpCode) throw new Error('Pengambilan OTP gagal setelah percobaan maksimum');
  return otpCode;
}

// --- API Request Functions ---
async function registSendRequest(encryptedEmail, encryptedPassword, proxyAgent) {
  const url = new URL('https://www.capcut.com/passport/web/email/send_code/');
  Object.entries(API_CONFIG).forEach(([k, v]) => url.searchParams.append(k, v));

  const formData = new URLSearchParams({
    mix_mode: '1',
    email: encryptedEmail,
    password: encryptedPassword,
    type: '34',
    fixed_mix_mode: '1'
  });

  const response = await axios.post(url.toString(), formData.toString(), {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    httpsAgent: proxyAgent,
    timeout: 20000
  });

  return response.data;
}

async function verifySendRequest(encryptedEmail, encryptedPassword, encryptedCode, proxyAgent) {
  const url = new URL('https://www.capcut.com/passport/web/email/register_verify_login/');
  Object.entries(API_CONFIG).forEach(([k, v]) => url.searchParams.append(k, v));

  const formData = new URLSearchParams({
    mix_mode: '1',
    email: encryptedEmail,
    code: encryptedCode,
    password: encryptedPassword,
    type: '34',
    birthday: new Date(faker.date.birthdate({ mode: 'year', min: 1990, max: 2005 })).toISOString().split('T')[0],
    force_user_region: 'ID',
    biz_param: '%7B%7D',
    check_region: '1',
    fixed_mix_mode: '1'
  });

  const response = await axios.post(url.toString(), formData.toString(), {
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    },
    httpsAgent: proxyAgent,
    timeout: 20000
  });

  return response.data;
}

// --- Fungsi Pembuatan Akun ---
async function createSingleAccount(selectedCountry, accountIndex, totalAccounts, passwordOverride) {
  let currentEmail = 'Unknown';
  let currentDomain = 'Unknown';
  let currentIP = 'Unknown';
  let currentCountry = 'Unknown';

  try {
    const proxyInfo = getProxyForCountry(selectedCountry, accountIndex);
    const proxyAgent = createProxyAgent(proxyInfo.proxy);
    currentCountry = proxyInfo.country;

    console.log(chalk.yellow(`${getCurrentTime()} [${accountIndex + 1}/${totalAccounts}] Memeriksa alamat IP`));
    currentIP = await getRealIP(proxyAgent);
    console.log(chalk.blue(`${getCurrentTime()} Menggunakan IP: ${currentIP} (${currentCountry})`));

    currentEmail = generateEmail();
    currentDomain = currentEmail.split('@')[1];
    console.log(chalk.green(`${getCurrentTime()} Email Dibuat: ${currentEmail}`));
    console.log(chalk.cyan(`${getCurrentTime()} Menggunakan Domain: ${currentDomain}`));

    const password = passwordOverride || config.password;
    const encryptedEmail = encryptToTargetHex(currentEmail);
    const encryptedPassword = encryptToTargetHex(password);

    console.log(chalk.yellow(`${getCurrentTime()} Mengirim permintaan pendaftaran`));
    const regResponse = await registSendRequest(encryptedEmail, encryptedPassword, proxyAgent);

    if (regResponse.message === "success") {
      console.log(chalk.green(`${getCurrentTime()} Permintaan pendaftaran berhasil!`));

      const otpCode = await getOTPCode(currentEmail);
      console.log(chalk.green(`${getCurrentTime()} OTP Diterima: ${otpCode}`));

      console.log(chalk.yellow(`${getCurrentTime()} Memverifikasi akun`));
      const encryptedCode = encryptToTargetHex(otpCode);
      const verifyResponse = await verifySendRequest(encryptedEmail, encryptedPassword, encryptedCode, proxyAgent);

      if (verifyResponse.message === "success") {
        await fs.writeFile('akuns.txt', `${currentEmail}\n`, { flag: 'a' });
        console.log(chalk.green(`${getCurrentTime()} ✅ Akun Berhasil Dibuat!`));
        console.log(chalk.green(`${getCurrentTime()} 💾 Akun disimpan ke akuns.txt`));
        return { success: true, ip: currentIP, country: currentCountry, domain: currentDomain, email: currentEmail };
      } else {
        console.log(chalk.red(`${getCurrentTime()} ❌ Verifikasi gagal: ${verifyResponse.message || 'Error tidak diketahui'}`));
        return { success: false, ip: currentIP, country: currentCountry, domain: currentDomain, email: currentEmail };
      }
    } else {
      console.log(chalk.red(`${getCurrentTime()} ❌ Pendaftaran gagal: ${regResponse.message || 'Error tidak diketahui'}`));
      return { success: false, ip: currentIP, country: currentCountry, domain: currentDomain, email: currentEmail };
    }
  } catch (error) {
    console.error(chalk.red(`${getCurrentTime()} ❌ Error saat membuat akun: ${error.message}`));
    return { success: false, ip: currentIP, country: currentCountry, domain: currentDomain, email: currentEmail };
  }
}

// --- Fungsi util untuk menjalankan pembuatan akun batch ---
async function runCreateBatch({ country, total, threads, password }) {
  const fetchedDomains = await fetchDomainsFromGeneratorEmail();
  if (fetchedDomains.length > 0) {
    DOMAINS = fetchedDomains;
  } else {
    throw new Error('Tidak ada domain yang tersedia dari generator.email');
  }

  const selectedCountry = country || DEFAULT_COUNTRY || 'SG';
  const totalAccounts = (!total || total < 1) ? 1 : total;
  const threadCount = (!threads || threads < 1) ? 1 : (threads > 20 ? 20 : threads);

  let successCount = 0;
  let failCount = 0;
  const allIPs = new Set();
  const domainCounts = {};
  const countryCounts = {};

  const limit = pLimit(threadCount);

  const tasks = Array.from({ length: totalAccounts }, (_, i) => {
    return limit(async () => {
      const result = await createSingleAccount(selectedCountry, i, totalAccounts, password);

      if (result.success) {
        successCount++;
      } else {
        failCount++;
      }

      if (result.ip !== 'Unknown') {
        allIPs.add(`${result.ip}:${result.country}`);
      }

      if (result.domain !== 'Unknown') {
        domainCounts[result.domain] = (domainCounts[result.domain] || 0) + 1;
      }

      if (result.country !== 'Unknown') {
        countryCounts[result.country] = (countryCounts[result.country] || 0) + 1;
      }

      return result;
    });
  });

  const startTime = Date.now();
  const results = await Promise.all(tasks);
  const endTime = Date.now();
  const totalTime = Math.round((endTime - startTime) / 1000);

  return {
    selectedCountry,
    totalAccounts,
    threadCount,
    successCount,
    failCount,
    totalTimeSeconds: totalTime,
    accountsSavedFile: 'akuns.txt',
    ipSet: Array.from(allIPs),
    domainCounts,
    countryCounts,
    results
  };
}

// --- HTTP Server (tanpa framework eksternal) ---
const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 8080;

function sendJson(res, statusCode, payload) {
  const data = JSON.stringify(payload);
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(data)
  });
  res.end(data);
}

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => { body += chunk.toString(); });
    req.on('end', () => {
      if (!body) return resolve({});
      try {
        resolve(JSON.parse(body));
      } catch (e) {
        reject(new Error('Invalid JSON body'));
      }
    });
    req.on('error', reject);
  });
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host}`);

    if (req.method === 'GET' && url.pathname === '/health') {
      return sendJson(res, 200, { status: 'ok', time: new Date().toISOString() });
    }

    if (req.method === 'GET' && url.pathname === '/countries') {
      return sendJson(res, 200, {
        availableCountries: Object.keys(PROXY_LIST),
        defaultCountry: DEFAULT_COUNTRY,
        info: 'Tambah/ubah kode negara di config.json -> proxies',
        reference: 'https://www.ssl.com/id/kode-negara-a/'
      });
    }

    if (req.method === 'POST' && url.pathname === '/create') {
      const body = await parseBody(req);
      const country = body.country === 'ALL' ? 'ALL' : (body.country || DEFAULT_COUNTRY);

      if (country !== 'ALL' && !PROXY_LIST[country]) {
        return sendJson(res, 400, { error: `Proxy untuk negara ${country} tidak ditemukan. Atur di config.json -> proxies.`, availableCountries: Object.keys(PROXY_LIST) });
      }

      const total = parseInt(body.total, 10) || 1;
      const threads = parseInt(body.threads, 10) || 1;
      const password = typeof body.password === 'string' && body.password.length > 0 ? body.password : undefined;

      console.log(chalk.magenta.bold(`\n🚀 Memulai batch create via API | country=${country} total=${total} threads=${threads}`));
      const summary = await runCreateBatch({ country, total, threads, password });
      return sendJson(res, 200, summary);
    }

    // Not found
    sendJson(res, 404, { error: 'Not Found' });
  } catch (error) {
    console.error(chalk.red(`API Error: ${error.message}`));
    sendJson(res, 500, { error: error.message });
  }
});

server.listen(PORT, () => {
  console.log(chalk.magenta.bold(`🚀 Backend berjalan di http://localhost:${PORT}`));
});