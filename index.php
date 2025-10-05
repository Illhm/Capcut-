<?php
// Simple PHP frontend to call Node backend (CapCut Creator)

// Start session
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Configure backend base URL
$BACKEND_BASE = getenv('BACKEND_BASE') ?: 'http://127.0.0.1:8000';

function http_get_json($url) {
    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL => $url,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_CONNECTTIMEOUT => 5,
        CURLOPT_TIMEOUT => 15,
    ]);
    $resp = curl_exec($ch);
    $err = curl_error($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    if ($resp === false) {
        return [null, $err ?: 'GET request failed'];
    }
    $data = json_decode($resp, true);
    if ($data === null && json_last_error() !== JSON_ERROR_NONE) {
        return [null, 'Invalid JSON from backend (GET). HTTP '.$code];
    }
    return [$data, null];
}

function http_post_json($url, $payload) {
    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL => $url,
        CURLOPT_POST => true,
        CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
        CURLOPT_POSTFIELDS => json_encode($payload),
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_CONNECTTIMEOUT => 5,
        CURLOPT_TIMEOUT => 120,
    ]);
    $resp = curl_exec($ch);
    $err = curl_error($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    if ($resp === false) {
        return [null, $err ?: 'POST request failed'];
    }
    $data = json_decode($resp, true);
    if ($data === null && json_last_error() !== JSON_ERROR_NONE) {
        return [null, 'Invalid JSON from backend (POST). HTTP '.$code];
    }
    return [$data, null];
}

// Tidak perlu memuat daftar negara dari backend; backend akan menangani default country

// SQLite rate limit (same pattern as spotify-creator, but limits adjusted)
$DB_PATH = __DIR__ . '/capcut_creator.db';
try {
    $pdo = new PDO('sqlite:' . $DB_PATH);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->exec("CREATE TABLE IF NOT EXISTS ip_submissions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT NOT NULL,
        ua_hash TEXT NOT NULL,
        submitted_at DATETIME NOT NULL
    )");
    $pdo->exec("CREATE TABLE IF NOT EXISTS daily_submissions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        date TEXT NOT NULL UNIQUE,
        count INTEGER DEFAULT 0
    )");
} catch (Exception $e) {
    error_log('CapCut DB error: ' . $e->getMessage());
}

// Limits
$MAX_PER_IP_BROWSER = 25; // 1 IP 1 browser hanya bisa 25
$MAX_GLOBAL_DAILY = 300;  // sehari max 300

// Handle form submit with rate limiting similar to spotify-creator
$result = null;
$error = null;
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $country = isset($_POST['country']) ? trim($_POST['country']) : '';
    $countryManual = isset($_POST['country_manual']) ? strtoupper(trim($_POST['country_manual'])) : '';
    $total = isset($_POST['total']) ? intval($_POST['total']) : 1;
    // Threads ditentukan otomatis: 1 jika total=1, selain itu 2
    $threads = 1;
    $password = isset($_POST['password']) ? (string)$_POST['password'] : '';
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
    $uaHash = hash('sha256', $ua);
    $today = date('Y-m-d');

    // Basic validation
    if ($total < 1) $total = 1;
    if ($total > 1) {
        $threads = 2;
    } else {
        $threads = 1;
    }
    if ($countryManual !== '') $country = $countryManual;
    // Biarkan kosong agar backend pakai default dari config.json / kode di gw.js

    // Rate limit checks (PHP-side)
    try {
        // Per IP+Browser limit (25 per hari)
        $stmt = $pdo->prepare("SELECT COUNT(*) FROM ip_submissions WHERE ip = ? AND ua_hash = ? AND date(submitted_at) = ?");
        $stmt->execute([$ip, $uaHash, $today]);
        $ipUaCount = (int)($stmt->fetchColumn() ?: 0);
        if ($ipUaCount >= $MAX_PER_IP_BROWSER) {
            $error = 'Anda sudah mencapai batas 25 pembuatan untuk IP/Browser ini hari ini. Coba lagi besok.';
        }

        // Global daily limit (300 per hari)
        if (!$error) {
            $stmt = $pdo->prepare("SELECT count FROM daily_submissions WHERE date = ?");
            $stmt->execute([$today]);
            $dailyCount = (int)($stmt->fetchColumn() ?: 0);
            if ($dailyCount >= $MAX_GLOBAL_DAILY) {
                $error = 'Kuota harian sudah habis (300 akun/hari). Coba lagi besok.';
            }
        }
    } catch (Exception $e) {
        // If DB fails, continue without rate limit but log
        error_log('CapCut rate-limit check error: ' . $e->getMessage());
    }

    if (!$error) {
        [$resp, $err] = http_post_json($BACKEND_BASE.'/create', [
            'country' => $country,
            'total' => $total,
            'threads' => $threads,
            'password' => $password,
        ]);
        if ($err) {
            $error = $err;
        } else {
            // Jika backend mengirim error di payload (mis. limit/validasi), tampilkan sebagai info sekali
            if (isset($resp['error'])) {
                $msg = (string)$resp['error'];
                if (stripos($msg, 'limit') !== false) {
                    $error = 'Limit backend tercapai. Coba lagi besok.';
                } else {
                    $error = $msg;
                }
            } else {
                $result = $resp;
            }
            // Catat berdasarkan jumlah akun sukses (successCount)
            $successCount = (int)($result['successCount'] ?? 0);
            if ($successCount > 0) {
                try {
                    // Tambahkan entry ip_submissions sebanyak jumlah sukses
                    $pdo->beginTransaction();
                    $stmtIns = $pdo->prepare("INSERT INTO ip_submissions (ip, ua_hash, submitted_at) VALUES (?, ?, datetime('now'))");
                    for ($i = 0; $i < $successCount; $i++) {
                        $stmtIns->execute([$ip, $uaHash]);
                    }
                    // Tambahkan ke daily_submissions sesuai jumlah sukses
                    $pdo->prepare("INSERT INTO daily_submissions (date, count) VALUES (?, ?) 
                                    ON CONFLICT(date) DO UPDATE SET count = count + ?")
                        ->execute([$today, $successCount, $successCount]);
                    $pdo->commit();
                } catch (Exception $e) {
                    if ($pdo->inTransaction()) { $pdo->rollBack(); }
                    error_log('CapCut rate-limit write error: ' . $e->getMessage());
                }
            }
        }
    }

    // Prevent duplicate submission on refresh: PRG pattern
    $_SESSION['capcut_result'] = $result;
    $_SESSION['capcut_error'] = $error;
    header('Location: ' . basename(__FILE__), true, 303);
    exit;
}

// Load result from session (GET after redirect)
if (isset($_SESSION['capcut_result']) || isset($_SESSION['capcut_error'])) {
    $result = $_SESSION['capcut_result'] ?? null;
    $error = $_SESSION['capcut_error'] ?? null;
    unset($_SESSION['capcut_result'], $_SESSION['capcut_error']);
}
?>
<?php
// Include shared header/footer for consistent styling with spotify-creator
$page_title = 'Premiumisme Tools';
$current_page = 'capcut';
$base_prefix = '../';
include '../includes/header.php';
?>

<div class="content-wrapper">
    <div class="content-section">
        <h2>CapCut Creator</h2>

        <form method="post" class="grid grid-cols-1 gap-4">
            <div>
                <label class="mb-2 text-sm opacity-80">Password Akun</label>
                <input class="form-input" type="password" id="password" name="password" placeholder="Contoh : masuk123">
            </div>
            <div>
                <label class="mb-2 text-sm opacity-80">Kode Negara Proxy</label>
                <input class="form-input" type="text" id="country_manual" name="country_manual" placeholder="Contoh: sg" value="<?php echo isset($_POST['country_manual']) ? htmlspecialchars($_POST['country_manual']) : ''; ?>">
                <div class="text-xs opacity-70 mt-1">Gunakan kode negara ISO-3166 dua huruf. Referensi: <a href="https://www.ssl.com/id/kode-negara-a/" target="_blank" rel="noopener" class="text-blue-400 hover:underline">Daftar Kode Negara</a></div>
            </div>
            <div class="grid grid-cols-1 gap-4">
                <div>
                    <label class="mb-2 text-sm opacity-80">Total Akun</label>
                    <input class="form-input" type="number" id="total" name="total" min="1" value="<?php echo isset($_POST['total']) ? intval($_POST['total']) : 1; ?>">
                </div>
                
            </div>
            <button type="submit" class="btn btn-primary w-full mt-2">Buat Akun</button>
        </form>

        <!-- Processing Modal -->
        <div id="processingModal" style="display:none; position: fixed; inset: 0; background: rgba(0,0,0,0.6); z-index: 9999; align-items: center; justify-content: center;">
            <div style="background: var(--glass-bg); border: 1px solid var(--glass-border); border-radius: 14px; padding: 24px; max-width: 440px; width: calc(100% - 40px); text-align: center;">
                <div class="flex items-center justify-center gap-4 mb-4">
                    <div class="w-10 h-10" style="border: 4px solid var(--accent); border-top-color: transparent; border-radius: 9999px; animation: spin 1s linear infinite;"></div>
                    <div class="text-left">
                        <div class="font-bold">Memproses pembuatan akun</div>
                    </div>
                </div>
                <div class="text-xs opacity-70">Jangan tutup halaman ini. Proses bisa memakan waktu beberapa menit.</div>
            </div>
        </div>
        <style>
            @keyframes spin { from { transform: rotate(0); } to { transform: rotate(360deg); } }
        </style>

        <?php if ($error): ?>
            <div class="result-card mt-6 bg-red-500/10 border-red-500/20">
                <div class="flex items-center gap-3 mb-3">
                    <div class="w-8 h-8 bg-red-500/20 rounded-full flex items-center justify-center">
                        <svg class="w-5 h-5 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
                        </svg>
                    </div>
                    <h3 class="text-lg font-semibold text-red-500">Gagal</h3>
                </div>
                <div class="text-sm text-red-400"><?php echo htmlspecialchars($error, ENT_QUOTES, 'UTF-8'); ?></div>
            </div>
        <?php endif; ?>

        <?php if ($result && !$error): ?>
            <?php
            $lines = '';
            if (!empty($result['successes']) && is_array($result['successes'])) {
                foreach ($result['successes'] as $row) {
                    $email = $row['email'] ?? '-';
                    $pwd = $row['password'] ?? ($_POST['password'] ?? '');
                    $cty = $row['country'] ?? ($result['selectedCountry'] ?? '');
                    $lines .= $email.'|'.$pwd.'|'.$cty."\n";
                }
            }
            ?>
            <div class="result-card mt-6">
                <div class="flex items-center justify-between mb-3">
                    <div class="font-bold">Hasil</div>
                    <button id="copyBtn" type="button" class="btn btn-secondary">Copy</button>
                </div>
                <pre id="resultText" class="bg-black/30 p-3 rounded border border-white/10 text-sm overflow-x-auto"><?php echo htmlspecialchars($lines, ENT_QUOTES, 'UTF-8'); ?></pre>
            </div>
        <?php endif; ?>
    </div>
</div>

<?php include '../includes/footer.php'; ?>

<script>
document.addEventListener('DOMContentLoaded', function() {
    const form = document.querySelector('form');
    const modal = document.getElementById('processingModal');
    let timer = null;

    if (form && modal) {
        form.addEventListener('submit', function() {
            // Tampilkan modal saat submit
            modal.style.display = 'flex';
            const start = Date.now();
            const timerEl = document.getElementById('elapsedSeconds');
            timer = setInterval(function() {
                const elapsed = (Date.now() - start) / 1000;
                if (timerEl) timerEl.textContent = elapsed.toFixed(1);
            }, 100);
        });
    }

    // Jika hasil sudah ada di halaman (server render setelah PRG), sembunyikan modal
    const hasResult = document.querySelector('.result-card');
    if (hasResult && modal) {
        modal.style.display = 'none';
    }

    // Cleanup timer saat navigasi
    window.addEventListener('beforeunload', function() {
        if (timer) clearInterval(timer);
    });
});
</script>

<script>
// Copy button handler
document.addEventListener('click', function(e) {
    if (e.target && e.target.id === 'copyBtn') {
        const pre = document.getElementById('resultText');
        if (pre) {
            const text = pre.innerText || pre.textContent || '';
            navigator.clipboard.writeText(text).then(function() {
                e.target.textContent = 'Copied';
                setTimeout(() => { e.target.textContent = 'Copy'; }, 1200);
            }).catch(function() {
                // Fallback
                const ta = document.createElement('textarea');
                ta.value = text;
                document.body.appendChild(ta);
                ta.select();
                document.execCommand('copy');
                document.body.removeChild(ta);
                e.target.textContent = 'Copied';
                setTimeout(() => { e.target.textContent = 'Copy'; }, 1200);
            });
        }
    }
});
</script>


