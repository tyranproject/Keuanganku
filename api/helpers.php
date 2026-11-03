<?php
/**
 * KEUANGANKU — Fungsi bersama (porting setia dari Code.gs).
 * Semua pesan error/sukses berbahasa Indonesia, disamakan dengan Code.gs.
 */

if (!defined('KEUANGANKU_APP')) {
    http_response_code(403);
    exit('Forbidden');
}

// ---------------------------------------------------------------------------
// Utilitas tanggal (zona waktu Asia/Jakarta, lihat config.php)
// ---------------------------------------------------------------------------

/** Tanggal hari ini 'yyyy-MM-dd' (pengganti getFormattedDateNow()). */
function todayId(): string
{
    return date('Y-m-d');
}

/** Bulan berjalan 'yyyy-MM'. */
function currentMonthId(): string
{
    return date('Y-m');
}

/**
 * Bulan sebelumnya 'yyyy-MM'. Januari mundur ke Desember tahun sebelumnya
 * (porting getPreviousMonthStr()).
 */
function previousMonthId(): string
{
    $y = (int) date('Y');
    $m = (int) date('m') - 1;
    if ($m < 1) {
        $m = 12;
        $y -= 1;
    }
    return sprintf('%04d-%02d', $y, $m);
}

// ---------------------------------------------------------------------------
// Sanitasi & normalisasi (porting sanitizeCell / formatDateVal /
// formatMonthVal dari Code.gs)
// ---------------------------------------------------------------------------

/**
 * Sanitasi string (porting sanitizeCell): bila string diawali salah satu
 * dari = + - @, awali dengan tanda petik satu. Di Google Sheets ini
 * mencegah formula injection; di sini dipertahankan agar perilaku impor
 * dan penyimpanan identik dengan aplikasi lama.
 */
function sanitizeCell($val): string
{
    if ($val === null || $val === '') {
        return '';
    }
    $str = (string) $val;
    if (preg_match('/^[=+@-]/', $str) === 1) {
        return "'" . $str;
    }
    return $str;
}

/**
 * Normalisasi tanggal penuh (porting formatDateVal): string kosong tetap
 * kosong; string ISO 'yyyy-MM-ddTHH:...' dipangkas ke tanggalnya.
 */
function formatDateVal($val): string
{
    if ($val === null || $val === '') {
        return '';
    }
    $s = (string) $val;
    $pos = strpos($s, 'T');
    if ($pos !== false) {
        $s = substr($s, 0, $pos);
    }
    return $s;
}

/**
 * Normalisasi kolom bulan 'yyyy-MM' (porting formatMonthVal).
 * Di Google Sheets, string '2026-10' berubah menjadi objek Date saat baris
 * ditambahkan; di MySQL hal itu tidak terjadi, tapi normalisasi ini tetap
 * dipertahankan agar data impor lama (mis. '2026-10-01') tetap cocok saat
 * dibandingkan dan ditampilkan.
 */
function formatMonthVal($val): string
{
    if ($val === null || $val === '') {
        return '';
    }
    $s = trim((string) $val);
    if ($s !== '' && $s[0] === "'") {
        $s = substr($s, 1);
    }
    if (preg_match('/^\d{4}-\d{2}/', $s, $m) === 1) {
        return $m[0];
    }
    return $s;
}

// ---------------------------------------------------------------------------
// ID, uang, dan saldo dompet
// ---------------------------------------------------------------------------

/** ID baru: prefix + 24 karakter heksadesimal acak (porting newId()). */
function newId(string $prefix): string
{
    return $prefix . bin2hex(random_bytes(12));
}

/** Token sesi baru: 32 karakter heksadesimal acak, berlaku 30 hari. */
function newToken(): string
{
    return bin2hex(random_bytes(16));
}

/** Format Rupiah gaya Code.gs (toLocaleString('id-ID')). */
function idr($num): string
{
    $n = (float) $num;
    $s = number_format($n, 2, ',', '.');
    // Buang nol desimal yang tidak perlu: 1000,50 -> 1.000,5 ; 1000 -> 1.000
    $s = rtrim(rtrim($s, '0'), ',');
    return $s;
}

/**
 * Hitung saldo dompet dari daftar transaksi (porting PERSIS
 * getWalletBalanceFromTransactions): Pemasukan +, Pengeluaran -,
 * Transfer - (asal) / + (tujuan). Nama dompet hanya di-trim, tanpa
 * normalisasi huruf (sama seperti backend lama).
 */
function getWalletBalanceFromTransactions(array $transactions, string $walletName): float
{
    $balances = [];
    foreach ($transactions as $t) {
        $amt = (float) ($t['jumlah'] ?? 0);
        $d = trim((string) ($t['dompet'] ?? 'Kas / Tunai'));
        if (!isset($balances[$d])) {
            $balances[$d] = 0.0;
        }
        $tipe = (string) ($t['tipe'] ?? '');
        if ($tipe === 'Pemasukan') {
            $balances[$d] += $amt;
        } elseif ($tipe === 'Pengeluaran') {
            $balances[$d] -= $amt;
        } elseif ($tipe === 'Transfer') {
            $balances[$d] -= $amt;
            $dt = trim((string) ($t['dompetTujuan'] ?? 'Kas / Tunai'));
            if (!isset($balances[$dt])) {
                $balances[$dt] = 0.0;
            }
            $balances[$dt] += $amt;
        }
    }
    return $balances[$walletName] ?? 0.0;
}

/** Ambil semua transaksi mentah milik user (untuk perhitungan saldo). */
function loadUserTransactionsRaw(PDO $pdo, string $userId): array
{
    $stmt = $pdo->prepare('SELECT tipe, jumlah, dompet, dompet_tujuan AS dompetTujuan FROM transaksi WHERE user_id = ? ORDER BY seq ASC');
    $stmt->execute([$userId]);
    return $stmt->fetchAll();
}

/**
 * Validasi saldo (porting assertWalletBalance). Melempar Exception dengan
 * pesan yang sama seperti Code.gs bila saldo tidak mencukupi.
 */
function assertWalletBalance(PDO $pdo, string $userId, string $walletName, float $amount): void
{
    $balance = getWalletBalanceFromTransactions(loadUserTransactionsRaw($pdo, $userId), $walletName);
    if ($balance < $amount) {
        throw new Exception('Saldo dompet "' . $walletName . '" tidak mencukupi! (Saldo saat ini: Rp ' . idr($balance) . ')');
    }
}

// ---------------------------------------------------------------------------
// Autentikasi sesi (porting verifyTokenAndGetSheet, tanpa spreadsheet)
// ---------------------------------------------------------------------------

/**
 * Memvalidasi token sesi dan mengembalikan baris user.
 * Pesan error disamakan dengan Code.gs:
 *  - token kosong            -> 'Sesi tidak valid / belum login.'
 *  - token tidak ditemukan   -> 'Sesi telah berakhir / Token tidak valid. Silakan login ulang.'
 *  - expiry kosong/kedaluwarsa -> 'Sesi kedaluwarsa. Silakan login kembali.'
 */
function requireAuth(PDO $pdo, $token): array
{
    if ($token === null || trim((string) $token) === '') {
        throw new Exception('Sesi tidak valid / belum login.');
    }
    $stmt = $pdo->prepare('SELECT id, email, password_hash, nama, salt, token_expiry, digest_optin FROM users WHERE token = ? LIMIT 1');
    $stmt->execute([(string) $token]);
    $user = $stmt->fetch();
    if ($user === false) {
        throw new Exception('Sesi telah berakhir / Token tidak valid. Silakan login ulang.');
    }
    $expiry = $user['token_expiry'];
    if ($expiry === null || $expiry === '' || strtotime((string) $expiry) < time()) {
        throw new Exception('Sesi kedaluwarsa. Silakan login kembali.');
    }
    return $user;
}

/** Bentuk user yang dikirim ke frontend (sama seperti Code.gs). */
function publicUser(array $user): array
{
    return [
        'name'        => (string) $user['nama'],
        'email'       => (string) $user['email'],
        'digestOptIn' => (string) ($user['digest_optin'] ?? 'YA'),
    ];
}

// ---------------------------------------------------------------------------
// Upload struk (pengganti saveReceiptToDrive; disimpan lokal, bukan Drive)
// ---------------------------------------------------------------------------

/**
 * Menyimpan struk dari data URI base64 ke public/uploads/{userId}/.
 * Mengembalikan path relatif 'uploads/{userId}/{file}' (dipakai frontend
 * sebagai href langsung dari public/index.html), atau '' bila tidak ada
 * data. Gagal -> Exception dan transaksi dibatalkan (sama seperti lama).
 * Aturan: mime image/* atau application/pdf, ukuran setelah decode maks 5MB.
 */
function saveReceipt(string $userId, string $base64Data): string
{
    if ($base64Data === '' || strpos($base64Data, 'base64,') === false) {
        return '';
    }
    $parts = explode(';base64,', $base64Data, 2);
    if (count($parts) !== 2) {
        throw new Exception('Gagal mengunggah struk: format data tidak valid. Transaksi dibatalkan.');
    }
    $mime = str_replace('data:', '', $parts[0]);
    $decoded = base64_decode($parts[1], true);
    if ($decoded === false) {
        throw new Exception('Gagal mengunggah struk: data tidak valid. Transaksi dibatalkan.');
    }
    if (strlen($decoded) > 5 * 1024 * 1024) {
        throw new Exception('Ukuran struk maksimal 5MB.');
    }
    if (strpos($mime, 'image/') !== 0 && $mime !== 'application/pdf') {
        throw new Exception('Format struk tidak didukung (hanya gambar atau PDF).');
    }
    // Pemetaan ekstensi sama seperti Code.gs: png -> png, pdf -> pdf,
    // sisanya (jpg/gif/webp/dll) -> jpg.
    if (strpos($mime, 'png') !== false) {
        $ext = 'png';
    } elseif (strpos($mime, 'pdf') !== false) {
        $ext = 'pdf';
    } else {
        $ext = 'jpg';
    }

    $safeUser = preg_replace('/[^A-Za-z0-9_-]/', '_', $userId);
    $baseDir = resolveUploadsDir();
    $userDir = $baseDir . '/' . $safeUser;
    if (!is_dir($userDir) && !mkdir($userDir, 0755, true) && !is_dir($userDir)) {
        throw new Exception('Gagal mengunggah struk: folder tujuan tidak dapat dibuat. Transaksi dibatalkan.');
    }
    $fileName = bin2hex(random_bytes(12)) . '.' . $ext;
    $fullPath = $userDir . '/' . $fileName;
    if (file_put_contents($fullPath, $decoded) === false) {
        throw new Exception('Gagal mengunggah struk: tidak dapat menulis berkas. Transaksi dibatalkan.');
    }
    return 'uploads/' . $safeUser . '/' . $fileName;
}

/**
 * Lokasi folder uploads di disk. Penentuan tata letak HANYA dari folder
 * yang sudah ada (tanpa mkdir), agar berkas tidak pernah tersimpan di
 * lokasi yang salah:
 *  - Tata letak 1: api/ dan public/ bersaudara (…/api + …/public/uploads)
 *    -> uploads = …/public/uploads.
 *  - Tata letak 2: api/ berada DI DALAM public/ (document root = public/)
 *    -> uploads = …/public/uploads (saudara api/).
 * Pembuatan folder dilakukan pemanggil (saveReceipt) dan gagal keras bila
 * tidak bisa dibuat — bukan diam-diam pindah lokasi.
 */
function resolveUploadsDir(): string
{
    if (is_dir(__DIR__ . '/../public')) {
        return __DIR__ . '/../public/uploads';
    }
    return __DIR__ . '/../uploads';
}
