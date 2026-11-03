<?php
/**
 * KEUANGANKU — Cron digest bulanan (pengganti processAllUsersMonthlyDigest
 * + setupMonthlyTrigger dari Code.gs).
 *
 * CARA PAKAI (pilih satu):
 *  1. Cron cPanel (disarankan):
 *     curl -s "https://domain-anda/api/cron_digest.php?key=KUNCI_DIGEST_ANDA"
 *     Jadwal: tanggal 1 tiap bulan, pukul 08:00 WIB (lihat PANDUAN_UPLOAD.md).
 *  2. CLI (SSH):  php /path/ke/api/cron_digest.php
 *
 * PERILAKU (disamakan dengan Code.gs):
 *  - Hanya user dengan digest_optin='YA' DAN token sesi yang masih ada
 *    (belum logout) yang dikirimi. Ini perilaku aplikasi lama: cron lama
 *    melewati user yang tokennya kosong.
 *  - Ringkasan yang dikirim adalah BULAN SEBELUMNYA (cron jalan tanggal 1,
 *    jadi bulan yang baru selesai yang dirangkum). Januari mundur ke
 *    Desember tahun sebelumnya.
 *  - Gagal kirim ke satu user tidak menghentikan user lain.
 *  - Kunci salah -> HTTP 403 (kecuali lewat CLI).
 */

define('KEUANGANKU_APP', true);

require __DIR__ . '/config.php';
require __DIR__ . '/db.php';
require __DIR__ . '/helpers.php';
require __DIR__ . '/digest.php';

header('Content-Type: application/json; charset=UTF-8');

$isCli = (php_sapi_name() === 'cli');
if (!$isCli) {
    $key = (string) ($_GET['key'] ?? '');
    if ($key === '' || !hash_equals((string) DIGEST_CRON_KEY, $key)) {
        http_response_code(403);
        echo json_encode(['status' => 'error', 'message' => 'Kunci cron tidak valid.']);
        exit;
    }
}

$monthStr = previousMonthId();
$pdo = pdo();

$stmt = $pdo->prepare("SELECT id, email, nama FROM users WHERE digest_optin = 'YA' AND token IS NOT NULL AND token <> ''");
$stmt->execute();
$users = $stmt->fetchAll();

$sent = 0;
$failed = 0;
$errors = [];
foreach ($users as $u) {
    try {
        $ok = sendDigestForUser($pdo, ['id' => (string) $u['id'], 'email' => (string) $u['email'], 'nama' => (string) $u['nama']], $monthStr, true);
        if ($ok) {
            $sent++;
        } else {
            $failed++;
            $errors[] = (string) $u['email'];
        }
    } catch (Throwable $e) {
        $failed++;
        $errors[] = (string) $u['email'];
    }
}

echo json_encode([
    'status' => 'success',
    'month'  => $monthStr,
    'total'  => count($users),
    'sent'   => $sent,
    'failed' => $failed,
    'failed_emails' => $errors,
]);
