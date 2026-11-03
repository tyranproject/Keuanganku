<?php
/**
 * KEUANGANKU — Konfigurasi aplikasi (hosting mandiri, PHP + MySQL)
 * ============================================================================
 * CARA PAKAI: ubah nilai placeholder di bawah sesuai data dari cPanel Anda,
 * lalu simpan. JANGAN membagikan berkas ini ke orang lain.
 *
 * KEAMANAN: berkas ini TIDAK boleh diakses langsung lewat browser.
 *  - Guard di bawah menolak eksekusi langsung (hanya boleh di-include oleh
 *    api/index.php / api/cron_digest.php yang mendefinisikan KEUANGANKU_APP).
 *  - api/.htaccess juga memblokir akses langsung ke config.php.
 */

// Guard: tolak akses langsung lewat browser.
if (!defined('KEUANGANKU_APP')) {
    http_response_code(403);
    exit('Forbidden');
}

// Zona waktu: samakan dengan zona waktu script Apps Script lama (WIB).
// Semua tanggal "hari ini" dan digest bulanan memakai zona ini.
date_default_timezone_set('Asia/Jakarta');

// --- Database MySQL/MariaDB (buat dulu di cPanel -> MySQL Databases) --------
define('DB_HOST', 'localhost');              // Biasanya 'localhost' di cPanel.
define('DB_NAME', 'taxag170_keuanganku');             // Nama database dari cPanel.
define('DB_USER', 'taxag170');        // User MySQL dari cPanel.
define('DB_PASS', 'A03Tkm9HjRXd'); // Password user MySQL.

// --- Aplikasi ----------------------------------------------------------------
// URL lengkap situs Anda (dipakai untuk header From email & tautan).
// Contoh: 'https://keuanganku.namadomain.com'
define('APP_URL', 'http://keuanganku.taxagent.my.id');

// Kunci cron untuk api/cron_digest.php. Buat yang panjang & acak, misal:
//   openssl rand -hex 24
// Cron memanggil: https://domain-anda/api/cron_digest.php?key=KUNCI_INI
define('DIGEST_CRON_KEY', '5TIQhy8UQ8h9aWBZL5zuHAHA');
