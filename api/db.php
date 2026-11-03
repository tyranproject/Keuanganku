<?php
/**
 * KEUANGANKU — Koneksi database PDO (MySQL/MariaDB).
 * Dipakai oleh api/index.php dan api/cron_digest.php.
 */

if (!defined('KEUANGANKU_APP')) {
    http_response_code(403);
    exit('Forbidden');
}

/**
 * Mengembalikan satu koneksi PDO bersama (singleton) untuk request ini.
 * - ERRMODE_EXCEPTION: error database melempar Exception (ditangkap router).
 * - FETCH_ASSOC: baris dikembalikan sebagai array asosiatif.
 * - utf8mb4: emoji & karakter Indonesia aman.
 * - Emulasi prepared statement MATI: parameter selalu dikirim terpisah ke
 *   server MySQL (bukan ditempel ke string SQL) -> anti SQL injection.
 */
function pdo(): PDO
{
    static $pdo = null;
    if ($pdo !== null) {
        return $pdo;
    }
    $dsn = 'mysql:host=' . DB_HOST . ';dbname=' . DB_NAME . ';charset=utf8mb4';
    $pdo = new PDO($dsn, DB_USER, DB_PASS, [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES   => false,
    ]);
    return $pdo;
}
