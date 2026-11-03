<?php
/**
 * KEUANGANKU — Pembangun & pengirim email digest bulanan.
 * Porting setia dari sendTestEmailDigest() Code.gs; dipakai oleh:
 *  - api/handlers.php  (tombol manual "Kirim Ringkasan ke Email" + digest
 *    otomatis bila dipanggil dengan bulan tertentu), dan
 *  - api/cron_digest.php (cron bulanan untuk SEMUA user yang opt-in).
 */

if (!defined('KEUANGANKU_APP')) {
    http_response_code(403);
    exit('Forbidden');
}

/**
 * Menghitung ringkasan satu user untuk satu bulan 'yyyy-MM' dari tabel
 * transaksi. Hanya baris yang tanggalnya diawali monthStr yang dihitung
 * (sama seperti dateStr.startsWith(monthStr) di Code.gs).
 *
 * @return array{income:float, expense:float, net:float, top:array<string,float>}
 */
function computeDigest(PDO $pdo, string $userId, string $monthStr): array
{
    $stmt = $pdo->prepare('SELECT tanggal, tipe, kategori, jumlah FROM transaksi WHERE user_id = ? ORDER BY seq ASC');
    $stmt->execute([$userId]);
    $income = 0.0;
    $expense = 0.0;
    $cats = [];
    foreach ($stmt->fetchAll() as $row) {
        $dateStr = formatDateVal($row['tanggal'] ?? '');
        if (strpos($dateStr, $monthStr) !== 0) {
            continue;
        }
        $amt = (float) $row['jumlah'];
        if ($row['tipe'] === 'Pemasukan') {
            $income += $amt;
        } elseif ($row['tipe'] === 'Pengeluaran') {
            $expense += $amt;
            $cat = (string) $row['kategori'];
            $cats[$cat] = ($cats[$cat] ?? 0.0) + $amt;
        }
    }
    arsort($cats);
    $top = array_slice($cats, 0, 3, true);
    return ['income' => $income, 'expense' => $expense, 'net' => $income - $expense, 'top' => $top];
}

/**
 * Merakit subject + body HTML digest (template disamakan dengan Code.gs).
 *
 * @param bool $isAuto true bila dipanggil jalur otomatis/cron (subject
 *                     menyebut bulannya); false untuk tombol manual
 *                     (subject "Bulan Ini").
 * @return array{subject:string, body:string}
 */
function buildDigestEmail(string $userName, string $monthStr, array $summary, bool $isAuto): array
{
    $subject = $isAuto
        ? '[KEUANGANKU] Ringkasan Laporan Keuangan ' . $monthStr . ' - ' . $userName
        : '[KEUANGANKU] Ringkasan Laporan Keuangan Bulan Ini - ' . $userName;

    if (count($summary['top']) > 0) {
        $topHtml = '<ul style="margin:8px 0; padding-left:20px; font-size:13px; color:#475569;">';
        foreach ($summary['top'] as $cat => $amt) {
            $topHtml .= '<li><b>' . htmlspecialchars((string) $cat, ENT_QUOTES, 'UTF-8') . '</b>: Rp ' . idr($amt) . '</li>';
        }
        $topHtml .= '</ul>';
    } else {
        $topHtml = '<p style="font-size:13px; color:#94a3b8; font-style:italic;">Belum ada pengeluaran pada periode ini.</p>';
    }

    $body = '
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; border: 1px solid #e2e8f0; border-radius: 12px; overflow: hidden; background-color: #ffffff;">
        <div style="background-color: #2563eb; padding: 20px; text-align: center; color: #ffffff;">
          <h2 style="margin: 0; font-size: 20px;">KEUANGANKU</h2>
          <p style="margin: 4px 0 0; font-size: 12px; opacity: 0.9;">Rangkuman Laporan Keuangan Bulanan</p>
        </div>
        <div style="padding: 24px;">
          <p style="font-size: 14px; color: #1e293b; margin-top: 0;">Halo <b>' . htmlspecialchars($userName, ENT_QUOTES, 'UTF-8') . '</b>,</p>
          <p style="font-size: 13px; color: #475569; line-height: 1.5;">
            Berikut adalah ringkasan performa finansial Anda untuk periode <b>' . htmlspecialchars($monthStr, ENT_QUOTES, 'UTF-8') . '</b>:
          </p>

          <div style="background-color: #f8fafc; border-radius: 8px; padding: 16px; margin: 16px 0;">
            <table style="width: 100%; font-size: 13px; border-collapse: collapse;">
              <tr>
                <td style="padding: 6px 0; color: #059669; font-weight: bold;">Total Pemasukan:</td>
                <td style="padding: 6px 0; text-align: right; color: #059669; font-weight: bold;">Rp ' . idr($summary['income']) . '</td>
              </tr>
              <tr>
                <td style="padding: 6px 0; color: #e11d48; font-weight: bold;">Total Pengeluaran:</td>
                <td style="padding: 6px 0; text-align: right; color: #e11d48; font-weight: bold;">Rp ' . idr($summary['expense']) . '</td>
              </tr>
              <tr style="border-top: 1px solid #e2e8f0;">
                <td style="padding: 8px 0 0; color: #2563eb; font-weight: bold; font-size: 14px;">Arus Kas Bersih:</td>
                <td style="padding: 8px 0 0; text-align: right; color: #2563eb; font-weight: bold; font-size: 14px;">Rp ' . idr($summary['net']) . '</td>
              </tr>
            </table>
          </div>

          <h4 style="font-size: 14px; color: #1e293b; margin: 16px 0 8px;">Top 3 Kategori Pengeluaran Terbesar:</h4>
          ' . $topHtml . '

          <p style="font-size: 12px; color: #94a3b8; margin-top: 24px; text-align: center;">
            Email ini dikirim otomatis oleh sistem KEUANGANKU Aplikasi Keuangan Pribadi.
          </p>
        </div>
      </div>
    ';

    return ['subject' => $subject, 'body' => $body];
}

/**
 * Mengirim digest satu user untuk satu bulan. Mengembalikan true bila
 * mail() diterima server mail lokal. Melempar Exception bila pengiriman
 * ditolak (di Code.gs, MailApp yang gagal juga melempar error).
 */
function sendDigestForUser(PDO $pdo, array $user, string $monthStr, bool $isAuto): bool
{
    $summary = computeDigest($pdo, (string) $user['id'], $monthStr);
    $mail = buildDigestEmail((string) $user['nama'], $monthStr, $summary, $isAuto);
    $host = parse_url(APP_URL, PHP_URL_HOST);
    if (!is_string($host) || $host === '') {
        $host = 'localhost';
    }
    $headers = "MIME-Version: 1.0\r\n"
        . "Content-type: text/html; charset=UTF-8\r\n"
        . 'From: KEUANGANKU <no-reply@' . $host . ">\r\n";
    return mail((string) $user['email'], $mail['subject'], $mail['body'], $headers);
}
