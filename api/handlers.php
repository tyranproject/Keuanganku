<?php
/**
 * KEUANGANKU — Handler aksi API (porting setia dari Code.gs).
 * Setiap fungsi menerima (PDO $pdo, array $args) dan mengembalikan array
 * respons {status, message, ...}. Argumen pertama tiap aksi adalah token,
 * persis seperti pemanggilan google.script.run lama — kecuali loginUser
 * dan registerUser yang argumen pertamanya adalah objek data.
 *
 * Exception yang dilempar handler ditangkap router (api/index.php) dan
 * diubah menjadi {status:'error', message} — setara failure handler
 * google.script.run di frontend lama.
 */

if (!defined('KEUANGANKU_APP')) {
    http_response_code(403);
    exit('Forbidden');
}

// ---------------------------------------------------------------------------
// Pembantu argumen
// ---------------------------------------------------------------------------

/** Payload objek (argumen ke-2) sebagai array; bila bukan array -> []. */
function payloadArg(array $args, int $index = 1): array
{
    $v = $args[$index] ?? null;
    return is_array($v) ? $v : [];
}

/** String dari payload (trim), '' bila tidak ada. */
function strArg(array $p, string $key, string $def = ''): string
{
    if (!isset($p[$key])) {
        return $def;
    }
    return trim((string) $p[$key]);
}

/** Angka dari payload, 0 bila bukan numerik. */
function numArg(array $p, string $key): float
{
    if (!isset($p[$key]) || !is_numeric($p[$key])) {
        return 0.0;
    }
    return (float) $p[$key];
}

/** Tanggal hari ini untuk kolom tanggal (sama seperti getFormattedDateNow). */
function argDateOrToday(array $p, string $key): string
{
    $v = strArg($p, $key);
    return $v !== '' ? $v : todayId();
}

// ---------------------------------------------------------------------------
// Autentikasi: register / login / logout / profil
// ---------------------------------------------------------------------------

function h_registerUser(PDO $pdo, array $args): array
{
    $data = payloadArg($args, 0);
    $email = strtolower(strArg($data, 'email'));
    $password = strArg($data, 'password');
    $name = strArg($data, 'name');

    if ($email === '' || $password === '' || $name === '') {
        throw new Exception('Data pendaftaran tidak lengkap.');
    }
    if (preg_match('/^[^\s@]+@[^\s@]+\.[^\s@]+$/', $email) !== 1) {
        throw new Exception('Format email tidak valid.');
    }
    if (strlen($password) < 6) {
        throw new Exception('Password minimal 6 karakter.');
    }

    $stmt = $pdo->prepare('SELECT id FROM users WHERE LOWER(email) = ? LIMIT 1');
    $stmt->execute([$email]);
    if ($stmt->fetch() !== false) {
        throw new Exception('Email sudah terdaftar. Silakan login.');
    }

    $userId = newId('USR-');
    $token = newToken();
    $expiry = date('Y-m-d H:i:s', time() + 30 * 24 * 60 * 60);
    $created = date('Y-m-d H:i:s');
    $hash = password_hash($password, PASSWORD_DEFAULT);
    $stmt = $pdo->prepare('INSERT INTO users (id, email, password_hash, nama, salt, token, token_expiry, digest_optin, created_at) VALUES (?, ?, ?, ?, NULL, ?, ?, ?, ?)');
    $stmt->execute([$userId, $email, $hash, $name, $token, $expiry, 'YA', $created]);

    return [
        'status'  => 'success',
        'message' => 'Pendaftaran berhasil! Selamat datang, ' . $name,
        'token'   => $token,
        'user'    => ['name' => $name, 'email' => $email, 'digestOptIn' => 'YA'],
    ];
}

function h_loginUser(PDO $pdo, array $args): array
{
    $data = payloadArg($args, 0);
    $email = strtolower(strArg($data, 'email'));
    $password = strArg($data, 'password');

    if ($email === '' || $password === '') {
        throw new Exception('Email dan kata sandi harus diisi.');
    }

    $stmt = $pdo->prepare('SELECT id, email, password_hash, nama, salt, digest_optin FROM users WHERE LOWER(email) = ? LIMIT 1');
    $stmt->execute([$email]);
    $row = $stmt->fetch();
    if ($row === false) {
        throw new Exception('Email atau kata sandi salah.');
    }

    $ok = false;
    $isLegacy = false;
    // 1) Akun bcrypt (baru / sudah di-upgrade).
    if (is_string($row['password_hash']) && password_verify($password, $row['password_hash'])) {
        $ok = true;
    } else {
        // 2) Akun lama SHA-256: bersalt (password|salt) atau tanpa salt.
        $salt = $row['salt'];
        $expected = ($salt !== null && (string) $salt !== '')
            ? hash('sha256', $password . '|' . (string) $salt)
            : hash('sha256', $password);
        if (hash_equals((string) $row['password_hash'], $expected)) {
            $ok = true;
            $isLegacy = true;
        }
    }
    if (!$ok) {
        throw new Exception('Email atau kata sandi salah.');
    }

    // Upgrade transparan akun lama ke bcrypt (menggantikan upgrade ke
    // SHA-256 bersalt di Code.gs); salt dikosongkan sesudahnya.
    if ($isLegacy) {
        $stmt = $pdo->prepare('UPDATE users SET password_hash = ?, salt = NULL WHERE id = ?');
        $stmt->execute([password_hash($password, PASSWORD_DEFAULT), $row['id']]);
    }

    $newToken = newToken();
    $expiry = date('Y-m-d H:i:s', time() + 30 * 24 * 60 * 60);
    $stmt = $pdo->prepare('UPDATE users SET token = ?, token_expiry = ? WHERE id = ?');
    $stmt->execute([$newToken, $expiry, $row['id']]);

    $name = (string) $row['nama'];
    $digest = (string) ($row['digest_optin'] ?? 'YA');
    return [
        'status'  => 'success',
        'message' => 'Login berhasil! Selamat datang kembali, ' . $name,
        'token'   => $newToken,
        'user'    => ['name' => $name, 'email' => (string) $row['email'], 'digestOptIn' => $digest],
    ];
}

function h_logoutUser(PDO $pdo, array $args): array
{
    // Code.gs selalu mengembalikan success, bahkan bila gagal.
    try {
        $token = $args[0] ?? null;
        if ($token !== null && trim((string) $token) !== '') {
            $stmt = $pdo->prepare('UPDATE users SET token = NULL WHERE token = ?');
            $stmt->execute([(string) $token]);
        }
    } catch (Throwable $e) {
        // Sengaja diabaikan (sama seperti Code.gs).
    }
    return ['status' => 'success'];
}

function h_getUserProfile(PDO $pdo, array $args): array
{
    $user = requireAuth($pdo, $args[0] ?? null);
    return ['status' => 'success', 'user' => publicUser($user)];
}

// ---------------------------------------------------------------------------
// Getter (dipakai getAllUserData). Urutan = urutan sisipan (seq), sama
// seperti urutan baris sheet. Nilai default mengikuti Code.gs.
// ---------------------------------------------------------------------------

function getTransactionsData(PDO $pdo, string $userId): array
{
    $stmt = $pdo->prepare('SELECT id, tanggal, tipe, kategori, jumlah, catatan, struk, dompet, dompet_tujuan FROM transaksi WHERE user_id = ? ORDER BY seq ASC');
    $stmt->execute([$userId]);
    $out = [];
    foreach ($stmt->fetchAll() as $r) {
        $out[] = [
            'id'           => (string) $r['id'],
            'tanggal'      => formatDateVal($r['tanggal']),
            'tipe'         => ((string) $r['tipe'] !== '') ? (string) $r['tipe'] : 'Pengeluaran',
            'kategori'     => ((string) $r['kategori'] !== '') ? (string) $r['kategori'] : 'Lainnya',
            'jumlah'       => (float) $r['jumlah'],
            'catatan'      => (string) ($r['catatan'] ?? ''),
            'struk'        => (string) $r['struk'],
            'dompet'       => ((string) $r['dompet'] !== '') ? (string) $r['dompet'] : 'Kas / Tunai',
            'dompetTujuan' => (string) $r['dompet_tujuan'],
        ];
    }
    return $out;
}

function getDebtsData(PDO $pdo, string $userId): array
{
    $stmt = $pdo->prepare('SELECT id, tanggal, jatuh_tempo, tipe, pihak_lain, jumlah, catatan, status, tanggal_lunas, dompet_pelunasan FROM hutang_piutang WHERE user_id = ? ORDER BY seq ASC');
    $stmt->execute([$userId]);
    $out = [];
    foreach ($stmt->fetchAll() as $r) {
        $out[] = [
            'id'              => (string) $r['id'],
            'tanggal'         => formatDateVal($r['tanggal']),
            'jatuhTempo'      => formatDateVal($r['jatuh_tempo']),
            'tipe'            => ((string) $r['tipe'] !== '') ? (string) $r['tipe'] : 'Hutang',
            'pihakLain'       => (string) $r['pihak_lain'],
            'jumlah'          => (float) $r['jumlah'],
            'catatan'         => (string) ($r['catatan'] ?? ''),
            'status'          => ((string) $r['status'] !== '') ? (string) $r['status'] : 'Belum Lunas',
            'tanggalLunas'    => formatDateVal($r['tanggal_lunas']),
            'dompetPelunasan' => (string) $r['dompet_pelunasan'],
        ];
    }
    return $out;
}

function getSavingsData(PDO $pdo, string $userId): array
{
    $stmt = $pdo->prepare('SELECT id, nama_target, target_amount, current_amount, tanggal_target, catatan, status, created_at FROM tabungan WHERE user_id = ? ORDER BY seq ASC');
    $stmt->execute([$userId]);
    $out = [];
    foreach ($stmt->fetchAll() as $r) {
        $out[] = [
            'id'            => (string) $r['id'],
            'namaTarget'    => (string) $r['nama_target'],
            'targetAmount'  => (float) $r['target_amount'],
            'currentAmount' => (float) $r['current_amount'],
            'tanggalTarget' => formatDateVal($r['tanggal_target']),
            'catatan'       => (string) ($r['catatan'] ?? ''),
            'status'        => ((string) $r['status'] !== '') ? (string) $r['status'] : 'Berjalan',
            'createdAt'     => formatDateVal($r['created_at']),
        ];
    }
    return $out;
}

function getRecurringData(PDO $pdo, string $userId): array
{
    $stmt = $pdo->prepare('SELECT id, nama_tagihan, tipe, kategori, jumlah, dompet, hari_tempo, catatan, last_processed_month FROM transaksi_rutin WHERE user_id = ? ORDER BY seq ASC');
    $stmt->execute([$userId]);
    $out = [];
    foreach ($stmt->fetchAll() as $r) {
        $hari = (int) $r['hari_tempo'];
        if ($hari === 0) {
            $hari = 1;
        }
        $out[] = [
            'id'                  => (string) $r['id'],
            'namaTagihan'         => (string) $r['nama_tagihan'],
            'tipe'                => ((string) $r['tipe'] !== '') ? (string) $r['tipe'] : 'Pengeluaran',
            'kategori'            => ((string) $r['kategori'] !== '') ? (string) $r['kategori'] : 'Tagihan & Utilitas',
            'jumlah'              => (float) $r['jumlah'],
            'dompet'              => ((string) $r['dompet'] !== '') ? (string) $r['dompet'] : 'Kas / Tunai',
            'hariTempo'           => $hari,
            'catatan'             => (string) ($r['catatan'] ?? ''),
            'lastProcessedMonth'  => formatMonthVal($r['last_processed_month']),
        ];
    }
    return $out;
}

function getWishlistData(PDO $pdo, string $userId): array
{
    $stmt = $pdo->prepare('SELECT id, nama_barang, tipe, estimasi_harga, prioritas, catatan, status, tanggal_target FROM wishlist WHERE user_id = ? ORDER BY seq ASC');
    $stmt->execute([$userId]);
    $out = [];
    foreach ($stmt->fetchAll() as $r) {
        $out[] = [
            'id'            => (string) $r['id'],
            'namaBarang'    => (string) $r['nama_barang'],
            'tipe'          => ((string) $r['tipe'] !== '') ? (string) $r['tipe'] : 'Kebutuhan',
            'estimasiHarga' => (float) $r['estimasi_harga'],
            'prioritas'     => ((string) $r['prioritas'] !== '') ? (string) $r['prioritas'] : 'Sedang',
            'catatan'       => (string) ($r['catatan'] ?? ''),
            'status'        => ((string) $r['status'] !== '') ? (string) $r['status'] : 'Belum Terbeli',
            'tanggalTarget' => formatDateVal($r['tanggal_target']),
        ];
    }
    return $out;
}

function getBudgetsData(PDO $pdo, string $userId): array
{
    $stmt = $pdo->prepare('SELECT id, bulan, kategori, limit_amount FROM anggaran WHERE user_id = ? ORDER BY seq ASC');
    $stmt->execute([$userId]);
    $out = [];
    foreach ($stmt->fetchAll() as $r) {
        $out[] = [
            'id'       => (string) $r['id'],
            'bulan'    => formatMonthVal($r['bulan']),
            'kategori' => (string) $r['kategori'],
            'limit'    => (float) $r['limit_amount'],
        ];
    }
    return $out;
}

function getCustomCategoriesData(PDO $pdo, string $userId): array
{
    $stmt = $pdo->prepare('SELECT id, kategori, tipe FROM kategori_kustom WHERE user_id = ? ORDER BY seq ASC');
    $stmt->execute([$userId]);
    $out = [];
    foreach ($stmt->fetchAll() as $r) {
        $out[] = [
            'id'       => (string) $r['id'],
            'kategori' => (string) $r['kategori'],
            'tipe'     => ((string) $r['tipe'] !== '') ? (string) $r['tipe'] : 'Pengeluaran',
        ];
    }
    return $out;
}

function h_getAllUserData(PDO $pdo, array $args): array
{
    $user = requireAuth($pdo, $args[0] ?? null);
    $userId = (string) $user['id'];
    return [
        'status'          => 'success',
        'transactions'    => getTransactionsData($pdo, $userId),
        'debts'           => getDebtsData($pdo, $userId),
        'savings'         => getSavingsData($pdo, $userId),
        'recurring'       => getRecurringData($pdo, $userId),
        'wishlist'        => getWishlistData($pdo, $userId),
        'budgets'         => getBudgetsData($pdo, $userId),
        'customCategories' => getCustomCategoriesData($pdo, $userId),
    ];
}

// ---------------------------------------------------------------------------
// Transaksi: tambah / ubah / hapus
// ---------------------------------------------------------------------------

function h_addTransaction(PDO $pdo, array $args): array
{
    $user = requireAuth($pdo, $args[0] ?? null);
    $userId = (string) $user['id'];
    $p = payloadArg($args, 1);

    $sourceWallet = trim((string) ($p['dompet'] ?? 'Kas / Tunai'));
    if ($sourceWallet === '') {
        $sourceWallet = 'Kas / Tunai';
    }
    $txAmount = numArg($p, 'jumlah');
    $txType = (string) ($p['tipe'] ?? 'Pengeluaran');
    if ($txType === '') {
        $txType = 'Pengeluaran';
    }

    if ($txAmount <= 0) {
        throw new Exception('Nominal transaksi harus lebih besar dari 0.');
    }
    // Urutan sama seperti Code.gs: cek saldo dulu, baru cek dompet sama.
    if ($txType === 'Pengeluaran' || $txType === 'Transfer') {
        assertWalletBalance($pdo, $userId, $sourceWallet, $txAmount);
    }

    $tanggal = sanitizeCell(strArg($p, 'tanggal') !== '' ? strArg($p, 'tanggal') : todayId());
    $tipe = sanitizeCell($txType);
    $kategori = ($txType === 'Transfer') ? '' : sanitizeCell($p['kategori'] ?? '');
    $catatan = sanitizeCell($p['catatan'] ?? '');
    $dompet = sanitizeCell($sourceWallet);
    $dompetTujuan = sanitizeCell($p['dompetTujuan'] ?? '');
    if ($txType === 'Transfer' && $sourceWallet === ($dompetTujuan !== '' ? $dompetTujuan : 'Kas / Tunai')) {
        throw new Exception('Dompet asal dan tujuan tidak boleh sama.');
    }

    $struk = '';
    $strukBase64 = (string) ($p['strukBase64'] ?? '');
    if ($strukBase64 !== '') {
        $struk = saveReceipt($userId, $strukBase64);
    }

    $id = newId('TX-');
    $stmt = $pdo->prepare('INSERT INTO transaksi (id, user_id, tanggal, tipe, kategori, jumlah, catatan, struk, dompet, dompet_tujuan) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)');
    $stmt->execute([$id, $userId, $tanggal, $tipe, $kategori, $txAmount, $catatan, $struk, $dompet, $dompetTujuan]);

    return [
        'status'  => 'success',
        'message' => 'Transaksi berhasil disimpan!',
        'data'    => ['id' => $id, 'tanggal' => $tanggal, 'tipe' => $tipe, 'kategori' => $kategori, 'jumlah' => $txAmount, 'catatan' => $catatan, 'struk' => $struk, 'dompet' => $dompet, 'dompetTujuan' => $dompetTujuan],
    ];
}

function h_updateTransaction(PDO $pdo, array $args): array
{
    $user = requireAuth($pdo, $args[0] ?? null);
    $userId = (string) $user['id'];
    $id = (string) ($args[1] ?? '');
    $p = payloadArg($args, 2);

    $sourceWallet = trim((string) ($p['dompet'] ?? 'Kas / Tunai'));
    if ($sourceWallet === '') {
        $sourceWallet = 'Kas / Tunai';
    }
    $txAmount = numArg($p, 'jumlah');
    $txType = (string) ($p['tipe'] ?? 'Pengeluaran');
    if ($txType === '') {
        $txType = 'Pengeluaran';
    }

    if ($txAmount <= 0) {
        throw new Exception('Nominal transaksi harus lebih besar dari 0.');
    }
    // Sama seperti Code.gs: dompet tujuan kosong dianggap 'Kas / Tunai'.
    $tujuanCheck = trim((string) ($p['dompetTujuan'] ?? 'Kas / Tunai'));
    if ($txType === 'Transfer' && $sourceWallet === $tujuanCheck) {
        throw new Exception('Dompet asal dan tujuan tidak boleh sama.');
    }
    if ($txType === 'Pengeluaran' || $txType === 'Transfer') {
        // Validasi saldo mengecualikan transaksi yang sedang diubah.
        $others = array_values(array_filter(
            getTransactionsData($pdo, $userId),
            function ($t) use ($id) { return (string) $t['id'] !== $id; }
        ));
        $balance = getWalletBalanceFromTransactions($others, $sourceWallet);
        if ($balance < $txAmount) {
            throw new Exception('Saldo dompet "' . $sourceWallet . '" tidak mencukupi! (Saldo saat ini: Rp ' . idr($balance) . ')');
        }
    }

    $stmt = $pdo->prepare('SELECT struk FROM transaksi WHERE id = ? AND user_id = ? LIMIT 1');
    $stmt->execute([$id, $userId]);
    $old = $stmt->fetch();
    if ($old === false) {
        throw new Exception('ID transaksi tidak ditemukan');
    }

    $struk = (string) $old['struk'];
    $tanggal = sanitizeCell(strArg($p, 'tanggal') !== '' ? strArg($p, 'tanggal') : todayId());
    $tipe = sanitizeCell($txType);
    $kategori = ($txType === 'Transfer') ? '' : sanitizeCell($p['kategori'] ?? '');
    $catatan = sanitizeCell($p['catatan'] ?? '');
    $dompet = sanitizeCell($sourceWallet);
    $dompetTujuan = sanitizeCell($p['dompetTujuan'] ?? '');
    $strukBase64 = (string) ($p['strukBase64'] ?? '');
    if ($strukBase64 !== '') {
        $struk = saveReceipt($userId, $strukBase64);
    }

    $stmt = $pdo->prepare('UPDATE transaksi SET tanggal = ?, tipe = ?, kategori = ?, jumlah = ?, catatan = ?, struk = ?, dompet = ?, dompet_tujuan = ? WHERE id = ? AND user_id = ?');
    $stmt->execute([$tanggal, $tipe, $kategori, $txAmount, $catatan, $struk, $dompet, $dompetTujuan, $id, $userId]);

    return [
        'status'  => 'success',
        'message' => 'Transaksi berhasil diperbarui!',
        'data'    => ['id' => $id, 'tanggal' => $tanggal, 'tipe' => $tipe, 'kategori' => $kategori, 'jumlah' => $txAmount, 'catatan' => $catatan, 'struk' => $struk, 'dompet' => $dompet, 'dompetTujuan' => $dompetTujuan],
    ];
}

/** Hapus generik satu baris milik user (pesan mengikuti Code.gs). */
function deleteUserRow(PDO $pdo, string $table, string $userId, string $id, string $emptyMsg, string $notFoundMsg, string $okMsg): array
{
    $stmt = $pdo->prepare("SELECT COUNT(*) AS c FROM {$table} WHERE user_id = ?");
    $stmt->execute([$userId]);
    if ((int) $stmt->fetch()['c'] === 0) {
        return ['status' => 'error', 'message' => $emptyMsg];
    }
    $stmt = $pdo->prepare("DELETE FROM {$table} WHERE id = ? AND user_id = ?");
    $stmt->execute([$id, $userId]);
    if ($stmt->rowCount() === 0) {
        return ['status' => 'error', 'message' => $notFoundMsg];
    }
    return ['status' => 'success', 'message' => $okMsg];
}

function h_deleteTransaction(PDO $pdo, array $args): array
{
    $user = requireAuth($pdo, $args[0] ?? null);
    return deleteUserRow($pdo, 'transaksi', (string) $user['id'], (string) ($args[1] ?? ''), 'Data kosong', 'ID transaksi tidak ditemukan', 'Transaksi berhasil dihapus!');
}

// ---------------------------------------------------------------------------
// Hutang & piutang: tambah / lunasi / hapus
// ---------------------------------------------------------------------------

function h_addDebt(PDO $pdo, array $args): array
{
    $user = requireAuth($pdo, $args[0] ?? null);
    $userId = (string) $user['id'];
    $p = payloadArg($args, 1);

    $tipe = sanitizeCell($p['tipe'] ?? 'Hutang');
    if ($tipe === '') {
        $tipe = 'Hutang';
    }
    $pihakLain = trim(sanitizeCell($p['pihakLain'] ?? ''));
    $jumlah = numArg($p, 'jumlah');
    $jatuhTempo = sanitizeCell($p['jatuhTempo'] ?? '');
    $catatan = sanitizeCell($p['catatan'] ?? '');

    if ($pihakLain === '') {
        throw new Exception('Nama pihak lain wajib diisi.');
    }
    if ($jumlah <= 0) {
        throw new Exception('Nominal pinjaman harus lebih dari 0.');
    }

    $id = newId('DEBT-');
    $tanggal = todayId();
    $stmt = $pdo->prepare('INSERT INTO hutang_piutang (id, user_id, tanggal, jatuh_tempo, tipe, pihak_lain, jumlah, catatan, status, tanggal_lunas, dompet_pelunasan) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)');
    $stmt->execute([$id, $userId, $tanggal, $jatuhTempo, $tipe, $pihakLain, $jumlah, $catatan, 'Belum Lunas', '', '']);

    return [
        'status'  => 'success',
        'message' => 'Catatan pinjaman berhasil disimpan!',
        'data'    => ['id' => $id, 'tanggal' => $tanggal, 'jatuhTempo' => $jatuhTempo, 'tipe' => $tipe, 'pihakLain' => $pihakLain, 'jumlah' => $jumlah, 'catatan' => $catatan, 'status' => 'Belum Lunas'],
    ];
}

function h_payoffDebt(PDO $pdo, array $args): array
{
    $user = requireAuth($pdo, $args[0] ?? null);
    $userId = (string) $user['id'];
    $p = payloadArg($args, 1);

    $debtId = (string) ($p['debtId'] ?? '');
    $walletName = sanitizeCell($p['walletName'] ?? 'Kas / Tunai');
    if ($walletName === '') {
        $walletName = 'Kas / Tunai';
    }
    $payDate = strArg($p, 'payDate') !== '' ? strArg($p, 'payDate') : todayId();

    $stmt = $pdo->prepare('SELECT id, tipe, pihak_lain, jumlah, status FROM hutang_piutang WHERE id = ? AND user_id = ? LIMIT 1');
    $stmt->execute([$debtId, $userId]);
    $debt = $stmt->fetch();
    if ($debt === false) {
        throw new Exception('Pinjaman tidak ditemukan.');
    }
    if ((string) $debt['status'] === 'Lunas') {
        throw new Exception('Pinjaman ini sudah lunas.');
    }
    $jumlah = (float) $debt['jumlah'];
    if ((string) $debt['tipe'] === 'Hutang') {
        assertWalletBalance($pdo, $userId, $walletName, $jumlah);
    }

    $pdo->beginTransaction();
    try {
        $stmt = $pdo->prepare('UPDATE hutang_piutang SET status = ?, tanggal_lunas = ?, dompet_pelunasan = ? WHERE id = ? AND user_id = ?');
        $stmt->execute(['Lunas', $payDate, $walletName, $debtId, $userId]);
        $isHutang = ((string) $debt['tipe'] === 'Hutang');
        $txTipe = $isHutang ? 'Pengeluaran' : 'Pemasukan';
        $txKategori = $isHutang ? 'Tagihan & Utilitas' : 'Lainnya';
        $txCatatan = sanitizeCell('Pelunasan ' . (string) $debt['tipe'] . ': ' . (string) $debt['pihak_lain']);
        $stmt = $pdo->prepare('INSERT INTO transaksi (id, user_id, tanggal, tipe, kategori, jumlah, catatan, struk, dompet, dompet_tujuan) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)');
        $stmt->execute([newId('TX-PELUNASAN-'), $userId, $payDate, $txTipe, $txKategori, $jumlah, $txCatatan, '', $walletName, '']);
        $pdo->commit();
    } catch (Throwable $e) {
        $pdo->rollBack();
        throw $e;
    }

    return ['status' => 'success', 'message' => 'Pinjaman berhasil dilunasi & dicatat ke riwayat transaksi!'];
}

function h_deleteDebt(PDO $pdo, array $args): array
{
    $user = requireAuth($pdo, $args[0] ?? null);
    return deleteUserRow($pdo, 'hutang_piutang', (string) $user['id'], (string) ($args[1] ?? ''), 'Data kosong', 'ID pinjaman tidak ditemukan', 'Catatan pinjaman berhasil dihapus!');
}

// ---------------------------------------------------------------------------
// Target tabungan: tambah / setor / hapus
// ---------------------------------------------------------------------------

function h_addSavingsGoal(PDO $pdo, array $args): array
{
    $user = requireAuth($pdo, $args[0] ?? null);
    $userId = (string) $user['id'];
    $p = payloadArg($args, 1);

    $namaTarget = trim(sanitizeCell($p['namaTarget'] ?? ''));
    $targetAmount = numArg($p, 'targetAmount');
    $currentAmount = numArg($p, 'currentAmount');
    $tanggalTarget = sanitizeCell($p['tanggalTarget'] ?? '');
    $catatan = sanitizeCell($p['catatan'] ?? '');
    $walletName = sanitizeCell($p['walletName'] ?? 'Kas / Tunai');
    if ($walletName === '') {
        $walletName = 'Kas / Tunai';
    }
    $status = ($currentAmount >= $targetAmount && $targetAmount > 0) ? 'Tercapai' : 'Berjalan';
    $createdAt = todayId();

    if ($namaTarget === '') {
        throw new Exception('Nama target impian wajib diisi.');
    }
    if ($targetAmount <= 0) {
        throw new Exception('Target nominal harus lebih besar dari 0.');
    }
    if ($currentAmount < 0) {
        throw new Exception('Setoran awal tidak boleh negatif.');
    }
    if ($currentAmount > 0) {
        assertWalletBalance($pdo, $userId, $walletName, $currentAmount);
    }

    $id = newId('GOAL-');
    $pdo->beginTransaction();
    try {
        $stmt = $pdo->prepare('INSERT INTO tabungan (id, user_id, nama_target, target_amount, current_amount, tanggal_target, catatan, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)');
        $stmt->execute([$id, $userId, $namaTarget, $targetAmount, $currentAmount, $tanggalTarget, $catatan, $status, $createdAt]);
        if ($currentAmount > 0) {
            $txCatatan = sanitizeCell('Setor Awal Tabungan: ' . $namaTarget);
            $stmt = $pdo->prepare('INSERT INTO transaksi (id, user_id, tanggal, tipe, kategori, jumlah, catatan, struk, dompet, dompet_tujuan) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)');
            $stmt->execute([newId('TX-TABUNGAN-'), $userId, todayId(), 'Pengeluaran', 'Investasi & Tabungan', $currentAmount, $txCatatan, '', $walletName, '']);
        }
        $pdo->commit();
    } catch (Throwable $e) {
        $pdo->rollBack();
        throw $e;
    }

    return [
        'status'  => 'success',
        'message' => 'Target tabungan berhasil disimpan!',
        'data'    => ['id' => $id, 'namaTarget' => $namaTarget, 'targetAmount' => $targetAmount, 'currentAmount' => $currentAmount, 'tanggalTarget' => $tanggalTarget, 'catatan' => $catatan, 'status' => $status, 'createdAt' => $createdAt],
    ];
}

function h_depositSavingsGoal(PDO $pdo, array $args): array
{
    $user = requireAuth($pdo, $args[0] ?? null);
    $userId = (string) $user['id'];
    $p = payloadArg($args, 1);

    $goalId = (string) ($p['goalId'] ?? '');
    $amount = numArg($p, 'amount');
    $walletName = sanitizeCell($p['walletName'] ?? 'Kas / Tunai');
    if ($walletName === '') {
        $walletName = 'Kas / Tunai';
    }
    $depositDate = strArg($p, 'depositDate') !== '' ? strArg($p, 'depositDate') : todayId();

    if ($amount <= 0) {
        throw new Exception('Nominal setoran harus lebih dari 0.');
    }

    $stmt = $pdo->prepare('SELECT id, nama_target, target_amount, current_amount, status FROM tabungan WHERE id = ? AND user_id = ? LIMIT 1');
    $stmt->execute([$goalId, $userId]);
    $goal = $stmt->fetch();
    if ($goal === false) {
        throw new Exception('Target tabungan tidak ditemukan.');
    }
    if ((string) $goal['status'] === 'Tercapai') {
        throw new Exception('Target tabungan ini sudah tercapai.');
    }

    assertWalletBalance($pdo, $userId, $walletName, $amount);

    $newCurrent = (float) $goal['current_amount'] + $amount;
    $newStatus = ($newCurrent >= (float) $goal['target_amount']) ? 'Tercapai' : 'Berjalan';

    $pdo->beginTransaction();
    try {
        $stmt = $pdo->prepare('UPDATE tabungan SET current_amount = ?, status = ? WHERE id = ? AND user_id = ?');
        $stmt->execute([$newCurrent, $newStatus, $goalId, $userId]);
        $txCatatan = sanitizeCell('Setor Tabungan: ' . (string) $goal['nama_target']);
        $stmt = $pdo->prepare('INSERT INTO transaksi (id, user_id, tanggal, tipe, kategori, jumlah, catatan, struk, dompet, dompet_tujuan) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)');
        $stmt->execute([newId('TX-TABUNGAN-'), $userId, $depositDate, 'Pengeluaran', 'Investasi & Tabungan', $amount, $txCatatan, '', $walletName, '']);
        $pdo->commit();
    } catch (Throwable $e) {
        $pdo->rollBack();
        throw $e;
    }

    return ['status' => 'success', 'message' => 'Setoran sebesar Rp ' . idr($amount) . ' berhasil ditambahkan!'];
}

function h_deleteSavingsGoal(PDO $pdo, array $args): array
{
    $user = requireAuth($pdo, $args[0] ?? null);
    return deleteUserRow($pdo, 'tabungan', (string) $user['id'], (string) ($args[1] ?? ''), 'Data kosong', 'ID target tabungan tidak ditemukan', 'Target tabungan berhasil dihapus!');
}

// ---------------------------------------------------------------------------
// Tagihan rutin: tambah / bayar / hapus
// ---------------------------------------------------------------------------

function h_addRecurringTransaction(PDO $pdo, array $args): array
{
    $user = requireAuth($pdo, $args[0] ?? null);
    $userId = (string) $user['id'];
    $p = payloadArg($args, 1);

    $namaTagihan = trim(sanitizeCell($p['namaTagihan'] ?? ''));
    $tipe = sanitizeCell($p['tipe'] ?? 'Pengeluaran');
    if ($tipe === '') {
        $tipe = 'Pengeluaran';
    }
    $kategori = sanitizeCell($p['kategori'] ?? 'Tagihan & Utilitas');
    if ($kategori === '') {
        $kategori = 'Tagihan & Utilitas';
    }
    $jumlah = numArg($p, 'jumlah');
    $dompet = sanitizeCell($p['dompet'] ?? 'Kas / Tunai');
    if ($dompet === '') {
        $dompet = 'Kas / Tunai';
    }
    $hariTempo = (int) numArg($p, 'hariTempo');
    if ($hariTempo === 0) {
        $hariTempo = 1;
    }
    $catatan = sanitizeCell($p['catatan'] ?? '');

    if ($namaTagihan === '') {
        throw new Exception('Nama tagihan wajib diisi.');
    }
    if ($jumlah <= 0) {
        throw new Exception('Nominal tagihan harus lebih dari 0.');
    }
    if ($hariTempo < 1 || $hariTempo > 31) {
        throw new Exception('Hari tempo harus 1-31.');
    }

    $id = newId('REC-');
    $stmt = $pdo->prepare('INSERT INTO transaksi_rutin (id, user_id, nama_tagihan, tipe, kategori, jumlah, dompet, hari_tempo, catatan, last_processed_month) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)');
    $stmt->execute([$id, $userId, $namaTagihan, $tipe, $kategori, $jumlah, $dompet, $hariTempo, $catatan, '']);

    return [
        'status'  => 'success',
        'message' => 'Tagihan rutin berhasil disimpan!',
        'data'    => ['id' => $id, 'namaTagihan' => $namaTagihan, 'tipe' => $tipe, 'kategori' => $kategori, 'jumlah' => $jumlah, 'dompet' => $dompet, 'hariTempo' => $hariTempo, 'catatan' => $catatan],
    ];
}

function h_payRecurringTransaction(PDO $pdo, array $args): array
{
    $user = requireAuth($pdo, $args[0] ?? null);
    $userId = (string) $user['id'];
    $p = payloadArg($args, 1);

    $recId = (string) ($p['recId'] ?? '');
    $payDate = strArg($p, 'payDate') !== '' ? strArg($p, 'payDate') : todayId();
    $currentMonth = substr($payDate, 0, 7);

    $stmt = $pdo->prepare('SELECT id, nama_tagihan, tipe, kategori, jumlah, dompet, catatan, last_processed_month FROM transaksi_rutin WHERE id = ? AND user_id = ? LIMIT 1');
    $stmt->execute([$recId, $userId]);
    $item = $stmt->fetch();
    if ($item === false) {
        throw new Exception('Tagihan rutin tidak ditemukan.');
    }

    // Sama seperti Code.gs: walletName || dompet item || 'Kas / Tunai'
    // (walletName kosong HARUS jatuh ke dompet item, bukan langsung ke
    // 'Kas / Tunai' — jangan memberi default sebelum baris ini).
    $walletRaw = sanitizeCell($p['walletName'] ?? '');
    $dompetFinal = ($walletRaw !== '') ? $walletRaw : (((string) $item['dompet'] !== '') ? (string) $item['dompet'] : 'Kas / Tunai');
    if (formatMonthVal($item['last_processed_month']) === $currentMonth) {
        throw new Exception('Tagihan ini sudah dibayar bulan ini.');
    }
    if ((string) $item['tipe'] === 'Pengeluaran') {
        assertWalletBalance($pdo, $userId, $dompetFinal, (float) $item['jumlah']);
    }

    $pdo->beginTransaction();
    try {
        $txCatatan = sanitizeCell('[Tagihan Rutin] ' . (string) $item['nama_tagihan'] . (((string) $item['catatan'] !== '') ? ' - ' . (string) $item['catatan'] : ''));
        $stmt = $pdo->prepare('INSERT INTO transaksi (id, user_id, tanggal, tipe, kategori, jumlah, catatan, struk, dompet, dompet_tujuan) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)');
        $stmt->execute([newId('TX-RUTIN-'), $userId, $payDate, (string) $item['tipe'], (string) $item['kategori'], (float) $item['jumlah'], $txCatatan, '', $dompetFinal, '']);
        $stmt = $pdo->prepare('UPDATE transaksi_rutin SET last_processed_month = ? WHERE id = ? AND user_id = ?');
        $stmt->execute([$currentMonth, $recId, $userId]);
        $pdo->commit();
    } catch (Throwable $e) {
        $pdo->rollBack();
        throw $e;
    }

    return ['status' => 'success', 'message' => 'Tagihan "' . (string) $item['nama_tagihan'] . '" sebesar Rp ' . idr((float) $item['jumlah']) . ' berhasil dicatat!'];
}

function h_deleteRecurringTransaction(PDO $pdo, array $args): array
{
    $user = requireAuth($pdo, $args[0] ?? null);
    return deleteUserRow($pdo, 'transaksi_rutin', (string) $user['id'], (string) ($args[1] ?? ''), 'Data kosong', 'ID tagihan rutin tidak ditemukan', 'Tagihan rutin berhasil dihapus!');
}

// ---------------------------------------------------------------------------
// Wishlist: tambah / beli / hapus
// ---------------------------------------------------------------------------

function h_addWishlistItem(PDO $pdo, array $args): array
{
    $user = requireAuth($pdo, $args[0] ?? null);
    $userId = (string) $user['id'];
    $p = payloadArg($args, 1);

    $namaBarang = trim((string) ($p['namaBarang'] ?? ''));
    $tipe = (string) ($p['tipe'] ?? 'Kebutuhan');
    if ($tipe === '') {
        $tipe = 'Kebutuhan';
    }
    $estimasiHarga = numArg($p, 'estimasiHarga');
    $prioritas = (string) ($p['prioritas'] ?? 'Sedang');
    if ($prioritas === '') {
        $prioritas = 'Sedang';
    }
    $catatan = (string) ($p['catatan'] ?? '');
    $tanggalTarget = (string) ($p['tanggalTarget'] ?? '');
    $status = 'Belum Terbeli';

    if ($namaBarang === '') {
        throw new Exception('Nama barang wajib diisi.');
    }
    if ($estimasiHarga <= 0) {
        throw new Exception('Estimasi harga harus lebih dari 0.');
    }

    // Catatan: Code.gs TIDAK menyaring nama/tipe wishlist lewat sanitizeCell
    // (hanya field tertentu), jadi di sini pun disimpan apa adanya.
    $id = newId('WISH-');
    $stmt = $pdo->prepare('INSERT INTO wishlist (id, user_id, nama_barang, tipe, estimasi_harga, prioritas, catatan, status, tanggal_target) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)');
    $stmt->execute([$id, $userId, $namaBarang, $tipe, $estimasiHarga, $prioritas, $catatan, $status, $tanggalTarget]);

    return [
        'status'  => 'success',
        'message' => 'Rencana belanja berhasil ditambahkan!',
        'data'    => ['id' => $id, 'namaBarang' => $namaBarang, 'tipe' => $tipe, 'estimasiHarga' => $estimasiHarga, 'prioritas' => $prioritas, 'catatan' => $catatan, 'status' => $status, 'tanggalTarget' => $tanggalTarget],
    ];
}

function h_buyWishlistItem(PDO $pdo, array $args): array
{
    $user = requireAuth($pdo, $args[0] ?? null);
    $userId = (string) $user['id'];
    $p = payloadArg($args, 1);

    $wishId = (string) ($p['wishId'] ?? '');
    $walletName = (string) ($p['walletName'] ?? 'Kas / Tunai');
    if ($walletName === '') {
        $walletName = 'Kas / Tunai';
    }
    $buyDate = strArg($p, 'buyDate') !== '' ? strArg($p, 'buyDate') : todayId();
    $category = (string) ($p['category'] ?? 'Belanja & Kebutuhan');
    if ($category === '') {
        $category = 'Belanja & Kebutuhan';
    }

    $stmt = $pdo->prepare('SELECT id, nama_barang, tipe, estimasi_harga, status FROM wishlist WHERE id = ? AND user_id = ? LIMIT 1');
    $stmt->execute([$wishId, $userId]);
    $item = $stmt->fetch();
    if ($item === false) {
        throw new Exception('Rencana belanja tidak ditemukan.');
    }
    if ((string) $item['status'] === 'Sudah Terbeli') {
        throw new Exception('Rencana belanja ini sudah dibeli.');
    }

    assertWalletBalance($pdo, $userId, $walletName, (float) $item['estimasi_harga']);

    $pdo->beginTransaction();
    try {
        $stmt = $pdo->prepare('UPDATE wishlist SET status = ? WHERE id = ? AND user_id = ?');
        $stmt->execute(['Sudah Terbeli', $wishId, $userId]);
        $txCatatan = 'Realisasi ' . (string) $item['tipe'] . ': ' . (string) $item['nama_barang'];
        $stmt = $pdo->prepare('INSERT INTO transaksi (id, user_id, tanggal, tipe, kategori, jumlah, catatan, struk, dompet, dompet_tujuan) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)');
        $stmt->execute([newId('TX-BELANJA-'), $userId, $buyDate, 'Pengeluaran', $category, (float) $item['estimasi_harga'], $txCatatan, '', $walletName, '']);
        $pdo->commit();
    } catch (Throwable $e) {
        $pdo->rollBack();
        throw $e;
    }

    return ['status' => 'success', 'message' => 'Pembelian "' . (string) $item['nama_barang'] . '" berhasil direalisasikan & dicatat!'];
}

function h_deleteWishlistItem(PDO $pdo, array $args): array
{
    $user = requireAuth($pdo, $args[0] ?? null);
    return deleteUserRow($pdo, 'wishlist', (string) $user['id'], (string) ($args[1] ?? ''), 'Data kosong', 'ID rencana belanja tidak ditemukan', 'Rencana belanja berhasil dihapus!');
}

// ---------------------------------------------------------------------------
// Anggaran: simpan (upsert) / hapus
// ---------------------------------------------------------------------------

function h_setBudget(PDO $pdo, array $args): array
{
    $user = requireAuth($pdo, $args[0] ?? null);
    $userId = (string) $user['id'];
    $p = payloadArg($args, 1);

    $bulan = trim(sanitizeCell($p['bulan'] ?? ''));
    $kategori = trim(sanitizeCell($p['kategori'] ?? ''));
    $limit = numArg($p, 'limit');

    if (preg_match('/^\d{4}-\d{2}$/', $bulan) !== 1) {
        throw new Exception('Format bulan tidak valid (gunakan yyyy-MM).');
    }
    if ($kategori === '') {
        throw new Exception('Kategori anggaran wajib diisi.');
    }
    if ($limit <= 0) {
        throw new Exception('Limit anggaran harus lebih besar dari 0.');
    }

    // Upsert per Bulan+Kategori (perbandingan bulan dinormalisasi seperti
    // Code.gs, agar data impor lama yang berbentuk tanggal penuh tetap cocok).
    $stmt = $pdo->prepare('SELECT id, bulan, kategori FROM anggaran WHERE user_id = ?');
    $stmt->execute([$userId]);
    foreach ($stmt->fetchAll() as $row) {
        if (formatMonthVal($row['bulan']) === $bulan && (string) $row['kategori'] === $kategori) {
            $upd = $pdo->prepare('UPDATE anggaran SET limit_amount = ? WHERE id = ? AND user_id = ?');
            $upd->execute([$limit, $row['id'], $userId]);
            return ['status' => 'success', 'message' => 'Anggaran berhasil diperbarui!'];
        }
    }
    $stmt = $pdo->prepare('INSERT INTO anggaran (id, user_id, bulan, kategori, limit_amount) VALUES (?, ?, ?, ?, ?)');
    $stmt->execute([newId('BUD-'), $userId, $bulan, $kategori, $limit]);
    return ['status' => 'success', 'message' => 'Anggaran berhasil disimpan!'];
}

function h_deleteBudget(PDO $pdo, array $args): array
{
    $user = requireAuth($pdo, $args[0] ?? null);
    return deleteUserRow($pdo, 'anggaran', (string) $user['id'], (string) ($args[1] ?? ''), 'Data kosong', 'ID anggaran tidak ditemukan', 'Anggaran berhasil dihapus!');
}

// ---------------------------------------------------------------------------
// Kategori kustom: tambah / hapus
// ---------------------------------------------------------------------------

function h_addCustomCategory(PDO $pdo, array $args): array
{
    $user = requireAuth($pdo, $args[0] ?? null);
    $userId = (string) $user['id'];
    $p = payloadArg($args, 1);

    $kategori = trim(sanitizeCell($p['kategori'] ?? ''));
    $tipe = (string) ($p['tipe'] ?? 'Pengeluaran');
    if ($kategori === '') {
        throw new Exception('Nama kategori wajib diisi.');
    }
    if ($tipe !== 'Pemasukan' && $tipe !== 'Pengeluaran') {
        throw new Exception('Tipe kategori tidak valid.');
    }

    $existing = getCustomCategoriesData($pdo, $userId);
    foreach ($existing as $c) {
        if ($c['tipe'] === $tipe && strtolower($c['kategori']) === strtolower($kategori)) {
            throw new Exception('Kategori "' . $kategori . '" sudah ada untuk tipe ' . $tipe . '.');
        }
    }

    $id = newId('CAT-');
    $stmt = $pdo->prepare('INSERT INTO kategori_kustom (id, user_id, kategori, tipe) VALUES (?, ?, ?, ?)');
    $stmt->execute([$id, $userId, $kategori, $tipe]);

    return [
        'status'  => 'success',
        'message' => 'Kategori berhasil ditambahkan!',
        'data'    => ['id' => $id, 'kategori' => $kategori, 'tipe' => $tipe],
    ];
}

function h_deleteCustomCategory(PDO $pdo, array $args): array
{
    $user = requireAuth($pdo, $args[0] ?? null);
    return deleteUserRow($pdo, 'kategori_kustom', (string) $user['id'], (string) ($args[1] ?? ''), 'Data kosong', 'ID kategori tidak ditemukan', 'Kategori berhasil dihapus!');
}

// ---------------------------------------------------------------------------
// Edit & rename (edit-v1): ubah data yang sudah ada.
// Pola mengikuti h_updateTransaction: requireAuth dulu, verifikasi baris
// milik user (id + user_id), prepared statement, pesan Indonesia.
// ---------------------------------------------------------------------------

/** Nilai string dari payload bila key ada, bila tidak pakai nilai lama. */
function editStrArg(array $p, string $key, string $old): string
{
    if (!array_key_exists($key, $p)) {
        return $old;
    }
    return sanitizeCell($p[$key]);
}

/** Nilai angka dari payload bila key ada, bila tidak pakai nilai lama. */
function editNumArg(array $p, string $key, float $old): float
{
    if (!array_key_exists($key, $p)) {
        return $old;
    }
    return numArg($p, $key);
}

function h_updateDebt(PDO $pdo, array $args): array
{
    $user = requireAuth($pdo, $args[0] ?? null);
    $userId = (string) $user['id'];
    $id = (string) ($args[1] ?? '');
    $p = payloadArg($args, 2);

    $stmt = $pdo->prepare('SELECT tanggal, jatuh_tempo, pihak_lain, jumlah, catatan FROM hutang_piutang WHERE id = ? AND user_id = ? LIMIT 1');
    $stmt->execute([$id, $userId]);
    $old = $stmt->fetch();
    if ($old === false) {
        throw new Exception('ID pinjaman tidak ditemukan');
    }

    // Status TIDAK diubah di sini (alurnya dimiliki payoffDebt); tipe juga
    // tidak diubah (Hutang/Piutang adalah identitas pinjaman).
    $tanggal = strArg($p, 'tanggal') !== '' ? sanitizeCell(strArg($p, 'tanggal')) : (string) $old['tanggal'];
    $jatuhTempo = strArg($p, 'jatuhTempo') !== '' ? sanitizeCell(strArg($p, 'jatuhTempo')) : (string) $old['jatuh_tempo'];
    $pihakLain = trim(editStrArg($p, 'pihakLain', (string) $old['pihak_lain']));
    $jumlah = editNumArg($p, 'jumlah', (float) $old['jumlah']);
    $catatan = editStrArg($p, 'catatan', (string) $old['catatan']);

    if ($pihakLain === '') {
        throw new Exception('Nama pihak lain wajib diisi.');
    }
    if ($jumlah <= 0) {
        throw new Exception('Nominal pinjaman harus lebih dari 0.');
    }

    $stmt = $pdo->prepare('UPDATE hutang_piutang SET tanggal = ?, jatuh_tempo = ?, pihak_lain = ?, jumlah = ?, catatan = ? WHERE id = ? AND user_id = ?');
    $stmt->execute([$tanggal, $jatuhTempo, $pihakLain, $jumlah, $catatan, $id, $userId]);

    return [
        'status'  => 'success',
        'message' => 'Catatan pinjaman berhasil diperbarui!',
        'data'    => ['id' => $id, 'tanggal' => $tanggal, 'jatuhTempo' => $jatuhTempo, 'pihakLain' => $pihakLain, 'jumlah' => $jumlah, 'catatan' => $catatan],
    ];
}

function h_updateSavingsGoal(PDO $pdo, array $args): array
{
    $user = requireAuth($pdo, $args[0] ?? null);
    $userId = (string) $user['id'];
    $id = (string) ($args[1] ?? '');
    $p = payloadArg($args, 2);

    $stmt = $pdo->prepare('SELECT nama_target, target_amount, current_amount, tanggal_target, catatan FROM tabungan WHERE id = ? AND user_id = ? LIMIT 1');
    $stmt->execute([$id, $userId]);
    $old = $stmt->fetch();
    if ($old === false) {
        throw new Exception('Target tabungan tidak ditemukan.');
    }

    // current_amount TIDAK diubah di sini (alurnya dimiliki setor tabungan);
    // status dihitung ulang dari target baru, sama seperti tambah/setor.
    $namaTarget = trim(editStrArg($p, 'namaTarget', (string) $old['nama_target']));
    $targetAmount = editNumArg($p, 'targetAmount', (float) $old['target_amount']);
    $tanggalTarget = editStrArg($p, 'tanggalTarget', (string) $old['tanggal_target']);
    $catatan = editStrArg($p, 'catatan', (string) $old['catatan']);
    $currentAmount = (float) $old['current_amount'];
    $status = ($currentAmount >= $targetAmount && $targetAmount > 0) ? 'Tercapai' : 'Berjalan';

    if ($namaTarget === '') {
        throw new Exception('Nama target impian wajib diisi.');
    }
    if ($targetAmount <= 0) {
        throw new Exception('Target nominal harus lebih besar dari 0.');
    }

    $stmt = $pdo->prepare('UPDATE tabungan SET nama_target = ?, target_amount = ?, tanggal_target = ?, catatan = ?, status = ? WHERE id = ? AND user_id = ?');
    $stmt->execute([$namaTarget, $targetAmount, $tanggalTarget, $catatan, $status, $id, $userId]);

    return [
        'status'  => 'success',
        'message' => 'Target tabungan berhasil diperbarui!',
        'data'    => ['id' => $id, 'namaTarget' => $namaTarget, 'targetAmount' => $targetAmount, 'currentAmount' => $currentAmount, 'tanggalTarget' => $tanggalTarget, 'catatan' => $catatan, 'status' => $status],
    ];
}

function h_updateRecurringTransaction(PDO $pdo, array $args): array
{
    $user = requireAuth($pdo, $args[0] ?? null);
    $userId = (string) $user['id'];
    $id = (string) ($args[1] ?? '');
    $p = payloadArg($args, 2);

    $stmt = $pdo->prepare('SELECT nama_tagihan, tipe, kategori, jumlah, dompet, hari_tempo, catatan FROM transaksi_rutin WHERE id = ? AND user_id = ? LIMIT 1');
    $stmt->execute([$id, $userId]);
    $old = $stmt->fetch();
    if ($old === false) {
        throw new Exception('Tagihan rutin tidak ditemukan.');
    }

    // last_processed_month TIDAK diubah (alurnya dimiliki pembayaran).
    $namaTagihan = trim(editStrArg($p, 'namaTagihan', (string) $old['nama_tagihan']));
    $tipe = editStrArg($p, 'tipe', (string) $old['tipe']);
    if ($tipe !== 'Pemasukan' && $tipe !== 'Pengeluaran') {
        $tipe = (string) $old['tipe'];
    }
    $kategori = editStrArg($p, 'kategori', (string) $old['kategori']);
    if ($kategori === '') {
        $kategori = 'Tagihan & Utilitas';
    }
    $jumlah = editNumArg($p, 'jumlah', (float) $old['jumlah']);
    $dompet = editStrArg($p, 'dompet', (string) $old['dompet']);
    if ($dompet === '') {
        $dompet = 'Kas / Tunai';
    }
    // Jepit 1-31 seperti restore (bukan melempar seperti tambah).
    $hariTempo = (int) editNumArg($p, 'hariTempo', (float) $old['hari_tempo']);
    if ($hariTempo === 0) {
        $hariTempo = 1;
    }
    $hariTempo = min(31, max(1, $hariTempo));
    $catatan = editStrArg($p, 'catatan', (string) $old['catatan']);

    if ($namaTagihan === '') {
        throw new Exception('Nama tagihan wajib diisi.');
    }
    if ($jumlah <= 0) {
        throw new Exception('Nominal tagihan harus lebih dari 0.');
    }

    $stmt = $pdo->prepare('UPDATE transaksi_rutin SET nama_tagihan = ?, tipe = ?, kategori = ?, jumlah = ?, dompet = ?, hari_tempo = ?, catatan = ? WHERE id = ? AND user_id = ?');
    $stmt->execute([$namaTagihan, $tipe, $kategori, $jumlah, $dompet, $hariTempo, $catatan, $id, $userId]);

    return [
        'status'  => 'success',
        'message' => 'Tagihan rutin berhasil diperbarui!',
        'data'    => ['id' => $id, 'namaTagihan' => $namaTagihan, 'tipe' => $tipe, 'kategori' => $kategori, 'jumlah' => $jumlah, 'dompet' => $dompet, 'hariTempo' => $hariTempo, 'catatan' => $catatan],
    ];
}

function h_updateWishlistItem(PDO $pdo, array $args): array
{
    $user = requireAuth($pdo, $args[0] ?? null);
    $userId = (string) $user['id'];
    $id = (string) ($args[1] ?? '');
    $p = payloadArg($args, 2);

    $stmt = $pdo->prepare('SELECT nama_barang, tipe, estimasi_harga, prioritas, catatan, tanggal_target FROM wishlist WHERE id = ? AND user_id = ? LIMIT 1');
    $stmt->execute([$id, $userId]);
    $old = $stmt->fetch();
    if ($old === false) {
        throw new Exception('Rencana belanja tidak ditemukan.');
    }

    // Status TIDAK diubah di sini (alurnya dimiliki pembelian).
    $namaBarang = trim(editStrArg($p, 'namaBarang', (string) $old['nama_barang']));
    $tipe = editStrArg($p, 'tipe', (string) $old['tipe']);
    if ($tipe === '') {
        $tipe = 'Kebutuhan';
    }
    $estimasiHarga = editNumArg($p, 'estimasiHarga', (float) $old['estimasi_harga']);
    $prioritas = editStrArg($p, 'prioritas', (string) $old['prioritas']);
    if ($prioritas === '') {
        $prioritas = 'Sedang';
    }
    $catatan = editStrArg($p, 'catatan', (string) $old['catatan']);
    $tanggalTarget = editStrArg($p, 'tanggalTarget', (string) $old['tanggal_target']);

    if ($namaBarang === '') {
        throw new Exception('Nama barang wajib diisi.');
    }
    if ($estimasiHarga <= 0) {
        throw new Exception('Estimasi harga harus lebih dari 0.');
    }

    $stmt = $pdo->prepare('UPDATE wishlist SET nama_barang = ?, tipe = ?, estimasi_harga = ?, prioritas = ?, catatan = ?, tanggal_target = ? WHERE id = ? AND user_id = ?');
    $stmt->execute([$namaBarang, $tipe, $estimasiHarga, $prioritas, $catatan, $tanggalTarget, $id, $userId]);

    return [
        'status'  => 'success',
        'message' => 'Rencana belanja berhasil diperbarui!',
        'data'    => ['id' => $id, 'namaBarang' => $namaBarang, 'tipe' => $tipe, 'estimasiHarga' => $estimasiHarga, 'prioritas' => $prioritas, 'catatan' => $catatan, 'tanggalTarget' => $tanggalTarget],
    ];
}

function h_renameCustomCategory(PDO $pdo, array $args): array
{
    $user = requireAuth($pdo, $args[0] ?? null);
    $userId = (string) $user['id'];
    $oldName = trim(sanitizeCell($args[1] ?? ''));
    $newName = trim(sanitizeCell($args[2] ?? ''));

    if ($oldName === '' || $newName === '') {
        throw new Exception('Nama kategori lama dan baru wajib diisi.');
    }
    if ($oldName === $newName) {
        throw new Exception('Nama kategori baru sama dengan nama lama.');
    }

    $stmt = $pdo->prepare('SELECT COUNT(*) AS c FROM kategori_kustom WHERE user_id = ? AND kategori = ?');
    $stmt->execute([$userId, $newName]);
    if ((int) $stmt->fetch()['c'] > 0) {
        throw new Exception('Kategori "' . $newName . '" sudah ada.');
    }

    // Satu transaksi database: baris kategori + semua baris pemakai nama
    // itu (transaksi, tagihan rutin, anggaran) berubah bersamaan.
    $pdo->beginTransaction();
    try {
        $total = 0;
        $upd = $pdo->prepare('UPDATE kategori_kustom SET kategori = ? WHERE user_id = ? AND kategori = ?');
        $upd->execute([$newName, $userId, $oldName]);
        $total += $upd->rowCount();
        $upd = $pdo->prepare('UPDATE transaksi SET kategori = ? WHERE user_id = ? AND kategori = ?');
        $upd->execute([$newName, $userId, $oldName]);
        $total += $upd->rowCount();
        $upd = $pdo->prepare('UPDATE transaksi_rutin SET kategori = ? WHERE user_id = ? AND kategori = ?');
        $upd->execute([$newName, $userId, $oldName]);
        $total += $upd->rowCount();
        $upd = $pdo->prepare('UPDATE anggaran SET kategori = ? WHERE user_id = ? AND kategori = ?');
        $upd->execute([$newName, $userId, $oldName]);
        $total += $upd->rowCount();
        if ($total === 0) {
            throw new Exception('Kategori "' . $oldName . '" tidak ditemukan.');
        }
        $pdo->commit();
    } catch (Throwable $e) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        throw $e;
    }

    return [
        'status'  => 'success',
        'message' => 'Kategori "' . $oldName . '" berhasil diubah menjadi "' . $newName . '".',
        'data'    => ['oldName' => $oldName, 'newName' => $newName, 'updatedRows' => $total],
    ];
}

function h_renameWallet(PDO $pdo, array $args): array
{
    $user = requireAuth($pdo, $args[0] ?? null);
    $userId = (string) $user['id'];
    $oldName = trim(sanitizeCell($args[1] ?? ''));
    $newName = trim(sanitizeCell($args[2] ?? ''));

    // Lewati tanpa error: tidak ada yang berubah.
    if ($oldName === '' || $newName === '' || $oldName === $newName) {
        return ['status' => 'success', 'message' => 'Nama dompet tidak berubah.'];
    }

    // Satu transaksi database: nama dompet di transaksi (asal & tujuan),
    // tagihan rutin, dan dompet pelunasan hutang berubah bersamaan.
    // Mengganti ke nama dompet yang sudah ada berarti menggabungkan
    // riwayat dan saldo kedua dompet itu — diizinkan dengan sengaja.
    $pdo->beginTransaction();
    try {
        $total = 0;
        $upd = $pdo->prepare('UPDATE transaksi SET dompet = ? WHERE user_id = ? AND dompet = ?');
        $upd->execute([$newName, $userId, $oldName]);
        $total += $upd->rowCount();
        $upd = $pdo->prepare('UPDATE transaksi SET dompet_tujuan = ? WHERE user_id = ? AND dompet_tujuan = ?');
        $upd->execute([$newName, $userId, $oldName]);
        $total += $upd->rowCount();
        $upd = $pdo->prepare('UPDATE transaksi_rutin SET dompet = ? WHERE user_id = ? AND dompet = ?');
        $upd->execute([$newName, $userId, $oldName]);
        $total += $upd->rowCount();
        $upd = $pdo->prepare('UPDATE hutang_piutang SET dompet_pelunasan = ? WHERE user_id = ? AND dompet_pelunasan = ?');
        $upd->execute([$newName, $userId, $oldName]);
        $total += $upd->rowCount();
        $pdo->commit();
    } catch (Throwable $e) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        throw $e;
    }

    return [
        'status'  => 'success',
        'message' => 'Dompet "' . $oldName . '" berhasil diubah menjadi "' . $newName . '".',
        'data'    => ['oldName' => $oldName, 'newName' => $newName, 'updatedRows' => $total],
    ];
}

function h_updateProfile(PDO $pdo, array $args): array
{
    // requireAuth mengembalikan baris user lengkap (termasuk
    // password_hash dan salt) sehingga verifikasi kata sandi lama bisa
    // memakai logika yang persis sama dengan h_loginUser.
    $user = requireAuth($pdo, $args[0] ?? null);
    $userId = (string) $user['id'];
    $p = payloadArg($args, 1);

    // Email TIDAK PERNAH diubah lewat aksi ini (identitas login + kunci
    // unik); field email di payload sengaja diabaikan.
    $nama = trim((string) ($p['nama'] ?? ''));
    $newPassword = (string) ($p['newPassword'] ?? '');
    $currentPassword = (string) ($p['currentPassword'] ?? '');

    $setParts = [];
    $params = [];
    if ($nama !== '') {
        $setParts[] = 'nama = ?';
        $params[] = $nama;
    }
    if ($newPassword !== '') {
        if ($currentPassword === '') {
            throw new Exception('Kata sandi lama wajib diisi untuk mengubah kata sandi.');
        }
        if (strlen($newPassword) < 6) {
            throw new Exception('Password baru minimal 6 karakter.');
        }
        // Verifikasi kata sandi lama: bcrypt dulu, lalu legacy SHA-256
        // (bersalt password|salt, atau tanpa salt) — persis h_loginUser.
        $ok = false;
        if (is_string($user['password_hash']) && password_verify($currentPassword, $user['password_hash'])) {
            $ok = true;
        } else {
            $salt = $user['salt'];
            $expected = ($salt !== null && (string) $salt !== '')
                ? hash('sha256', $currentPassword . '|' . (string) $salt)
                : hash('sha256', $currentPassword);
            if (hash_equals((string) $user['password_hash'], $expected)) {
                $ok = true;
            }
        }
        if (!$ok) {
            throw new Exception('Kata sandi lama salah.');
        }
        // Simpan persis seperti h_registerUser: bcrypt, salt dikosongkan.
        $setParts[] = 'password_hash = ?';
        $params[] = password_hash($newPassword, PASSWORD_DEFAULT);
        $setParts[] = 'salt = NULL';
    }
    if (empty($setParts)) {
        throw new Exception('Tidak ada perubahan untuk disimpan.');
    }

    $params[] = $userId;
    $stmt = $pdo->prepare('UPDATE users SET ' . implode(', ', $setParts) . ' WHERE id = ?');
    $stmt->execute($params);

    $stmt = $pdo->prepare('SELECT nama, email, digest_optin FROM users WHERE id = ? LIMIT 1');
    $stmt->execute([$userId]);
    $row = $stmt->fetch();

    return [
        'status'  => 'success',
        'message' => 'Profil berhasil diperbarui!',
        'user'    => $row !== false ? publicUser($row) : ['name' => $nama, 'email' => (string) $user['email'], 'digestOptIn' => (string) ($user['digest_optin'] ?? 'YA')],
    ];
}

// ---------------------------------------------------------------------------
// Backup: pulihkan seluruh data (7 tabel, TANPA menyentuh tabel users)
// ---------------------------------------------------------------------------

function h_restoreUserData(PDO $pdo, array $args): array
{
    $user = requireAuth($pdo, $args[0] ?? null);
    $userId = (string) $user['id'];
    $data = payloadArg($args, 1);

    // Code.gs hanya memeriksa "object"; validasi app==='KEUANGANKU' sudah
    // dilakukan frontend sebelum berkas dikirim.
    $arr = function ($v) { return is_array($v) ? $v : []; };
    $txs = $arr($data['transactions'] ?? null);
    $debts = $arr($data['debts'] ?? null);
    $savings = $arr($data['savings'] ?? null);
    $recurring = $arr($data['recurring'] ?? null);
    $wishlist = $arr($data['wishlist'] ?? null);
    $cats = $arr($data['customCategories'] ?? null);
    $budgets = $arr($data['budgets'] ?? null);
    $total = count($txs) + count($debts) + count($savings) + count($recurring) + count($wishlist) + count($cats) + count($budgets);
    if ($total > 10000) {
        throw new Exception('Backup terlalu besar (maksimal 10000 baris).');
    }

    // Pemetaan S/N/T yang sama seperti Code.gs.
    $S = function ($v) { return sanitizeCell($v === null ? '' : (string) $v); };
    $N = function ($v) { return (is_numeric($v) ? (float) $v : 0.0); };
    $T = function ($v, array $allowed, string $fallback) {
        $s = (string) ($v ?? '');
        return in_array($s, $allowed, true) ? $s : $fallback;
    };
    $nonEmptyOr = function ($v, string $fallback) use ($S) {
        $s = $S($v);
        return ($s !== '') ? $s : $fallback;
    };

    $pdo->beginTransaction();
    try {
        foreach (['transaksi', 'hutang_piutang', 'tabungan', 'transaksi_rutin', 'wishlist', 'kategori_kustom', 'anggaran'] as $table) {
            $stmt = $pdo->prepare("DELETE FROM {$table} WHERE user_id = ?");
            $stmt->execute([$userId]);
        }

        $stmt = $pdo->prepare('INSERT INTO transaksi (id, user_id, tanggal, tipe, kategori, jumlah, catatan, struk, dompet, dompet_tujuan) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)');
        foreach ($txs as $t) {
            if (!is_array($t)) {
                continue;
            }
            $stmt->execute([
                $nonEmptyOr($t['id'] ?? '', newId('TX-')),
                $userId,
                $S($t['tanggal'] ?? ''),
                $T($t['tipe'] ?? '', ['Pemasukan', 'Pengeluaran', 'Transfer'], 'Pengeluaran'),
                $S($t['kategori'] ?? ''),
                $N($t['jumlah'] ?? 0),
                $S($t['catatan'] ?? ''),
                $S($t['struk'] ?? ''),
                $nonEmptyOr($t['dompet'] ?? '', 'Kas / Tunai'),
                $S($t['dompetTujuan'] ?? ''),
            ]);
        }

        $stmt = $pdo->prepare('INSERT INTO hutang_piutang (id, user_id, tanggal, jatuh_tempo, tipe, pihak_lain, jumlah, catatan, status, tanggal_lunas, dompet_pelunasan) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)');
        foreach ($debts as $d) {
            if (!is_array($d)) {
                continue;
            }
            $stmt->execute([
                $nonEmptyOr($d['id'] ?? '', newId('DEBT-')),
                $userId,
                $S($d['tanggal'] ?? ''),
                $S($d['jatuhTempo'] ?? ''),
                $T($d['tipe'] ?? '', ['Hutang', 'Piutang'], 'Hutang'),
                $S($d['pihakLain'] ?? ''),
                $N($d['jumlah'] ?? 0),
                $S($d['catatan'] ?? ''),
                $nonEmptyOr($d['status'] ?? '', 'Belum Lunas'),
                $S($d['tanggalLunas'] ?? ''),
                $S($d['dompetPelunasan'] ?? ''),
            ]);
        }

        $stmt = $pdo->prepare('INSERT INTO tabungan (id, user_id, nama_target, target_amount, current_amount, tanggal_target, catatan, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)');
        foreach ($savings as $s) {
            if (!is_array($s)) {
                continue;
            }
            $stmt->execute([
                $nonEmptyOr($s['id'] ?? '', newId('GOAL-')),
                $userId,
                $S($s['namaTarget'] ?? ''),
                $N($s['targetAmount'] ?? 0),
                $N($s['currentAmount'] ?? 0),
                $S($s['tanggalTarget'] ?? ''),
                $S($s['catatan'] ?? ''),
                $nonEmptyOr($s['status'] ?? '', 'Berjalan'),
                $S($s['createdAt'] ?? ''),
            ]);
        }

        $stmt = $pdo->prepare('INSERT INTO transaksi_rutin (id, user_id, nama_tagihan, tipe, kategori, jumlah, dompet, hari_tempo, catatan, last_processed_month) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)');
        foreach ($recurring as $r) {
            if (!is_array($r)) {
                continue;
            }
            $hari = $N($r['hariTempo'] ?? 0);
            if ($hari == 0) {
                $hari = 1;
            }
            $hari = min(31, max(1, $hari));
            $stmt->execute([
                $nonEmptyOr($r['id'] ?? '', newId('REC-')),
                $userId,
                $S($r['namaTagihan'] ?? ''),
                $T($r['tipe'] ?? '', ['Pemasukan', 'Pengeluaran'], 'Pengeluaran'),
                $S($r['kategori'] ?? ''),
                $N($r['jumlah'] ?? 0),
                $nonEmptyOr($r['dompet'] ?? '', 'Kas / Tunai'),
                (int) $hari,
                $S($r['catatan'] ?? ''),
                $S($r['lastProcessedMonth'] ?? ''),
            ]);
        }

        $stmt = $pdo->prepare('INSERT INTO wishlist (id, user_id, nama_barang, tipe, estimasi_harga, prioritas, catatan, status, tanggal_target) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)');
        foreach ($wishlist as $w) {
            if (!is_array($w)) {
                continue;
            }
            $stmt->execute([
                $nonEmptyOr($w['id'] ?? '', newId('WISH-')),
                $userId,
                $S($w['namaBarang'] ?? ''),
                $nonEmptyOr($w['tipe'] ?? '', 'Kebutuhan'),
                $N($w['estimasiHarga'] ?? 0),
                $nonEmptyOr($w['prioritas'] ?? '', 'Sedang'),
                $S($w['catatan'] ?? ''),
                $nonEmptyOr($w['status'] ?? '', 'Belum Terbeli'),
                $S($w['tanggalTarget'] ?? ''),
            ]);
        }

        $stmt = $pdo->prepare('INSERT INTO kategori_kustom (id, user_id, kategori, tipe) VALUES (?, ?, ?, ?)');
        foreach ($cats as $c) {
            if (!is_array($c)) {
                continue;
            }
            if ($S($c['kategori'] ?? '') === '') {
                continue;
            }
            $stmt->execute([
                $nonEmptyOr($c['id'] ?? '', newId('CAT-')),
                $userId,
                $S($c['kategori']),
                $T($c['tipe'] ?? '', ['Pemasukan', 'Pengeluaran'], 'Pengeluaran'),
            ]);
        }

        $stmt = $pdo->prepare('INSERT INTO anggaran (id, user_id, bulan, kategori, limit_amount) VALUES (?, ?, ?, ?, ?)');
        foreach ($budgets as $b) {
            if (!is_array($b)) {
                continue;
            }
            $bulanRaw = (string) ($b['bulan'] ?? '');
            if (preg_match('/^\d{4}-\d{2}$/', $bulanRaw) !== 1) {
                continue;
            }
            if ($S($b['kategori'] ?? '') === '' || $N($b['limit'] ?? 0) <= 0) {
                continue;
            }
            $stmt->execute([
                $nonEmptyOr($b['id'] ?? '', newId('BUD-')),
                $userId,
                $S($b['bulan']),
                $S($b['kategori']),
                $N($b['limit']),
            ]);
        }

        $pdo->commit();
    } catch (Throwable $e) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        throw $e;
    }

    return ['status' => 'success', 'message' => 'Backup berhasil dipulihkan! ' . $total . ' baris data dimuat ulang.'];
}

// ---------------------------------------------------------------------------
// Email digest: manual (tombol) & opt-in
// ---------------------------------------------------------------------------

function h_sendTestEmailDigest(PDO $pdo, array $args): array
{
    $user = requireAuth($pdo, $args[0] ?? null);
    $monthArg = isset($args[1]) ? (string) $args[1] : null;
    $isAuto = ($monthArg !== null && preg_match('/^\d{4}-\d{2}$/', $monthArg) === 1);
    $monthStr = $isAuto ? $monthArg : currentMonthId();

    $fullUser = [
        'id'    => (string) $user['id'],
        'email' => (string) $user['email'],
        'nama'  => (string) $user['nama'],
    ];
    if (!sendDigestForUser($pdo, $fullUser, $monthStr, $isAuto)) {
        throw new Exception('Gagal mengirim email ringkasan. Periksa pengaturan email hosting Anda.');
    }

    return ['status' => 'success', 'message' => 'Ringkasan berhasil dikirim ke email ' . (string) $user['email'] . '!'];
}

function h_setEmailDigestOptIn(PDO $pdo, array $args): array
{
    $user = requireAuth($pdo, $args[0] ?? null);
    $optIn = isset($args[1]) ? (string) $args[1] : '';
    $value = (strtoupper($optIn) === 'TIDAK') ? 'TIDAK' : 'YA';

    $stmt = $pdo->prepare('UPDATE users SET digest_optin = ? WHERE id = ?');
    $stmt->execute([$value, $user['id']]);

    return [
        'status'      => 'success',
        'message'     => ($value === 'YA') ? 'Ringkasan bulanan diaktifkan.' : 'Ringkasan bulanan dinonaktifkan.',
        'digestOptIn' => $value,
    ];
}
