<?php
/**
 * KEUANGANKU — Router API (pengganti google.script.run).
 *
 * Frontend (public/index.html) memanggil endpoint ini lewat google-shim.js
 * dengan JSON: {"action": "namaFungsi", "args": [arg1, arg2, ...]}.
 * Argumen pertama tiap aksi adalah token, persis seperti pemanggilan
 * google.script.run lama — kecuali loginUser/registerUser yang argumen
 * pertamanya adalah objek data.
 *
 * Respons selalu JSON:
 *   sukses -> {"status":"success", "message":..., ...data}
 *   gagal  -> {"status":"error", "message":"..."}  (HTTP 200, agar shim
 *             dapat menyalurkannya ke failure handler seperti dulu)
 */

define('KEUANGANKU_APP', true);

require __DIR__ . '/config.php';
require __DIR__ . '/db.php';
require __DIR__ . '/helpers.php';
require __DIR__ . '/digest.php';
require __DIR__ . '/handlers.php';

header('Content-Type: application/json; charset=UTF-8');

// Cek kesehatan sederhana (GET): berguna untuk memastikan API hidup
// tanpa harus login. Bukan bagian dari API aplikasi lama.
if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'GET') {
    echo json_encode(['status' => 'ok', 'app' => 'KEUANGANKU', 'version' => 1]);
    exit;
}

// Peta aksi -> handler. Nama HARUS persis sama dengan pemanggilan frontend.
$routes = [
    'loginUser'                => 'h_loginUser',
    'registerUser'             => 'h_registerUser',
    'logoutUser'               => 'h_logoutUser',
    'getUserProfile'           => 'h_getUserProfile',
    'getAllUserData'           => 'h_getAllUserData',
    'addTransaction'           => 'h_addTransaction',
    'updateTransaction'        => 'h_updateTransaction',
    'deleteTransaction'        => 'h_deleteTransaction',
    'addDebt'                  => 'h_addDebt',
    'deleteDebt'               => 'h_deleteDebt',
    'payoffDebt'               => 'h_payoffDebt',
    'addSavingsGoal'           => 'h_addSavingsGoal',
    'deleteSavingsGoal'        => 'h_deleteSavingsGoal',
    'depositSavingsGoal'       => 'h_depositSavingsGoal',
    'addRecurringTransaction'  => 'h_addRecurringTransaction',
    'deleteRecurringTransaction' => 'h_deleteRecurringTransaction',
    'payRecurringTransaction'  => 'h_payRecurringTransaction',
    'addWishlistItem'          => 'h_addWishlistItem',
    'buyWishlistItem'          => 'h_buyWishlistItem',
    'deleteWishlistItem'       => 'h_deleteWishlistItem',
    'setBudget'                => 'h_setBudget',
    'deleteBudget'             => 'h_deleteBudget',
    'addCustomCategory'        => 'h_addCustomCategory',
    'deleteCustomCategory'     => 'h_deleteCustomCategory',
    'updateDebt'               => 'h_updateDebt',
    'updateSavingsGoal'        => 'h_updateSavingsGoal',
    'updateRecurringTransaction' => 'h_updateRecurringTransaction',
    'updateWishlistItem'       => 'h_updateWishlistItem',
    'renameCustomCategory'     => 'h_renameCustomCategory',
    'renameWallet'             => 'h_renameWallet',
    'updateProfile'            => 'h_updateProfile',
    'restoreUserData'          => 'h_restoreUserData',
    'sendTestEmailDigest'      => 'h_sendTestEmailDigest',
    'setEmailDigestOptIn'      => 'h_setEmailDigestOptIn',
];

try {
    $raw = file_get_contents('php://input');
    $req = json_decode($raw === false ? '' : $raw, true);
    if (!is_array($req) || !isset($req['action']) || !is_string($req['action'])) {
        throw new Exception('Permintaan tidak valid.');
    }
    $action = $req['action'];
    $args = isset($req['args']) && is_array($req['args']) ? $req['args'] : [];
    if (!isset($routes[$action])) {
        throw new Exception('Aksi tidak dikenal: ' . $action);
    }
    $handler = $routes[$action];
    $result = $handler(pdo(), $args);
    if (!is_array($result)) {
        throw new Exception('Respons handler tidak valid.');
    }
    echo json_encode($result);
} catch (Throwable $e) {
    // Pesan error untuk pengguna tetap Bahasa Indonesia (pesan dari handler
    // sudah Indonesia; pesan sistem fallback juga dibuat Indonesia).
    $msg = $e->getMessage();
    if ($msg === '') {
        $msg = 'Terjadi kesalahan pada server.';
    }
    echo json_encode(['status' => 'error', 'message' => $msg]);
}
