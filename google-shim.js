/**
 * KEUANGANKU — google.script.run SHIM (untuk hosting mandiri PHP + MySQL)
 * ============================================================================
 * Berkas ini HANYA mendefinisikan window.google.script.run bila yang asli
 * (Google Apps Script) tidak ada. Di hosting mandiri, `google` memang tidak
 * ada, sehingga shim ini yang dipakai. Di Apps Script, berkas ini tidak
 * pernah di-load, jadi perilaku asli tidak terganggu.
 *
 * CARA KERJA:
 *  - Setiap akses `google.script.run` mengembalikan runner BARU (handler
 *    terisolasi), sehingga dua panggilan yang tumpang tindih tidak saling
 *    menukar handler.
 *  - Runner mendukung rantai gaya lama:
 *      google.script.run
 *        .withSuccessHandler(fn).withFailureHandler(fn).namaFungsi(...args)
 *    dan juga pola:
 *      var runner = google.script.run.withSuccessHandler(fn)...;
 *      runner.updateTransaction(...)  ATAU  runner.addTransaction(...)
 *    (nama fungsi apa pun bisa dipanggil setelah handler dipasang).
 *  - Panggilan tanpa handler (mis. logoutUser) tetap dikirim, hasilnya
 *    diabaikan — sama seperti google.script.run asli.
 *  - Setiap pemanggilan fungsi dikirim sebagai JSON {action, args} via POST
 *    ke ../api/index.php (relatif dari public/index.html).
 *  - Respons JSON dengan status==='success' -> success handler dengan
 *    SELURUH JSON. Respons lain -> failure handler dengan Error(message).
 *    Gagal jaringan / respons bukan JSON -> failure handler dengan Error.
 *
 * TATA LETAK (penting):
 *  - Bila folder proyek diunggah apa adanya ke document root hosting
 *    (public/ dapat diakses sebagai /public/), path '../api/index.php'
 *    dari /public/index.html akan mengarah ke /api/index.php. Benar.
 *  - Bila document root diarahkan langsung ke public/, salin juga folder
 *    api/ ke dalam public/ (atau ubah API_URL di bawah menjadi
 *    'api/index.php'), agar path tetap mengarah ke file yang benar.
 */
(function () {
  'use strict';

  // Jangan menimpa google.script.run asli bila ada (mis. halaman ini
  // dibuka dari Apps Script).
  if (typeof window !== 'undefined' && window.google && window.google.script && window.google.script.run) {
    return;
  }

  var API_URL = '../api/index.php';

  function postAction(action, args, onSuccess, onFailure) {
    fetch(API_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: action, args: args })
    })
      .then(function (resp) {
        return resp.text().then(function (text) {
          var data;
          try {
            data = JSON.parse(text);
          } catch (e) {
            throw new Error('Respons server tidak valid (HTTP ' + resp.status + ').');
          }
          if (data && data.status === 'success') {
            if (onSuccess) onSuccess(data);
          } else {
            var msg = (data && data.message) ? data.message : ('Server mengembalikan status ' + resp.status + '.');
            if (onFailure) onFailure(new Error(msg));
          }
        });
      })
      .catch(function (err) {
        if (onFailure) onFailure(err instanceof Error ? err : new Error(String(err)));
      });
  }

  function createRunner() {
    var state = { onSuccess: null, onFailure: null };
    var runner = new Proxy({}, {
      get: function (target, prop) {
        if (typeof prop === 'symbol') return undefined;
        if (prop === 'withSuccessHandler') {
          return function (fn) { state.onSuccess = fn; return runner; };
        }
        if (prop === 'withFailureHandler') {
          return function (fn) { state.onFailure = fn; return runner; };
        }
        // Nama fungsi server apa pun: kirim sebagai {action, args}.
        // Handler dibaca SAAT pemanggilan (bukan saat respons), sehingga
        // panggilan yang tumpang tindih tidak saling menukar handler.
        return function () {
          var args = Array.prototype.slice.call(arguments);
          var onSuccess = state.onSuccess;
          var onFailure = state.onFailure;
          postAction(prop, args, onSuccess, onFailure);
        };
      }
    });
    return runner;
  }

  if (typeof window !== 'undefined') {
    window.google = window.google || {};
    window.google.script = window.google.script || {};
    // Getter: setiap akses google.script.run menghasilkan runner baru.
    Object.defineProperty(window.google.script, 'run', {
      configurable: true,
      enumerable: true,
      get: function () { return createRunner(); }
    });
  }
})();
