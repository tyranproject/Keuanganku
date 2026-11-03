-- =============================================================================
-- KEUANGANKU — Skema database MySQL 8 / MariaDB (porting dari Google Sheets)
-- =============================================================================
-- Cara pakai: impor berkas ini lewat phpMyAdmin (tab Impor) setelah database
-- dibuat DI CPANEL dan dipilih di panel kiri phpMyAdmin. Berkas ini SENGAJA
-- tidak mengandung CREATE DATABASE / USE: di hosting cPanel, nama database
-- wajib berawalan username akun (mis. taxagi70_keuanganku), sehingga perintah
-- CREATE DATABASE `keuanganku` (tanpa awalan) ditolak dengan error #1044
-- "Access denied". Dengan mengimpor ke database yang sudah dipilih, tabel
-- dibuat di database yang benar apa pun nama lengkapnya.
-- Semua tabel memakai utf8mb4 agar emoji & karakter Indonesia aman.
--
-- Catatan pemetaan dari sheet lama:
--   DATA_USER          -> users
--   KEUANGANKU         -> transaksi
--   HUTANG_PIUTANG     -> hutang_piutang
--   SAVINGS_GOALS      -> tabungan
--   TRANSAKSI_RUTIN    -> transaksi_rutin
--   WISHLIST_NEEDS     -> wishlist
--   ANGGARAN           -> anggaran
--   KATEGORI_KUSTOM    -> kategori_kustom
--
-- Dua keputusan yang disengaja:
-- 1. Kolom tanggal disimpan sebagai VARCHAR (bukan DATE). Alasannya:
--    data lama boleh berisi string kosong / format tidak baku, dan frontend
--    membandingkan tanggal sebagai string 'yyyy-MM-dd' (mis. startsWith
--    untuk digest bulanan). VARCHAR membuat impor backup JSON lama tidak
--    pernah gagal karena mode STRICT MySQL.
-- 2. Setiap tabel data punya kolom `seq` AUTO_INCREMENT yang diurutkan
--    menaik saat dibaca. Ini menggantikan "urutan baris sheet" — frontend
--    mengandalkan urutan sisipan sebagai penyeimbang urutan saat tanggal
--    sama (lihat logika sort transaksi di Index.html).
-- =============================================================================

-- -----------------------------------------------------------------------------
-- users: satu baris per akun. `password_hash` berisi hash bcrypt untuk akun
-- baru / akun yang sudah di-upgrade, atau hash SHA-256 heksadesimal (64
-- karakter) untuk akun lama hasil impor DATA_USER. `salt` hanya diisi untuk
-- akun lama (verifikasi SHA-256(password|salt)); setelah login pertama di
-- aplikasi baru, akun di-upgrade ke bcrypt dan `salt` dikosongkan.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `users` (
  `id`            VARCHAR(64)  NOT NULL,
  `email`         VARCHAR(255) NOT NULL,
  `password_hash` VARCHAR(255) NOT NULL,
  `nama`          VARCHAR(255) NOT NULL,
  `salt`          VARCHAR(128) NULL DEFAULT NULL,
  `token`         VARCHAR(128) NULL DEFAULT NULL,
  `token_expiry`  DATETIME     NULL DEFAULT NULL,
  `digest_optin`  VARCHAR(8)   NOT NULL DEFAULT 'YA',
  `created_at`    DATETIME     NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_users_email` (`email`),
  KEY `idx_users_token` (`token`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- -----------------------------------------------------------------------------
-- transaksi (sheet KEUANGANKU)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `transaksi` (
  `id`            VARCHAR(64)   NOT NULL,
  `seq`           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id`       VARCHAR(64)   NOT NULL,
  `tanggal`       VARCHAR(16)   NOT NULL DEFAULT '',
  `tipe`          VARCHAR(32)   NOT NULL DEFAULT 'Pengeluaran',
  `kategori`      VARCHAR(128)  NOT NULL DEFAULT '',
  `jumlah`        DECIMAL(19,2) NOT NULL DEFAULT 0,
  `catatan`       TEXT          NULL,
  `struk`         VARCHAR(512)  NOT NULL DEFAULT '',
  `dompet`        VARCHAR(128)  NOT NULL DEFAULT 'Kas / Tunai',
  `dompet_tujuan` VARCHAR(128)  NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_transaksi_seq` (`seq`),
  KEY `idx_transaksi_user` (`user_id`),
  KEY `idx_transaksi_user_tanggal` (`user_id`, `tanggal`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- -----------------------------------------------------------------------------
-- hutang_piutang (sheet HUTANG_PIUTANG)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `hutang_piutang` (
  `id`               VARCHAR(64)   NOT NULL,
  `seq`              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id`          VARCHAR(64)   NOT NULL,
  `tanggal`          VARCHAR(16)   NOT NULL DEFAULT '',
  `jatuh_tempo`      VARCHAR(16)   NOT NULL DEFAULT '',
  `tipe`             VARCHAR(32)   NOT NULL DEFAULT 'Hutang',
  `pihak_lain`       VARCHAR(255)  NOT NULL DEFAULT '',
  `jumlah`           DECIMAL(19,2) NOT NULL DEFAULT 0,
  `catatan`          TEXT          NULL,
  `status`           VARCHAR(32)   NOT NULL DEFAULT 'Belum Lunas',
  `tanggal_lunas`    VARCHAR(16)   NOT NULL DEFAULT '',
  `dompet_pelunasan` VARCHAR(128)  NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_hutang_seq` (`seq`),
  KEY `idx_hutang_user` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- -----------------------------------------------------------------------------
-- tabungan (sheet SAVINGS_GOALS)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `tabungan` (
  `id`             VARCHAR(64)   NOT NULL,
  `seq`            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id`        VARCHAR(64)   NOT NULL,
  `nama_target`    VARCHAR(255)  NOT NULL DEFAULT '',
  `target_amount`  DECIMAL(19,2) NOT NULL DEFAULT 0,
  `current_amount` DECIMAL(19,2) NOT NULL DEFAULT 0,
  `tanggal_target` VARCHAR(16)   NOT NULL DEFAULT '',
  `catatan`        TEXT          NULL,
  `status`         VARCHAR(32)   NOT NULL DEFAULT 'Berjalan',
  `created_at`     VARCHAR(16)   NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_tabungan_seq` (`seq`),
  KEY `idx_tabungan_user` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- -----------------------------------------------------------------------------
-- transaksi_rutin (sheet TRANSAKSI_RUTIN)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `transaksi_rutin` (
  `id`                   VARCHAR(64)   NOT NULL,
  `seq`                  BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id`              VARCHAR(64)   NOT NULL,
  `nama_tagihan`         VARCHAR(255)  NOT NULL DEFAULT '',
  `tipe`                 VARCHAR(32)   NOT NULL DEFAULT 'Pengeluaran',
  `kategori`             VARCHAR(128)  NOT NULL DEFAULT 'Tagihan & Utilitas',
  `jumlah`               DECIMAL(19,2) NOT NULL DEFAULT 0,
  `dompet`               VARCHAR(128)  NOT NULL DEFAULT 'Kas / Tunai',
  `hari_tempo`           INT           NOT NULL DEFAULT 1,
  `catatan`              TEXT          NULL,
  `last_processed_month` VARCHAR(7)    NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_rutin_seq` (`seq`),
  KEY `idx_rutin_user` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- -----------------------------------------------------------------------------
-- wishlist (sheet WISHLIST_NEEDS)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `wishlist` (
  `id`             VARCHAR(64)   NOT NULL,
  `seq`            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id`        VARCHAR(64)   NOT NULL,
  `nama_barang`    VARCHAR(255)  NOT NULL DEFAULT '',
  `tipe`           VARCHAR(64)   NOT NULL DEFAULT 'Kebutuhan',
  `estimasi_harga` DECIMAL(19,2) NOT NULL DEFAULT 0,
  `prioritas`      VARCHAR(32)   NOT NULL DEFAULT 'Sedang',
  `catatan`        TEXT          NULL,
  `status`         VARCHAR(32)   NOT NULL DEFAULT 'Belum Terbeli',
  `tanggal_target` VARCHAR(16)   NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_wishlist_seq` (`seq`),
  KEY `idx_wishlist_user` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- -----------------------------------------------------------------------------
-- anggaran (sheet ANGGARAN). `limit` adalah kata kunci MySQL, jadi kolomnya
-- bernama `limit_amount`; API tetap mengeluarkannya sebagai field `limit`
-- agar frontend tidak berubah. UNIQUE(user_id, bulan, kategori) menguatkan
-- aturan upsert dari Code.gs di level database.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `anggaran` (
  `id`           VARCHAR(64)   NOT NULL,
  `seq`          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id`      VARCHAR(64)   NOT NULL,
  `bulan`        VARCHAR(7)    NOT NULL DEFAULT '',
  `kategori`     VARCHAR(128)  NOT NULL DEFAULT '',
  `limit_amount` DECIMAL(19,2) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_anggaran_seq` (`seq`),
  UNIQUE KEY `uq_anggaran_user_bulan_kategori` (`user_id`, `bulan`, `kategori`),
  KEY `idx_anggaran_user` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- -----------------------------------------------------------------------------
-- kategori_kustom (sheet KATEGORI_KUSTOM)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `kategori_kustom` (
  `id`       VARCHAR(64)  NOT NULL,
  `seq`      BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id`  VARCHAR(64)  NOT NULL,
  `kategori` VARCHAR(128) NOT NULL DEFAULT '',
  `tipe`     VARCHAR(32)  NOT NULL DEFAULT 'Pengeluaran',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_kategori_seq` (`seq`),
  KEY `idx_kategori_user` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
