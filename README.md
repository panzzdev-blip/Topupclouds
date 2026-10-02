# Top up Clouds — Cloud Store

Website Top up Clouds dengan katalog dari SQLite, akun email/password, admin panel, stok Redeem Code, dan Midtrans Snap.

## Upgrade versi ini
- Premium sky/cloud UI dengan dark mode yang lebih rapi.
- **Lite/Performance Mode** untuk mengurangi animasi, blur, dan efek berat di HP.
- Foto profil bisa di-crop menjadi lingkaran dengan **zoom + arah horizontal + arah vertikal** sebelum disimpan.
- Pilihan bahasa: Indonesia, English, Melayu, 中文, Español, العربية.
- Arabic otomatis menggunakan RTL.
- Admin key memakai environment variable `ADMIN_KEY`, bukan hard-code.
- Admin memiliki endpoint pengecekan `/api/admin/check`.
- Perbandingan ADMIN_KEY memakai `crypto.timingSafeEqual`.
- Database path bisa diatur dengan `DB_PATH`, sehingga bisa diarahkan ke persistent volume.
- Express 5 SPA fallback kompatibel.
- Checkout tetap membuat transaksi Midtrans di server.
- Redeem Code di-reserve 15 menit dan baru dianggap terjual setelah pembayaran terverifikasi.

## Railway Variables
Tambahkan:

`ADMIN_KEY`

Isi value dengan secret panjang dan acak milik kamu. **Jangan kirim value secret ke chat atau masukkan ke GitHub.** Setelah mengubah Variables, tunggu Railway melakukan redeploy.

Untuk data yang harus tetap ada setelah redeploy, gunakan Railway Volume dan set `DB_PATH` ke lokasi file database pada volume tersebut.

## Midtrans
Mulai dari Sandbox:

`MIDTRANS_IS_PRODUCTION=false`

Notification URL:

`https://DOMAIN-KAMU/api/midtrans/notification`

Server Key hanya berada di environment variable server. Jangan pernah menaruh Server Key di frontend.

## Jalankan

```bash
npm install
npm start
```

Website: `/`

Admin: `/admin`

Health: `/health`

## Production checklist
- Domain + HTTPS.
- Midtrans Production keys setelah pengujian Sandbox selesai.
- Backup database.
- Rate limiting dan monitoring.
- Terms, Privacy, Refund/Cancellation, Contact/Support.
- Produk dan Redeem Code harus diperoleh secara sah dan sesuai ketentuan reseller/provider.
- Jangan mengklaim sebagai website resmi provider tanpa otorisasi tertulis.
