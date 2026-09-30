# Top up Clouds — Integrated Starter v3

Versi ini menyambungkan frontend dengan backend toko dan Midtrans Snap.

## Sudah terintegrasi
- Katalog produk dari SQLite, bukan hard-code frontend.
- Durasi 1/3/7/30 hanya muncul jika produk tersebut dimasukkan di database.
- Register/login email + password dengan bcrypt.
- Session token disimpan di database dan berlaku 30 hari.
- Checkout membuat order di server.
- Server membuat Snap transaction token.
- Frontend membuka Snap checkout.
- Kode Redeem di-reserve 15 menit untuk mencegah satu kode dijual ke dua order.
- Midtrans webhook memverifikasi `signature_key` SHA-512.
- Kode hanya berubah menjadi `sold` setelah status pembayaran sukses.
- Order yang expire/cancel/deny/failure melepas reservation kode.
- Riwayat order + Redeem Code tampil di akun.
- Admin panel `/admin` untuk produk, harga, stok kode, statistik, dan order.

## Jalankan lokal
1. Node.js 20+.
2. `npm install`
3. Salin `.env.example` menjadi `.env`.
4. Isi Midtrans Sandbox Server Key + Client Key.
5. Buat ADMIN_KEY acak yang panjang.
6. `npm start`
7. Buka `http://localhost:3000`.
8. Admin: `http://localhost:3000/admin`.

## Midtrans
Mulai dari Sandbox. Snap JS menggunakan sandbox ketika `MIDTRANS_IS_PRODUCTION=false`; production memakai endpoint production setelah merchant siap.

Payment Notification URL pada Midtrans Dashboard:
`https://DOMAIN-KAMU/api/midtrans/notification`

Webhook wajib memakai HTTPS di server publik. Jangan pernah menaruh Server Key di frontend atau mengirim Redeem Code hanya berdasarkan callback browser. Server harus memverifikasi notification/signature dan status pembayaran.

## Sebelum production
- Gunakan domain + HTTPS.
- Gunakan Midtrans Production Server Key/Client Key melalui environment variables.
- Isi katalog dengan harga supplier yang benar.
- Masukkan Redeem Code yang memang diperoleh secara sah dari supplier/provider.
- Pastikan hak reseller/ketentuan provider mengizinkan penjualan kembali.
- Tambahkan Terms, Privacy, Refund/Cancellation, Contact/Support.
- Tambahkan rate limiting, audit log, backup database, monitoring, dan secret management pada deployment production.
- Jangan bagikan ADMIN_KEY atau MIDTRANS_SERVER_KEY.

## Batasan versi ini
Google/Apple login belum dibuat; versi ini menggunakan email/password. Supplier API otomatis juga belum dibuat karena endpoint/SKU supplier belum diberikan. Itu perlu integrasi terpisah berdasarkan API resmi supplier.
