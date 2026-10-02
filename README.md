# Top up Clouds — deploy-ready

Struktur wajib:
- server.js
- package.json
- public/index.html
- public/admin.html

Railway:
1. Connect Railway ke repository yang berisi FILE DI ATAS pada root repository.
2. Start command: `npm start`.
3. Jangan membuat folder `src`/`app` untuk file ini kecuali server.js dan public dipindahkan sesuai path.
4. Variables yang dibutuhkan untuk pembayaran/admin:
   - ADMIN_KEY
   - MIDTRANS_SERVER_KEY
   - MIDTRANS_CLIENT_KEY
   - MIDTRANS_IS_PRODUCTION=false untuk Sandbox
   - DB_PATH=/data/data.db hanya jika Railway Volume dipasang di /data; jika tidak, biarkan kosong.
5. Health check: `/health` atau `/api/health`.
6. Midtrans notification URL: `https://DOMAIN-KAMU/api/midtrans/notification`.

PENTING: ADMIN_KEY dan MIDTRANS_SERVER_KEY jangan ditaruh di HTML atau GitHub.
