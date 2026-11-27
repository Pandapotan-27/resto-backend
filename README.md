# Resto Backend Authentication

API menggunakan Bearer access token bertanda tangan HMAC-SHA256. Access token berlaku 15 menit dan refresh token berlaku 7 hari. Jika access token kedaluwarsa, middleware akan menerbitkan access token baru secara otomatis saat request menyertakan refresh token yang masih valid.

## Konfigurasi

Tambahkan variabel dari `.env.example` ke file `.env` dan ganti semua nilai contoh dengan kredensial rahasia yang kuat. `JWT_SECRET` minimal 32 karakter. Kredensial client dipakai untuk meminta token; jangan kirim atau commit file `.env`.

## Meminta token

`POST /api/auth/token`

```json
{
  "clientId": "resto-api-client",
  "clientSecret": "client-secret-anda"
}
```

Response berisi `accessToken`, `refreshToken`, `expiresIn` (detik), dan `tokenType`.

## Memanggil API terlindungi

Kirim header berikut untuk request API:

```text
Authorization: Bearer <accessToken>
X-Refresh-Token: <refreshToken>
```

Endpoint contoh `GET /api/auth/me` akan mengembalikan identitas dari token. Jika access token kedaluwarsa tetapi refresh token valid, request tetap diproses dan response menyertakan access token baru pada header `X-Access-Token` serta `X-Token-Refreshed: true`. Simpan token baru dari header tersebut dan gunakan untuk request selanjutnya.

Pembaruan juga dapat dilakukan secara eksplisit melalui `POST /api/auth/refresh` dengan body:

```json
{
  "refreshToken": "<refreshToken>"
}
```
