## Docker Compose

Buat file `docker-compose.yml` seperti berikut:

```yaml
services:
  happy_bank:
    build: .
    container_name: happy_bank
    ports:
      - "8000:8000"
    volumes:
      - ./instance:/app/instance
    restart: unless-stopped
```

Kalau mau lebih lengkap, tambahkan cara jalaninnya:


Jalankan:

```bash
docker compose up -d --build
```

Catatan kecil: pastikan nama file image kamu `Dockerfile` (huruf **D** besar), bukan `dockerfile`.