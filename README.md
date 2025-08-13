# OpenVPN Agent Deployment Script

Skrip ini dirancang untuk mengotomatiskan seluruh proses deployment Agen OpenVPN pada server baru berbasis Debian/Ubuntu. Agen ini berfungsi sebagai jembatan antara server OpenVPN Anda dan **OpenVPN Management Dashboard**, memungkinkan monitoring dan pengelolaan pengguna dari satu antarmuka.

---

## 📜 Deskripsi

Tujuan utama skrip ini adalah untuk menghilangkan langkah-langkah manual yang repetitif dan rawan kesalahan saat menyiapkan server OpenVPN baru untuk diintegrasikan dengan dashboard. Skrip ini menangani semua hal mulai dari instalasi dependensi, pembuatan lingkungan virtual yang terisolasi, hingga konfigurasi layanan agar berjalan secara persisten.

---

## ✨ Fitur Utama

- **Otomatisasi Penuh**: Menjalankan seluruh proses setup dengan satu perintah.
- **Instalasi Dependensi**: Menginstal semua paket yang diperlukan seperti `python3`, `pip`, `venv`, `nodejs`, dan `pm2`.
- **Lingkungan Terisolasi**: Membuat Python Virtual Environment (venv) untuk mencegah konflik dependensi.
- **Konfigurasi Interaktif**: Mengumpulkan data penting (API Key, Server ID, URL Dashboard) langsung dari pengguna.
- **Deployment Dinamis**: Membuat skrip-skrip yang diperlukan secara otomatis di server:
  - `main.py`: Agen FastAPI inti.
  - `openvpn-client-manager.sh`: Skrip utilitas klien VPN.
  - `.env`: File konfigurasi berisi kredensial dan path.
  - `ecosystem.config.js`: Konfigurasi PM2.
- **Manajemen Proses dengan PM2**: Agen Python berjalan secara persisten dan restart otomatis.
- **Deteksi Otomatis**: Memeriksa path `index.txt` Easy-RSA dan status layanan OpenVPN.

---

## 🛠️ Prasyarat

- Server Debian/Ubuntu baru.
- Akses root atau hak sudo.
- Skrip utama instalasi OpenVPN (`ubuntu-22.04-lts-vpn-server.sh`) sudah ada di `/root/`.
- Untuk penginstalan OpenVPN nya bisa dari tutorial berikut:
https://www.cyberciti.biz/faq/ubuntu-22-04-lts-set-up-openvpn-server-in-5-minutes/

---

## 🚀 Cara Penggunaan

### 1. Salin Skrip ke Server
```bash
wget https://raw.githubusercontent.com/SoramiKS/ovpn-agent-bash/refs/heads/main/deploymentovpn.sh
```

### 2. Berikan Izin Eksekusi
```bash
chmod +x deploymentovpn.sh
```

### 3. Jalankan dengan Sudo
```bash
sudo ./deploymentovpn.sh
```

### 4. Ikuti Proses Konfigurasi
Masukkan:
- **Nama Aplikasi untuk PM2** (contoh: `vpn-agent-jakarta`)
- **AGENT_API_KEY** (harus sama dengan di dashboard)
- **Alamat Dashboard** (IP/domain)
- **SERVER_ID** (unik per server)
- **Direktori OVPN** (lokasi file `.ovpn`)

---

## ⚙️ Cara Kerja Skrip

1. **Pemeriksaan Awal**: Memastikan dijalankan dengan sudo.
2. **Pengumpulan Input**: Mengambil konfigurasi dari pengguna.
3. **Pembuatan Direktori**: `./openvpn-agent`
4. **Validasi OpenVPN**: Menjalankan skrip instalasi jika OpenVPN belum aktif.
5. **Instalasi Dependensi**: `openvpn`, `python3-venv`, `nodejs`, `pm2`, dll.
6. **Setup Virtual Environment**: Menginstal pustaka Python seperti `fastapi`, `uvicorn`, `requests`.
7. **Pembuatan File**:
   - `.env`
   - `main.py`
   - `openvpn-client-manager.sh`
   - `ecosystem.config.js`
8. **Konfigurasi PM2**: Menjalankan agen dan set agar autostart.

---

## ✅ Verifikasi Pasca-Instalasi

**Cek Status PM2**
```bash
pm2 status
```

**Lihat Log Output**
```bash
tail -f ./openvpn-agent/logs/agent-out.log
```

**Lihat Log Error**
```bash
tail -f ./openvpn-agent/logs/agent-err.log
```

---

## 🔗 Integrasi dengan OpenVPN Management Dashboard

- Pastikan `AGENT_API_KEY` dan `SERVER_ID` sesuai dengan yang terdaftar di dashboard.
- Dashboard akan otomatis mendeteksi agen yang terhubung dan menampilkan statusnya.
- Semua profil VPN yang dikelola agen akan sinkron dengan dashboard.

---

## 📜 Lisensi
Proyek ini dilisensikan di bawah **MIT License**.
