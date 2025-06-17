# Real-time-Chat-app
Real-time chat app with Flask, JWT authentication and SocketIO

# Flask Chat App with JWT & WebSocket

Bu proje, Flask kullanılarak geliştirilmiş bir chat uygulamasıdır. Kullanıcılar kayıt olabilir, giriş yapabilir, oda oluşturabilir ve yöneticinin onayıyla odalara katılıp sohbet edebilir.

## 🔧 Kullanılan Teknolojiler
- Flask
- Flask-SQLAlchemy
- Flask-JWT-Extended
- Flask-SocketIO
- SQLite

## 🚀 Başlatma Adımları

### 1. Ortamı Hazırla
```bash
python -m venv venv
source venv/bin/activate  # Windows için: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Veritabanını Oluştur
```bash
python
>>> from chat_cleaned import db
>>> db.create_all()
>>> exit()
```

### 3. Uygulamayı Başlat
```bash
python chat_cleaned.py
```

## 🛠 Özellikler
- JWT ile kimlik doğrulama
- Oda oluşturma (admin tarafından)
- Katılım isteği ve onayı
- SocketIO ile gerçek zamanlı mesajlaşma

## 📬 API Örnekleri
- `POST /register` → Kullanıcı kaydı
- `POST /login` → Giriş & JWT token alımı
- `POST /rooms` → Yeni oda oluşturma (JWT gerekli)
- `GET /rooms` → Tüm odaları listele
- `POST /join_request` → Odaya katılma isteği
- `POST /approve_request` → Admin onayı
