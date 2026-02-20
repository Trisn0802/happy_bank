from flask import Flask, request, jsonify, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import datetime

app = Flask(__name__)

# KONFIGURASI
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///bank.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'supersecretkey'  # Ganti dengan secret key yang aman
app.config['SECRET_KEY'] = 'anothersecretkey'  # Untuk flash messages
app.config['JWT_TOKEN_LOCATION'] = ['cookies']  # Simpan token di cookie
app.config['JWT_COOKIE_SECURE'] = False  # Hanya aktifkan di production dengan HTTPS
app.config['JWT_COOKIE_CSRF_PROTECT'] = False  # Nonaktifkan CSRF protection untuk sederhanakan

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Filter untuk memformat angka dengan titik sebagai pemisah ribuan
@app.template_filter('format_currency')
def format_currency(value):
    return f"Rp {value:,.0f}".replace(",", ".")

# MODEL USER
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    saldo = db.Column(db.Float, default=0.0)

# MODEL TRANSACTION
class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Integer, nullable=False)  # Ubah tipe data menjadi Integer
    transaction_type = db.Column(db.String(50), nullable=False)
    sender_name = db.Column(db.String(100), nullable=False)  # Tambahkan kolom sender_name
    recipient_name = db.Column(db.String(100), nullable=True)  # Tambahkan kolom recipient_name
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

# Inisialisasi database
with app.app_context():
    db.create_all()

# ROUTES
@app.route('/')
def home():
    return render_template('index.html')

# Halaman Registrasi
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(email=email, password=hashed_password)
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Registrasi berhasil! Silakan login.', 'success')
            return redirect(url_for('login'))
        except:
            db.session.rollback()
            flash('Email sudah terdaftar!', 'danger')
    return render_template('register.html')

# Halaman Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        # Validasi input tidak boleh kosong
        if not email or not password:
            flash('Email dan password tidak boleh kosong!', 'danger')
            return redirect(url_for('login'))

        # Cek apakah user ada
        user = User.query.filter_by(email=email).first()
        if not user:
            flash('Email belum terdaftar silahkan buat akun terlebih dahulu!', 'danger')
            return redirect(url_for('login'))

        # Cek password
        if not bcrypt.check_password_hash(user.password, password):
            flash('Password salah!', 'danger')
            return redirect(url_for('login'))

        # Jika semua valid, buat token dan redirect ke dashboard
        access_token = create_access_token(identity=str(user.id), expires_delta=datetime.timedelta(days=1))
        response = redirect(url_for('dashboard'))
        response.set_cookie('access_token_cookie', access_token, httponly=True)
        return response

    return render_template('login.html')

# Halaman Dashboard
@app.route('/dashboard')
@jwt_required()
def dashboard():
    user_id = get_jwt_identity()  # user_id sudah berupa string
    user = User.query.get(int(user_id))  # Konversi kembali ke integer untuk query
    transactions = Transaction.query.filter_by(user_id=int(user_id)).order_by(Transaction.created_at.desc()).all()
    return render_template('dashboard.html', user=user, transactions=transactions)

# Top-Up Saldo
@app.route('/topup', methods=['POST'])
@jwt_required()
def topup():
    data = request.get_json()
    if not data or 'amount' not in data:
        return jsonify({"pesan": "Data tidak lengkap"}), 400

    try:
        amount = int(data['amount'])  # Konversi amount ke integer
    except ValueError:
        return jsonify({"pesan": "Nilai amount tidak valid"}), 400

    user_id = get_jwt_identity()
    user = User.query.get(int(user_id))

    if amount <= 0:
        return jsonify({"pesan": "Jumlah top-up harus lebih dari 0"}), 400

    # Tambahkan saldo
    user.saldo += amount

    # Simpan transaksi top-up
    transaction = Transaction(user_id=user.id, amount=amount, transaction_type="TOPUP", sender_name="Happy Bank", recipient_name=None)
    db.session.add(transaction)
    db.session.commit()

    return jsonify({"pesan": "Top-up berhasil", "saldo_baru": user.saldo}), 200

# API untuk Transfer
@app.route('/transfer', methods=['POST'])
@jwt_required()
def transfer():
    data = request.get_json()
    if not data or 'recipient_email' not in data or 'amount' not in data:
        return jsonify({"pesan": "Data tidak lengkap"}), 400

    try:
        amount = int(data['amount'])  # Konversi amount ke integer
        if amount <= 0:
            return jsonify({"pesan": "Jumlah transfer harus lebih dari 0"}), 400
    except ValueError:
        return jsonify({"pesan": "Nilai amount tidak valid"}), 400

    sender_id = get_jwt_identity()  # sender_id berupa string
    recipient = User.query.filter_by(email=data['recipient_email']).first()
    
    if not recipient:
        return jsonify({"pesan": "Penerima tidak ditemukan"}), 404

    sender = User.query.get(int(sender_id))  # Konversi kembali ke integer untuk query
    if sender.saldo < amount:
        return jsonify({"pesan": "Dana tidak cukup"}), 400
    
    # Proses Transfer
    sender.saldo -= amount
    recipient.saldo += amount

    # Simpan Transaksi
    transaction_sender = Transaction(user_id=int(sender_id), amount=-amount, transaction_type="TRANSFER", sender_name=sender.email, recipient_name=recipient.email)
    transaction_recipient = Transaction(user_id=recipient.id, amount=amount, transaction_type="TRANSFER", sender_name=sender.email, recipient_name=recipient.email)

    try:
        db.session.add(transaction_sender)
        db.session.add(transaction_recipient)
        db.session.commit()
    except:
        db.session.rollback()
        return jsonify({"pesan": "Terjadi kesalahan saat menyimpan transaksi"}), 500
    
    return jsonify({"pesan": "Transfer berhasil"}), 200

# Logout
@app.route('/logout')
def logout():
    response = redirect(url_for('home'))
    response.delete_cookie('access_token_cookie')  # Hapus cookie
    return response

# Menjalankan Aplikasi
if __name__ == '__main__':
    app.run(debug=True)