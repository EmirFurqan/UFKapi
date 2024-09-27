from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
from pymongo import MongoClient
from pymongo.server_api import ServerApi
import bcrypt
import jwt
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from bson import ObjectId
import os
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from datetime import datetime as dt
import datetime
from PIL import Image
import time

# .env dosyasını yükle
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['UPLOAD_FOLDER'] = 'uploads'

# MongoDB bağlantısı
uri = os.getenv('MONGO_URI')
client = MongoClient(uri, server_api=ServerApi('1'))


# CORS yapılandırması
CORS(app, resources={r"/*": {"origins": "*"}})

try:
    client.admin.command('ping')
    print("MongoDB bağlantısı başarılı!")
except Exception as e:
    print("MongoDB bağlantısı başarısız:", str(e))

db = client["test"]
users_collection = db["users"]
files_collection = db["files"]
basvuru_collection = db["basvurular"]



def send_verification_email(to_email, token, name):
    sender_email = os.getenv('SENDER_EMAIL')
    sender_password = os.getenv('SENDER_PASSWORD')
    subject = 'Email Verification'
    body = f'Sevgili {name}, sitemize kayıt olmuşsun. Yapman gereken son bir işlem kaldı. Şu linke tıklayarak hesabını doğrulayabilirsin: http://localhost:3000/verify-email?token={token}'

    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = to_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        with smtplib.SMTP('smtp.gmail.com', 587) as server:  # Port 587 TLS için
            server.starttls()
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, to_email, msg.as_string())
    except Exception as e:
        print(f'Error: {e}')

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    
    if not all([email, password]):
        return jsonify({"message": "Missing information", "status": 400}), 400
    
    # Check if email already exists
    existing_user = users_collection.find_one({'email': email})
    if existing_user:
        return jsonify({"message": "Email already exists", "status": 409}), 409
    
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    token = jwt.encode({'email': email, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)}, app.config['SECRET_KEY'], algorithm='HS256')

    users_collection.insert_one({
        'name': data.get('name'),
        'surname': data.get('surname'),
        'email': email,
        'password': hashed_password,
        'email_verified': False,
        'role': 'user',
        'verification_token': token
    })
    
    # Assume send_verification_email function is defined elsewhere
    send_verification_email(email, token, data.get('name'))
    
    return jsonify({"message": "User registered successfully, please check your email to verify your account", "status": 201}), 201

@app.route('/verify-email', methods=['GET'])
def verify_email():
    token = request.args.get('token')
    if not token:
        return jsonify({"message": "Token is missing", "status": 400})

    try:
        decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        email = decoded['email']
        result = users_collection.update_one({'email': email, 'verification_token': token}, {'$set': {'email_verified': True, 'verification_token': None}})
        if result.matched_count:
            return jsonify({"message": "Email verified successfully", "status": 200})
        else:
            return jsonify({"message": "Invalid or expired token", "status": 400})
    except jwt.ExpiredSignatureError:
        return jsonify({"message": "Token has expired", "status": 400})
    except jwt.InvalidTokenError:
        return jsonify({"message": "Invalid token", "status": 400})

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')  # Use email instead of username
    password = data.get('password')

    # Find the user by email
    user = users_collection.find_one({'email': email})

    if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
        if not user.get('email_verified'):
            return jsonify({"message": "Email not verified"}), 403
        
        token = jwt.encode({
            'email': email,  # Include email in the token payload
            'role': user['role'],
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        }, app.config['SECRET_KEY'], algorithm='HS256')

        return jsonify({"message": "Login successful", "token": token, "role": user['role']}), 200
    else:
        return jsonify({"message": "Invalid credentials"}), 401

@app.route('/profile', methods=['GET'])
def profile():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({"message": "Token is missing"}), 401

    try:
        token = token.split(" ")[1]  # Extract token from 'Bearer <token>'
        decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        email = decoded['email']
        user = users_collection.find_one({'email': email}, {'_id': 0, 'password': 0})
        if user:
            # Convert ObjectId to string
            user = {k: (str(v) if isinstance(v, ObjectId) else v) for k, v in user.items()}
            return jsonify(user), 200
        else:
            return jsonify({"message": "User not found"}), 404
    except jwt.ExpiredSignatureError:
        return jsonify({"message": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"message": "Invalid token"}), 401
    
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    
@app.route('/upload-profile-picture', methods=['POST'])
def upload_profile_picture():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({"message": "Token is missing"}), 401

    try:
        token = token.split(" ")[1]  # Extract token from 'Bearer <token>'
        decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        email = decoded['email']

        # Get the file from the request
        if 'file' not in request.files:
            return jsonify({"message": "No file part"}), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({"message": "No selected file"}), 400

        # Fotoğrafı yeniden boyutlandırma (örneğin, maksimum genişlik/yükseklik: 1024x1024)
        image = Image.open(file)
        max_size = (1024, 1024)
        image.thumbnail(max_size)  # Maksimum boyut ile yeniden boyutlandır

        # Özel dosya adı oluşturma
        extension = file.filename.rsplit('.', 1)[1].lower()  # Dosya uzantısını al
        timestamp = int(time.time())  # Zaman damgası (epoch time)
        filename = f"{timestamp}.{extension}"  # Yeni dosya adı

        # Dosya yolunu oluştur ve kaydet
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        image.save(file_path, format="JPEG", quality=85)  # JPEG formatında sıkıştırılmış şekilde kaydet

        user = users_collection.find_one({'email': email})
        if user:
            user_id = user.get('_id')
            file_url = f'http://localhost:8080/uploads/{filename}'  # Fotoğrafın erişim URL'si
            users_collection.update_one({'email': email}, {'$set': {'profile_picture': file_url}})
            files_collection.update_one({'user_id': user_id}, {'$set': {'file_path': file_url}}, upsert=True)
            return jsonify({"message": "Profile picture uploaded successfully"}), 200
        else:
            return jsonify({"message": "User not found"}), 404

    except jwt.ExpiredSignatureError:
        return jsonify({"message": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"message": "Invalid token"}), 401
    

@app.route('/verify-token', methods=['GET'])
def verify_token():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({"message": "Token is missing!"}), 401

    try:
        token = token.split(" ")[1]  # Bearer token'dan ayırma
        decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        
        # Kullanıcı adı ve rol bilgisine erişim
        email = decoded.get('email')
        role = decoded.get('role')  # Rol bilgisi token'da eklenmiş olmalı

        # Eğer rol bilgisi yoksa, varsayılan olarak "user" yapabilirsiniz
        return jsonify({"message": "Token is valid", "role": role, "email": email}), 200

    except jwt.ExpiredSignatureError:
        return jsonify({"message": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"message": "Invalid token"}), 401


@app.route('/api/users', methods=['GET'])
def get_users():
    users = users_collection.find({}, {'password': 0})  # Şifreyi göstermemek için password alanını hariç tutuyoruz
    users_list = []
    for user in users:
        user['_id'] = str(user['_id'])  # ObjectId'yi stringe çevir
        users_list.append(user)
    return jsonify(users_list), 200


@app.route('/api/users/<user_id>', methods=['DELETE'])
def delete_user(user_id):
    result = users_collection.delete_one({'_id': ObjectId(user_id)})
    if result.deleted_count:
        return jsonify({"message": "User deleted successfully"}), 200
    else:
        return jsonify({"message": "User not found"}), 404

@app.route('/api/users/<user_id>', methods=['PUT'])
def update_user(user_id):
    data = request.json
    update_fields = {}
    
    # Güncellenebilecek alanları kontrol edelim
    if 'email' in data:
        update_fields['email'] = data['email']
    if 'role' in data:
        update_fields['role'] = data['role']
    
    result = users_collection.update_one({'_id': ObjectId(user_id)}, {'$set': update_fields})
    
    if result.matched_count:
        return jsonify({"message": "User updated successfully"}), 200
    else:
        return jsonify({"message": "User not found"}), 404


@app.route('/api/users', methods=['POST'])
def create_user():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    
    if not all([email,  password]):
        return jsonify({"message": "Missing information", "status": 400}), 400
    
    # Kullanıcıyı kontrol et
    existing_user = users_collection.find_one({'email': email})
    if existing_user:
        return jsonify({"message": "Email already exists", "status": 409}), 409
    
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    
    users_collection.insert_one({
        'email': email,
        'password': hashed_password,
        'role': 'user'  # Varsayılan role user olacak
    })
    
    return jsonify({"message": "User created successfully", "status": 201}), 201












        # Jobs collection
jobs_collection = db["jobs"]

@app.route('/add-job', methods=['POST'])
def add_job():
    data = request.json
    title = data.get('title')
    department = data.get('department')
    skills = data.get('skills')
    desc = data.get('desc')

    if not all([title, department, skills]):
        return jsonify({"message": "Missing information", "status": 400})

    # Insert job into MongoDB
    job_id = jobs_collection.insert_one({
        'title': title,
        'department': department,
        'skills': skills,
        'desc': desc,
        'active':True
        
    }).inserted_id

    return jsonify({"message": "Job added successfully", "job_id": str(job_id), "status": 201})

# Fetch all jobs
@app.route('/jobs', methods=['GET'])
def get_jobs():
    jobs = list(jobs_collection.find({}, {'_id': 1, 'title': 1, 'department': 1, 'skills': 1, 'desc': 1,'active':1}))
    
    # Convert MongoDB ObjectId to string for each job and rename _id to id
    for job in jobs:
        job['id'] = str(job['_id'])
        del job['_id']  # Remove original _id

    return jsonify(jobs), 200


@app.route('/jobs/<job_id>', methods=['GET'])
def get_job(job_id):
    try:
        job = jobs_collection.find_one({'_id': ObjectId(job_id)}, {'_id': 0})  # Exclude _id from response
        if job:
            return jsonify(job), 200
        else:
            return jsonify({"message": "Job not found"}), 404
    except Exception as e:
        return jsonify({"message": str(e)}), 500
    


@app.route('/jobs/<job_id>', methods=['PATCH'])
def update_job(job_id):
    job = jobs_collection.find_one({"_id": ObjectId(job_id)})
    if not job:
        return jsonify({"message": "Job not found"}), 404

    # Update job details
    updated_data = {}
    if 'title' in request.json:
        updated_data['title'] = request.json['title']
    if 'department' in request.json:
        updated_data['department'] = request.json['department']
    if 'skills' in request.json:
        updated_data['skills'] = request.json['skills']
    if 'desc' in request.json:
        updated_data['desc'] = request.json['desc']
    if 'active' in request.json:
        updated_data['active'] = request.json['active']

    jobs_collection.update_one({"_id": ObjectId(job_id)}, {"$set": updated_data})
    return jsonify({"message": "Job updated successfully"}), 200

    
@app.route('/jobs/<job_id>', methods=['DELETE'])
def delete_job(job_id):
    result = jobs_collection.delete_one({'_id': ObjectId(job_id)})

    if result.deleted_count > 0:
        return jsonify({"message": "Job deleted successfully"}), 200
    return jsonify({"message": "Job not found"}), 404




@app.route('/apply-job', methods=['POST'])
def apply_job():
    # Başvuru form verilerini alın
    form_data = request.form.to_dict()
    job_id = form_data.get('jobId')

    # Eğer job_id yoksa, 400 hatası döndür
    if not job_id:
        return jsonify({"message": "Job ID is required"}), 400
    
    # Eğer CV dosyası varsa kontrol et
    if 'cv' in request.files:
        file = request.files['cv']
        if file.filename == '':
            # Dosya yoksa hata döndürme
            form_data['cv_path'] = None  # CV yolu boş bırakılır
        else:
            # Sadece PDF dosyası yüklenmesine izin ver
            if not file.filename.endswith('.pdf'):
                return jsonify({"message": "Only PDF files are allowed"}), 400

            # Dosyayı yükle
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            form_data['cv_path'] = file_path  # CV yolunu kaydet

    else:
        form_data['cv_path'] = None  # Eğer dosya yoksa, CV yolu None olarak ayarlanır

    # Başvuru tarihini ayarla
    form_data['application_date'] = dt.utcnow()

    # Job ID'yi form verisine ekleyin
    form_data['job_id'] = job_id

    # Başvuru verisini MongoDB'ye kaydedin
    basvuru_collection.insert_one(form_data)

    return jsonify({"message": "Application submitted successfully"}), 201


@app.route('/api/applications', methods=['GET'])
def get_applications():
    job_id = request.args.get('job_id')
    if not job_id:
        return jsonify({"error": "Job ID is required"}), 400

    applications = basvuru_collection.find({"job_id": job_id})
    applications_list = list(applications)  # Convert cursor to a list

    # Format the data if necessary
    for application in applications_list:
        application['_id'] = str(application['_id'])

    return jsonify(applications_list), 200





if __name__ == '__main__':
    app.run(port=8080, debug=True)




