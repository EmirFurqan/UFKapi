from fastapi import FastAPI, HTTPException, Request, File, UploadFile, Depends
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pymongo import MongoClient
from pymongo.server_api import ServerApi
from dotenv import load_dotenv
from pydantic import BaseModel
from bson import ObjectId
import os
import bcrypt
import jwt
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from PIL import Image
from datetime import datetime, timedelta
import time

# .env dosyasını yükle
load_dotenv()

app = FastAPI()

# CORS yapılandırması
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# MongoDB bağlantısı
uri = os.getenv('MONGO_URI')
client = MongoClient(uri, server_api=ServerApi('1'))

db = client["test"]
users_collection = db["users"]
files_collection = db["files"]
jobs_collection = db["jobs"]
basvuru_collection = db["basvurular"]

SECRET_KEY = os.getenv('SECRET_KEY')

# Email doğrulama fonksiyonu
def send_verification_email(to_email, token, name):
    sender_email = os.getenv('SENDER_EMAIL')
    sender_password = os.getenv('SENDER_PASSWORD')
    subject = 'Email Verification'
    body = f'Sevgili {name}, hesabını doğrulamak için şu linke tıklayabilirsin: http://localhost:3000/verify-email?token={token}'

    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = to_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, to_email, msg.as_string())
    except Exception as e:
        print(f'Error: {e}')


class RegisterModel(BaseModel):
    name: str
    surname: str
    email: str
    password: str


@app.post("/register")
async def register(data: RegisterModel):
    email = data.email
    password = data.password
    
    # Email kontrolü
    existing_user = users_collection.find_one({'email': email})
    if existing_user:
        raise HTTPException(status_code=409, detail="Email already exists")
    
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    token = jwt.encode({'email': email, 'exp': datetime.utcnow() + timedelta(hours=24)}, SECRET_KEY, algorithm='HS256')

    users_collection.insert_one({
        'name': data.name,
        'surname': data.surname,
        'email': email,
        'password': hashed_password,
        'email_verified': False,
        'role': 'user',
        'verification_token': token
    })
    
    send_verification_email(email, token, data.name)
    
    return {"message": "User registered successfully, please check your email to verify your account"}


@app.get("/verify-email")
async def verify_email(token: str):
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        email = decoded['email']
        result = users_collection.update_one({'email': email, 'verification_token': token}, {'$set': {'email_verified': True, 'verification_token': None}})
        if result.matched_count:
            return {"message": "Email verified successfully"}
        else:
            raise HTTPException(status_code=400, detail="Invalid or expired token")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=400, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=400, detail="Invalid token")


class LoginModel(BaseModel):
    email: str
    password: str


@app.post("/login")
async def login(data: LoginModel):
    email = data.email
    password = data.password

    user = users_collection.find_one({'email': email})

    if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
        if not user.get('email_verified'):
            raise HTTPException(status_code=403, detail="Email not verified")

        token = jwt.encode({
            'email': email,
            'role': user['role'],
            'exp': datetime.utcnow() + timedelta(hours=24)
        }, SECRET_KEY, algorithm='HS256')

        return {"message": "Login successful", "token": token, "role": user['role']}
    else:
        raise HTTPException(status_code=401, detail="Invalid credentials")


@app.get("/profile")
async def profile(token: str = Depends()):
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        email = decoded['email']
        user = users_collection.find_one({'email': email}, {'_id': 0, 'password': 0})
        if user:
            return user
        else:
            raise HTTPException(status_code=404, detail="User not found")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


@app.post("/upload-profile-picture")
async def upload_profile_picture(file: UploadFile = File(...), token: str = Depends()):
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        email = decoded['email']

        # Resmi yeniden boyutlandırma
        image = Image.open(file.file)
        max_size = (1024, 1024)
        image.thumbnail(max_size)

        # Özel dosya adı oluşturma
        extension = file.filename.rsplit('.', 1)[1].lower()
        timestamp = int(time.time())
        filename = f"{timestamp}.{extension}"

        file_path = os.path.join('uploads', filename)
        image.save(file_path, format="JPEG", quality=85)

        user = users_collection.find_one({'email': email})
        if user:
            file_url = f'http://localhost:8080/uploads/{filename}'
            users_collection.update_one({'email': email}, {'$set': {'profile_picture': file_url}})
            return {"message": "Profile picture uploaded successfully"}
        else:
            raise HTTPException(status_code=404, detail="User not found")

    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


class JobModel(BaseModel):
    title: str
    department: str
    skills: str
    desc: str


@app.post("/add-job")
async def add_job(data: JobModel):
    job_id = jobs_collection.insert_one({
        'title': data.title,
        'department': data.department,
        'skills': data.skills,
        'desc': data.desc,
        'active': True
    }).inserted_id

    return {"message": "Job added successfully", "job_id": str(job_id)}


@app.get("/jobs")
async def get_jobs():
    jobs = list(jobs_collection.find({}, {'_id': 1, 'title': 1, 'department': 1, 'skills': 1, 'desc': 1, 'active': 1}))
    for job in jobs:
        job['id'] = str(job['_id'])
        del job['_id']
    return jobs


@app.get("/jobs/{job_id}")
async def get_job(job_id: str):
    try:
        job = jobs_collection.find_one({'_id': ObjectId(job_id)}, {'_id': 0})
        if job:
            return job
        else:
            raise HTTPException(status_code=404, detail="Job not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
