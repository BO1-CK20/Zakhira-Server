"""
Dakhira Pro - PayPal Webhook Server
نظام Webhook احترافي للدفع التلقائي

Features:
- RSA-SHA256 Signature Verification (أمان PayPal الرسمي)
- SQLite Database للاشتراكات
- API endpoints للتحقق من حالة الاشتراك
- دعم Webhook Events: PAYMENT.CAPTURE.COMPLETED, BILLING.SUBSCRIPTION.ACTIVATED

Setup:
    1. pip install fastapi uvicorn sqlite3 crc32
    2. Set environment variables:
       - PAYPAL_WEBHOOK_ID
       - SERVER_API_KEY (لحماية API)
    3. Run: uvicorn webhook_server:app --host 0.0.0.0 --port 8000

PayPal Webhook URL:
    https://your-server.com/webhook/paypal
    
API Endpoints:
    POST /webhook/paypal - استقبال إشعارات PayPal
    GET  /api/status/{user_id} - التحقق من حالة اشتراك مستخدم
    POST /api/verify - التحقق من الاشتراك (من اللانشر)

Author: Professional Implementation
Date: April 2026
"""

import os
import json
import base64
import hashlib
import sqlite3
import requests
import time
import re
import random
import string
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from pathlib import Path

from fastapi import FastAPI, Request, HTTPException, Header, Depends
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, validator

# ========== License Key Generation ==========

def generate_license_key(plan_type: str, order_id: str = None) -> str:
    """
    توليد كود تفعيل فريد
    
    Format: DKH-{MONTH|YEAR}-XXXX-XXXX
    - MONTH for monthly subscriptions
    - YEAR for yearly subscriptions
    
    Args:
        plan_type: "monthly" or "yearly"
        order_id: PayPal order ID (optional, for uniqueness)
    
    Returns:
        license_key: كود التفعيل المُولد
    """
    prefix = "DKH"
    plan_code = "MONTH" if plan_type == "monthly" else "YEAR"
    
    # توليد أجزاء عشوائية
    part1 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
    part2 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=4))
    
    license_key = f"{prefix}-{plan_code}-{part1}-{part2}"
    
    return license_key


# ========== Input Sanitization (منع Injection) ==========

def sanitize_user_id(user_id: str) -> str:
    """
    تنظيف user_id لمنع SQL Injection و XSS
    
    Rules:
        - السماح فقط بـ: a-z, A-Z, 0-9, _, -, .
        - الحد الأقصى: 64 حرف
        - رفض أي محاولات حقن SQL
    """
    if not user_id:
        raise HTTPException(status_code=400, detail="User ID is required")
    
    # Check length
    if len(user_id) > 64:
        raise HTTPException(status_code=400, detail="User ID too long (max 64 characters)")
    
    # Check for SQL injection patterns
    sql_patterns = [
        r"(--|#|/\*|\*/|;|'|\"|`)",  # SQL comments and quotes
        r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE|UNION|OR\s+1\s*=\s*1|AND\s+1\s*=\s*1)\b)",  # SQL keywords
        r"(%27|%22|%3B|--)",  # URL encoded SQL
    ]
    
    for pattern in sql_patterns:
        if re.search(pattern, user_id, re.IGNORECASE):
            print(f"[SECURITY] SQL injection attempt detected in user_id: {user_id[:20]}...")
            raise HTTPException(status_code=400, detail="Invalid user ID format")
    
    # Allow only alphanumeric and safe characters
    if not re.match(r'^[a-zA-Z0-9_.-]+$', user_id):
        raise HTTPException(status_code=400, detail="User ID contains invalid characters")
    
    return user_id

def sanitize_email(email: str) -> str:
    """تنظيف email للتحقق من صحته"""
    if not email:
        return ""
    
    # Basic email validation
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_pattern, email):
        raise HTTPException(status_code=400, detail="Invalid email format")
    
    # Check length
    if len(email) > 254:  # RFC 5321
        raise HTTPException(status_code=400, detail="Email too long")
    
    return email.lower().strip()

def sanitize_plan_type(plan_type: str) -> str:
    """التحقق من نوع الخطة"""
    allowed_plans = ["monthly", "yearly", "season"]
    
    if plan_type not in allowed_plans:
        raise HTTPException(status_code=400, detail=f"Invalid plan type. Allowed: {', '.join(allowed_plans)}")
    
    return plan_type

# Load Environment Variables from .env file (إذا وجد)
try:
    from dotenv import load_dotenv
    # ابحث عن ملف .env في نفس مجلد الملف الحالي
    env_path = Path(__file__).parent / ".env"
    if env_path.exists():
        load_dotenv(env_path)
        print(f"[ENV] Loaded .env from: {env_path}")
    else:
        print(f"[ENV] No .env file found at: {env_path}")
        print("[ENV] Using system environment variables")
except ImportError:
    print("[ENV] python-dotenv not installed, using system environment variables")

# PayPal Integration
from paypal_integration import get_paypal_integration, PayPalIntegration

# ========== Configuration ==========
PAYPAL_WEBHOOK_ID = os.getenv("PAYPAL_WEBHOOK_ID", "")
SERVER_API_KEY = os.getenv("SERVER_API_KEY", "dakhira_secure_key_2024")
DATABASE_PATH = Path("data/subscriptions.db")

# ========== Database Setup ==========
class Database:
    """قاعدة بيانات الاشتراكات"""
    
    def __init__(self, db_path: Path = DATABASE_PATH):
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.init_db()
    
    def get_connection(self):
        return sqlite3.connect(self.db_path)
    
    def init_db(self):
        """إنشاء الجداول"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # جدول الاشتراكات
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS subscriptions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id TEXT NOT NULL,
                    paypal_subscription_id TEXT,
                    paypal_order_id TEXT,
                    plan_type TEXT NOT NULL,  -- monthly, yearly, season
                    status TEXT NOT NULL,     -- active, cancelled, expired
                    payer_email TEXT,
                    amount REAL,
                    currency TEXT DEFAULT 'USD',
                    start_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    end_date TIMESTAMP,
                    last_payment_date TIMESTAMP,
                    next_payment_date TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # جدول webhook events (للتتبع)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS webhook_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT UNIQUE NOT NULL,
                    event_type TEXT NOT NULL,
                    resource_id TEXT,
                    payload TEXT,
                    received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    processed BOOLEAN DEFAULT 0
                )
            """)
            
            # جدول API access logs (للأمان)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS api_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id TEXT,
                    action TEXT,
                    ip_address TEXT,
                    success BOOLEAN,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # 🔥 NEW: جدول أكواد التفعيل (license codes)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS license_codes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    code TEXT UNIQUE NOT NULL,           -- DKH-XXXX-XXXX-XXXX
                    plan_type TEXT NOT NULL,             -- monthly, yearly
                    order_id TEXT,                       -- PayPal order ID
                    user_email TEXT,                     -- Buyer email
                    is_used BOOLEAN DEFAULT 0,           -- Has been activated?
                    user_id TEXT,                        -- Who activated it
                    used_at TIMESTAMP,                   -- When activated
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP,                -- License expiry
                    client_id TEXT                       -- For verification
                )
            """)
            
            # 🔥 NEW: جدول سجل تفعيل الأكواد
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS license_activations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    license_key TEXT NOT NULL,
                    plan_type TEXT,
                    order_id TEXT,
                    user_email TEXT,
                    timestamp TIMESTAMP,
                    status TEXT,                         -- pending, activated, expired
                    ip_address TEXT,
                    activated_by TEXT,                   -- user_id
                    activated_at TIMESTAMP
                )
            """)
            
            # Create indexes for faster queries
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_license_code ON license_codes(code)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_license_order ON license_codes(order_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_activation_key ON license_activations(license_key)")
            
            conn.commit()
    
    def add_subscription(self, user_id: str, plan_type: str, 
                        paypal_sub_id: str = None, paypal_order_id: str = None,
                        payer_email: str = None, amount: float = None) -> bool:
        """إضافة اشتراك جديد"""
        # حساب تاريخ الانتهاء
        duration_days = {
            "monthly": 30,
            "yearly": 365,
            "season": 90
        }.get(plan_type, 30)
        
        end_date = datetime.now() + timedelta(days=duration_days)
        
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO subscriptions 
                (user_id, paypal_subscription_id, paypal_order_id, plan_type, status,
                 payer_email, amount, end_date, next_payment_date)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (user_id, paypal_sub_id, paypal_order_id, plan_type, "active",
                  payer_email, amount, end_date, end_date))
            conn.commit()
            return True
    
    def get_active_subscription(self, user_id: str) -> Optional[Dict]:
        """الحصول على الاشتراك النشط"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM subscriptions 
                WHERE user_id = ? AND status = 'active' AND end_date > datetime('now')
                ORDER BY created_at DESC LIMIT 1
            """, (user_id,))
            
            row = cursor.fetchone()
            if row:
                columns = [description[0] for description in cursor.description]
                return dict(zip(columns, row))
            return None
    
    def update_subscription_status(self, paypal_sub_id: str, status: str):
        """تحديث حالة الاشتراك"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE subscriptions 
                SET status = ?, updated_at = datetime('now')
                WHERE paypal_subscription_id = ?
            """, (status, paypal_sub_id))
            conn.commit()
    
    def cancel_subscription(self, user_id: str) -> bool:
        """إلغاء اشتراك"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE subscriptions 
                SET status = 'cancelled', updated_at = datetime('now')
                WHERE user_id = ? AND status = 'active'
            """, (user_id,))
            conn.commit()
            return cursor.rowcount > 0
    
    def log_event(self, event_id: str, event_type: str, resource_id: str, payload: str):
        """تسجيل webhook event"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT OR IGNORE INTO webhook_events (event_id, event_type, resource_id, payload)
                    VALUES (?, ?, ?, ?)
                """, (event_id, event_type, resource_id, payload))
                conn.commit()
        except:
            pass  # لا نريد فشل Webhook بسبب logging
    
    def log_api_access(self, user_id: str, action: str, ip_address: str, success: bool):
        """تسجيل وصول API"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO api_logs (user_id, action, ip_address, success)
                    VALUES (?, ?, ?, ?)
                """, (user_id, action, ip_address, success))
                conn.commit()
        except:
            pass


# ========== PayPal Signature Verification ==========
class PayPalVerifier:
    """التحقق من توقيع PayPal Webhook"""
    
    @staticmethod
    def fetch_paypal_certificate(cert_url: str) -> str:
        """جلب شهادة PayPal"""
        # تأكد من أن الرابط من PayPal فقط (أمان)
        if not (cert_url.endswith('.paypal.com') or cert_url.endswith('.sandbox.paypal.com')):
            raise ValueError("Invalid certificate URL - not from PayPal domain")
        
        response = requests.get(cert_url, timeout=10)
        response.raise_for_status()
        return response.text
    
    @staticmethod
    def compute_crc32(body: str) -> int:
        """حساب CRC32 للـ body"""
        # CRC32 للتحقق من سلامة البيانات
        import zlib
        return zlib.crc32(body.encode('utf-8')) & 0xffffffff
    
    @staticmethod
    def verify_signature(headers: dict, body: str, webhook_id: str) -> bool:
        """
        التحقق من توقيع PayPal Webhook
        
        Algorithm: RSA-SHA256 (الموصى به من PayPal)
        """
        try:
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import padding
            
            # استخراج Headers
            transmission_id = headers.get("paypal-transmission-id")
            transmission_time = headers.get("paypal-transmission-time")
            transmission_sig = headers.get("paypal-transmission-sig")
            cert_url = headers.get("paypal-cert-url")
            auth_algo = headers.get("paypal-auth-algo")
            
            # التحقق من وجود جميع القيم
            if not all([transmission_id, transmission_time, transmission_sig, cert_url, webhook_id]):
                print("[PayPal] Missing required headers")
                return False
            
            # التحقق من Algorithm
            if auth_algo != "SHA256withRSA":
                print(f"[PayPal] Invalid auth algorithm: {auth_algo}")
                return False
            
            # حساب CRC32
            crc = PayPalVerifier.compute_crc32(body)
            
            # بناء string للتحقق
            verification_string = f"{transmission_id}|{transmission_time}|{webhook_id}|{crc}"
            
            # جلب الشهادة
            cert_pem = PayPalVerifier.fetch_paypal_certificate(cert_url)
            
            # تحميل المفتاح العام من الشهادة
            certificate = serialization.load_pem_public_key(cert_pem.encode())
            
            # فك تشفير التوقيع
            signature_bytes = base64.b64decode(transmission_sig)
            
            # التحقق
            certificate.verify(
                signature_bytes,
                verification_string.encode(),
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            
            print("[PayPal] Signature verified successfully")
            return True
            
        except Exception as e:
            print(f"[PayPal] Signature verification failed: {e}")
            return False


# ========== Security & Rate Limiting ==========
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
import time
from collections import defaultdict

# Rate Limiter Configuration (حماية DDoS & Brute Force)
limiter = Limiter(key_func=get_remote_address)

# IP Blocking for repeated failures (حماية Brute Force)
failed_attempts = defaultdict(lambda: {"count": 0, "last_attempt": 0, "blocked_until": 0})
MAX_FAILED_ATTEMPTS = 5
BLOCK_DURATION = 3600  # 1 hour

def is_ip_blocked(ip: str) -> bool:
    """التحقق إذا كان الـ IP محظور"""
    now = time.time()
    if ip in failed_attempts:
        if failed_attempts[ip]["blocked_until"] > now:
            return True
        # Reset if block expired
        if failed_attempts[ip]["blocked_until"] > 0 and failed_attempts[ip]["blocked_until"] <= now:
            failed_attempts[ip] = {"count": 0, "last_attempt": 0, "blocked_until": 0}
    return False

def record_failed_attempt(ip: str):
    """تسجيل محاولة فاشلة"""
    now = time.time()
    failed_attempts[ip]["count"] += 1
    failed_attempts[ip]["last_attempt"] = now
    
    if failed_attempts[ip]["count"] >= MAX_FAILED_ATTEMPTS:
        failed_attempts[ip]["blocked_until"] = now + BLOCK_DURATION
        print(f"[SECURITY] IP {ip} blocked for {BLOCK_DURATION} seconds due to {MAX_FAILED_ATTEMPTS} failed attempts")

def record_successful_attempt(ip: str):
    """إعادة تعيين المحاولات الفاشلة بعد نجاح"""
    if ip in failed_attempts:
        failed_attempts[ip] = {"count": 0, "last_attempt": 0, "blocked_until": 0}

# ========== FastAPI Application ==========
app = FastAPI(
    title="Dakhira Pro Webhook Server",
    version="1.0.0",
    description="Secure Payment & Subscription Management System",
    docs_url="/docs" if os.getenv("DEBUG", "false").lower() == "true" else None,  # Disable docs in production
    redoc_url=None  # Disable ReDoc in production
)

# Add Rate Limiter
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

db = Database()
security = HTTPBearer()

# ========== CORS Configuration ==========
# السماح فقط بالمصادر الموثوقة
ALLOWED_ORIGINS = [
    "https://zakhira-pro.carrd.co",  # Carrd page
    "https://*.carrd.co",            # Any Carrd subdomain
    "https://*.railway.app",         # Railway deployment
    "https://*.onrender.com",        # Render deployment
    "https://*.loca.lt",             # LocalTunnel
    "https://*.ngrok-free.app",      # Ngrok
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],  # Restrict methods
    allow_headers=["Authorization", "Content-Type", "X-Client-Version"],
    max_age=600,  # Cache preflight for 10 minutes
)

# ========== Security Headers Middleware ==========
@app.middleware("http")
async def security_headers(request: Request, call_next):
    """إضافة رؤوس أمان HTTP"""
    response = await call_next(request)
    
    # Security Headers (OWASP Recommended)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline' https://www.paypal.com; frame-src https://www.paypal.com; connect-src 'self' https://api-m.paypal.com;"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    
    # Remove server identification
    response.headers.pop("Server", None)
    
    return response

# ========== Request Logging & Monitoring ==========
@app.middleware("http")
async def log_requests(request: Request, call_next):
    """تسجيل الطلبات للمراقبة"""
    start_time = time.time()
    client_ip = get_remote_address(request)
    
    # Check if IP is blocked
    if is_ip_blocked(client_ip):
        print(f"[SECURITY] Blocked request from {client_ip} - IP is temporarily blocked")
        return JSONResponse(
            status_code=403,
            content={"detail": "Access temporarily blocked due to suspicious activity"}
        )
    
    # Log request
    print(f"[REQUEST] {client_ip} - {request.method} {request.url.path}")
    
    response = await call_next(request)
    
    # Log response time
    process_time = time.time() - start_time
    print(f"[RESPONSE] {client_ip} - {request.method} {request.url.path} - {response.status_code} - {process_time:.3f}s")
    
    return response

# Pydantic Models
class SubscriptionStatus(BaseModel):
    user_id: str
    is_active: bool
    plan_type: Optional[str] = None
    end_date: Optional[str] = None
    days_remaining: int = 0

class VerificationRequest(BaseModel):
    user_id: str
    hardware_id: Optional[str] = None
    
    @validator('user_id')
    def validate_user_id(cls, v):
        return sanitize_user_id(v)
    
    @validator('hardware_id')
    def validate_hardware_id(cls, v):
        if v:
            # Hardware ID: alphanumeric only, max 128 chars
            if len(v) > 128:
                raise HTTPException(status_code=400, detail="Hardware ID too long")
            if not re.match(r'^[a-zA-Z0-9_-]+$', v):
                raise HTTPException(status_code=400, detail="Invalid hardware ID format")
        return v

class VerificationResponse(BaseModel):
    valid: bool
    subscription: Optional[Dict] = None
    message: str

class CreateOrderRequest(BaseModel):
    user_id: str
    plan_type: str  # monthly, yearly, season
    
    @validator('user_id')
    def validate_user_id(cls, v):
        return sanitize_user_id(v)
    
    @validator('plan_type')
    def validate_plan_type(cls, v):
        return sanitize_plan_type(v)

class CreateOrderResponse(BaseModel):
    order_id: str
    status: str
    approval_url: Optional[str] = None
    plan_type: str
    amount: str

class CaptureOrderResponse(BaseModel):
    order_id: str
    status: str
    capture_id: Optional[str] = None
    amount: Optional[str] = None
    payer_email: Optional[str] = None


# ========== API Endpoints ==========

@app.get("/")
@limiter.limit("60/minute")  # Health check endpoint - higher limit
def root():
    """الصفحة الرئيسية"""
    return {
        "service": "Dakhira Pro Webhook Server",
        "version": "1.0.0",
        "status": "running",
        "security": {
            "rate_limiting": "enabled",
            "ip_blocking": "enabled",
            "cors": "configured",
            "headers": "secure"
        },
        "endpoints": {
            "webhook": "/webhook/paypal",
            "status": "/api/status/{user_id}",
            "verify": "/api/verify",
            "health": "/health"
        }
    }


@app.get("/health")
@limiter.limit("60/minute")  # Health check - higher limit
def health_check():
    """فحص صحة السيرفر (للـ monitoring)"""
    return {
        "status": "healthy",
        "database": "connected",
        "timestamp": datetime.now().isoformat(),
        "version": "1.0.0"
    }


@app.get("/admin/security-status")
@limiter.limit("10/minute")  # Admin endpoint - strict limit
def security_status(api_key: str = Depends(verify_api_key)):
    """
    حالة الأمان (للإدارة فقط)
    
    Returns:
        - blocked_ips: عدد الـ IPs المحظورة
        - failed_attempts: إحصائيات المحاولات الفاشلة
        - rate_limits: حدود الطلبات المطبقة
    """
    now = time.time()
    active_blocks = [
        ip for ip, data in failed_attempts.items()
        if data["blocked_until"] > now
    ]
    
    return {
        "security_status": {
            "active_ip_blocks": len(active_blocks),
            "blocked_ips": active_blocks,
            "rate_limits": {
                "webhook": "10/minute",
                "status_check": "30/minute",
                "order_creation": "10/minute",
                "general": "60/minute"
            },
            "cors_origins": len(ALLOWED_ORIGINS),
            "security_headers": [
                "X-Content-Type-Options",
                "X-Frame-Options", 
                "X-XSS-Protection",
                "Strict-Transport-Security",
                "Content-Security-Policy",
                "Referrer-Policy",
                "Permissions-Policy"
            ]
        },
        "timestamp": datetime.now().isoformat()
    }


@app.post("/webhook/paypal")
@limiter.limit("10/minute")  # Rate limit for webhooks (10 per minute per IP)
async def paypal_webhook(request: Request):
    """
    استقبال Webhook من PayPal
    
    Events:
        - PAYMENT.CAPTURE.COMPLETED (دفع لمرة واحدة)
        - BILLING.SUBSCRIPTION.ACTIVATED (اشتراك جديد)
        - BILLING.SUBSCRIPTION.CANCELLED (إلغاء اشتراك)
        - BILLING.SUBSCRIPTION.EXPIRED (انتهاء اشتراك)
    """
    # قراءة headers
    headers = {
        "paypal-transmission-id": request.headers.get("paypal-transmission-id"),
        "paypal-transmission-time": request.headers.get("paypal-transmission-time"),
        "paypal-transmission-sig": request.headers.get("paypal-transmission-sig"),
        "paypal-cert-url": request.headers.get("paypal-cert-url"),
        "paypal-auth-algo": request.headers.get("paypal-auth-algo"),
    }
    
    # قراءة body
    body_bytes = await request.body()
    body = body_bytes.decode("utf-8")
    
    print(f"[Webhook] Received PayPal webhook")
    print(f"[Webhook] Headers: {json.dumps({k: v for k, v in headers.items() if v}, indent=2)}")
    
    # التحقق من التوقيع (الأمان)
    if not PayPalVerifier.verify_signature(headers, body, PAYPAL_WEBHOOK_ID):
        print("[Webhook] Signature verification failed - rejecting")
        raise HTTPException(status_code=401, detail="Invalid signature")
    
    # parse payload
    try:
        payload = json.loads(body)
    except:
        raise HTTPException(status_code=400, detail="Invalid JSON")
    
    event_type = payload.get("event_type")
    event_id = payload.get("id")
    resource = payload.get("resource", {})
    
    print(f"[Webhook] Event: {event_type} (ID: {event_id})")
    
    # تسجيل الحدث
    db.log_event(event_id, event_type, resource.get("id"), body)
    
    # معالجة الحدث
    if event_type == "PAYMENT.CAPTURE.COMPLETED":
        # دفع لمرة واحدة (One-time payment)
        handle_payment_completed(resource)
        
    elif event_type == "BILLING.SUBSCRIPTION.ACTIVATED":
        # اشتراك جديد
        handle_subscription_activated(resource)
        
    elif event_type == "BILLING.SUBSCRIPTION.CANCELLED":
        # إلغاء اشتراك
        handle_subscription_cancelled(resource)
        
    elif event_type == "BILLING.SUBSCRIPTION.EXPIRED":
        # انتهاء اشتراك
        handle_subscription_expired(resource)
    
    # مهم: إرجاع 200 فوراً لمنع PayPal من إعادة الإرسال
    return {"received": True, "event_type": event_type}


def handle_payment_completed(resource: dict):
    """معالجة اكتمال الدفع"""
    try:
        # استخراج المعلومات
        order_id = resource.get("id")
        amount = resource.get("amount", {}).get("value")
        currency = resource.get("amount", {}).get("currency_code")
        
        # custom_id يحتوي على user_id (نرسله من صفحة الدفع)
        custom_id = resource.get("custom_id", "")
        
        # استخراج plan من custom_id أو invoice_id
        # مثال: custom_id = "user_123_yearly"
        user_id = None
        plan_type = "monthly"  # default
        
        if custom_id:
            parts = custom_id.split("_")
            if len(parts) >= 2:
                user_id = parts[0]
                if len(parts) >= 3:
                    plan_type = parts[2]  # monthly/yearly/season
        
        # ✅ تحديد نوع الخطة من المبلغ المدفوع (إذا لم يكن محدد في custom_id)
        if amount:
            amount_float = float(amount)
            if 5.0 <= amount_float <= 6.0:  # ~5.33 USD = 20 SAR (Monthly)
                plan_type = "monthly"
            elif 35.0 <= amount_float <= 45.0:  # ~39.47 USD = 148 SAR (Yearly)
                plan_type = "yearly"
        
        # ✅ توليد كود تفعيل فريد
        license_key = generate_license_key(plan_type, order_id)
        
        # ✅ حفظ الكود في قاعدة البيانات
        if order_id:
            with db.get_connection() as conn:
                cursor = conn.cursor()
                now = datetime.now()
                
                # حساب تاريخ انتهاء الصلاحية
                if plan_type == "yearly":
                    expires_at = now + timedelta(days=365)
                else:
                    expires_at = now + timedelta(days=30)
                
                cursor.execute("""
                    INSERT INTO license_codes 
                    (code, plan_type, order_id, is_used, created_at, expires_at)
                    VALUES (?, ?, ?, 0, ?, ?)
                """, (license_key, plan_type, order_id, now.isoformat(), expires_at.isoformat()))
                conn.commit()
                
                print(f"[Payment] Generated license: {license_key} ({plan_type})")
        
        if user_id:
            db.add_subscription(user_id, plan_type, 
                              paypal_order_id=order_id,
                              amount=float(amount) if amount else None)
            print(f"[Payment] Activated {plan_type} for user {user_id}")
        
    except Exception as e:
        print(f"[Payment] Error processing payment: {e}")


def handle_subscription_activated(resource: dict):
    """معالجة تفعيل اشتراك"""
    try:
        sub_id = resource.get("id")
        status = resource.get("status")
        
        # استخراج بيانات المشترك
        subscriber = resource.get("subscriber", {})
        payer_email = subscriber.get("email_address")
        payer_id = subscriber.get("payer_id")
        
        # custom_id يحتوي على user_id
        custom_id = resource.get("custom_id", "")
        
        # تحديد نوع الخطة من plan_id
        plan_id = resource.get("plan_id", "")
        plan_type = "monthly"  # default
        
        if "yearly" in plan_id.lower() or "annual" in plan_id.lower():
            plan_type = "yearly"
        elif "season" in plan_id.lower():
            plan_type = "season"
        
        user_id = custom_id if custom_id else payer_id
        
        # تفعيل الاشتراك
        db.add_subscription(user_id, plan_type,
                          paypal_sub_id=sub_id,
                          payer_email=payer_email,
                          amount=None)
        
        print(f"[Subscription] Activated {plan_type} subscription for {user_id}")
        
    except Exception as e:
        print(f"[Subscription] Error: {e}")


def handle_subscription_cancelled(resource: dict):
    """معالجة إلغاء اشتراك"""
    try:
        sub_id = resource.get("id")
        db.update_subscription_status(sub_id, "cancelled")
        print(f"[Subscription] Cancelled: {sub_id}")
    except Exception as e:
        print(f"[Subscription] Error cancelling: {e}")


def handle_subscription_expired(resource: dict):
    """معالجة انتهاء اشتراك"""
    try:
        sub_id = resource.get("id")
        db.update_subscription_status(sub_id, "expired")
        print(f"[Subscription] Expired: {sub_id}")
    except Exception as e:
        print(f"[Subscription] Error expiring: {e}")


# ========== API for Launcher ==========

async def verify_api_key(request: Request, credentials: HTTPAuthorizationCredentials = Depends(security)):
    """التحقق من API Key مع حماية Brute Force"""
    client_ip = get_remote_address(request)
    
    # Check if IP is already blocked
    if is_ip_blocked(client_ip):
        print(f"[SECURITY] Blocked API attempt from {client_ip}")
        raise HTTPException(status_code=403, detail="Access temporarily blocked due to suspicious activity")
    
    # Verify API Key
    if credentials.credentials != SERVER_API_KEY:
        # Record failed attempt
        record_failed_attempt(client_ip)
        remaining = MAX_FAILED_ATTEMPTS - failed_attempts[client_ip]["count"]
        print(f"[SECURITY] Invalid API key attempt from {client_ip} ({remaining} attempts remaining)")
        
        if is_ip_blocked(client_ip):
            raise HTTPException(status_code=403, detail="Access blocked due to too many failed attempts")
        
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    # Reset failed attempts on success
    record_successful_attempt(client_ip)
    return credentials.credentials


@app.get("/api/status/{user_id}", response_model=SubscriptionStatus)
@limiter.limit("30/minute")  # Rate limit for status checks (30 per minute per IP)
def check_status(user_id: str, request: Request, api_key: str = Depends(verify_api_key)):
    """
    التحقق من حالة اشتراك مستخدم (يستخدمه اللانشر)
    
    Security:
        - user_id sanitized to prevent injection
        - Rate limited to 30/minute per IP
    
    Returns:
        - is_active: هل الاشتراك نشط؟
        - plan_type: نوع الخطة
        - end_date: تاريخ الانتهاء
        - days_remaining: الأيام المتبقية
    """
    # Sanitize user_id
    user_id = sanitize_user_id(user_id)
    
    ip = request.client.host
    
    sub = db.get_active_subscription(user_id)
    
    if sub:
        # حساب الأيام المتبقية
        end_date = datetime.fromisoformat(sub["end_date"].replace("Z", "+00:00").replace("+00:00", ""))
        days_remaining = (end_date - datetime.now()).days
        
        db.log_api_access(user_id, "check_status", ip, True)
        
        return SubscriptionStatus(
            user_id=user_id,
            is_active=True,
            plan_type=sub["plan_type"],
            end_date=sub["end_date"],
            days_remaining=max(0, days_remaining)
        )
    else:
        db.log_api_access(user_id, "check_status", ip, False)
        return SubscriptionStatus(
            user_id=user_id,
            is_active=False,
            plan_type=None,
            end_date=None,
            days_remaining=0
        )


@app.post("/api/verify", response_model=VerificationResponse)
def verify_subscription(verification: VerificationRequest, request: Request, 
                       api_key: str = Depends(verify_api_key)):
    """
    التحقق من الاشتراك مع hardware ID (للأمان الإضافي)
    """
    ip = request.client.host
    user_id = verification.user_id
    hardware_id = verification.hardware_id
    
    sub = db.get_active_subscription(user_id)
    
    if sub:
        db.log_api_access(user_id, "verify_with_hw", ip, True)
        
        return VerificationResponse(
            valid=True,
            subscription={
                "plan_type": sub["plan_type"],
                "status": sub["status"],
                "end_date": sub["end_date"],
                "payer_email": sub["payer_email"]
            },
            message="Subscription verified successfully"
        )
    else:
        db.log_api_access(user_id, "verify_with_hw", ip, False)
        return VerificationResponse(
            valid=False,
            subscription=None,
            message="No active subscription found"
        )


@app.post("/api/cancel/{user_id}")
def cancel_user_subscription(user_id: str, api_key: str = Depends(verify_api_key)):
    """إلغاء اشتراك مستخدم (من اللانشر)"""
    success = db.cancel_subscription(user_id)
    return {"success": success, "message": "Subscription cancelled" if success else "No active subscription"}


# ========== PayPal Order API (Server-Side) ==========

@app.post("/api/create-order", response_model=CreateOrderResponse)
@limiter.limit("10/minute")  # Rate limit for order creation (10 per minute per IP)
def create_paypal_order(order_request: CreateOrderRequest, 
                       api_key: str = Depends(verify_api_key)):
    """
    إنشاء طلب دفع PayPal من السيرفر (الطريقة الآمنة)
    
    الأمان:
        - المبلغ يُحدد في السيرvoir (مكافحة التلاعب)
        - Secret Key لا يُرسل للمتصفح أبداً
        - يُرجع Order ID فقط
    
    Usage:
        1. اللانشر/صفحة Carrd ترسل: {user_id, plan_type}
        2. السيرفر ينشئ Order ويُرجع order_id
        3. المتصفح يعرض PayPal button بهذا الـ order_id
        4. بعد الدفع، PayPal يرسل Webhook أو نستدعي /api/capture-order
    """
    try:
        paypal = get_paypal_integration()
        
        result = paypal.create_order(
            user_id=order_request.user_id,
            plan_type=order_request.plan_type
        )
        
        # تسجيل في logs
        db.log_api_access(
            order_request.user_id,
            f"create_order_{order_request.plan_type}",
            "server",
            True
        )
        
        return CreateOrderResponse(
            order_id=result["order_id"],
            status=result["status"],
            approval_url=result["approval_url"],
            plan_type=result["plan_type"],
            amount=result["amount"]
        )
        
    except Exception as e:
        print(f"[PayPal] Create order error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/capture-order/{order_id}", response_model=CaptureOrderResponse)
def capture_paypal_order(order_id: str, api_key: str = Depends(verify_api_key)):
    """
    تأكيد استلام الدفع (يُستدعى بعد نجاح الدفع)
    
    يمكن استدعاؤه:
        - تلقائياً عن طريق Webhook
        - يدوياً من اللانشر بعد الدفع
    """
    try:
        paypal = get_paypal_integration()
        
        # Capture the order
        result = paypal.capture_order(order_id)
        
        # استخراج معلومات المستخدم من custom_id
        custom_id = result.get("custom_id", "")
        user_id = None
        plan_type = "monthly"
        
        if custom_id and "_" in custom_id:
            parts = custom_id.split("_")
            if len(parts) >= 2:
                user_id = parts[0]
                plan_type = parts[1]
        
        # تفعيل الاشتراك في قاعدة البيانات
        if user_id and result["status"] == "COMPLETED":
            db.add_subscription(
                user_id=user_id,
                plan_type=plan_type,
                paypal_order_id=order_id,
                payer_email=result.get("payer_email"),
                amount=float(result.get("amount", 0))
            )
            
            print(f"[PayPal] Subscription activated: {user_id} - {plan_type}")
        
        return CaptureOrderResponse(
            order_id=result["order_id"],
            status=result["status"],
            capture_id=result.get("capture_id"),
            amount=result.get("amount"),
            payer_email=result.get("payer_email")
        )
        
    except Exception as e:
        print(f"[PayPal] Capture order error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ========== License Activation Endpoint ==========

class LicenseActivationRequest(BaseModel):
    """طلب تفعيل كود الاشتراك من صفحة الدفع"""
    license_key: str
    plan_type: str
    order_id: str
    user_email: Optional[str] = None
    timestamp: int
    client_id: str

class LicenseActivationResponse(BaseModel):
    """رد تفعيل الاشتراك"""
    success: bool
    message: str
    license_key: Optional[str] = None
    is_valid: bool = False


@app.post("/api/activate-license", response_model=LicenseActivationResponse)
def activate_license_from_payment(request: LicenseActivationRequest):
    """
    🔥 NEW: تفعيل كود اشتراك من صفحة الدفع
    
    يُستدعى من:
        - صفحة الدفع (payment_page/index.html)
        - بعد نجاح الدفع في PayPal
    
    Args:
        license_key: كود التفعيل (DKH-XXXX-XXXX-XXXX)
        plan_type: monthly أو yearly
        order_id: رقم طلب PayPal
        user_email: بريد المستخدم (اختياري)
    
    Returns:
        success: true/false
        message: وصف النتيجة
        is_valid: هل الكود صالح
    """
    try:
        print(f"[LICENSE] Activation request: {request.license_key[:20]}...")
        
        # ✅ التحقق من صيغة الكود
        license_pattern = r'^DKH-(MONTH|YEAR)-[A-Z0-9]{8}-[A-Z0-9]{4}$'
        if not re.match(license_pattern, request.license_key):
            print(f"[LICENSE] Invalid format: {request.license_key}")
            return LicenseActivationResponse(
                success=False,
                message="Invalid license key format",
                is_valid=False
            )
        
        # ✅ التحقق من عدم وجود الكود مسبقاً
        with db.get_connection() as conn:
            cursor = conn.cursor()
            
            # Check if license already exists
            cursor.execute(
                "SELECT id, is_used, user_id FROM license_codes WHERE code = ?",
                (request.license_key,)
            )
            existing = cursor.fetchone()
            
            if existing:
                license_id, is_used, existing_user_id = existing
                if is_used:
                    print(f"[LICENSE] Already used: {request.license_key}")
                    return LicenseActivationResponse(
                        success=False,
                        message="License key already activated",
                        license_key=request.license_key,
                        is_valid=False
                    )
            
            # ✅ حفظ الكود في قاعدة البيانات
            # Calculate expiry date based on plan
            now = datetime.now()
            if request.plan_type == 'yearly':
                expires_at = now + timedelta(days=365)
            else:
                expires_at = now + timedelta(days=30)
            
            # Insert or update license code
            cursor.execute("""
                INSERT OR REPLACE INTO license_codes 
                (code, plan_type, order_id, user_email, is_used, created_at, expires_at, client_id)
                VALUES (?, ?, ?, ?, 0, ?, ?, ?)
            """, (
                request.license_key,
                request.plan_type,
                request.order_id,
                request.user_email,
                now.isoformat(),
                expires_at.isoformat(),
                request.client_id[:20]  # Store partial client_id for verification
            ))
            
            # Log the event
            cursor.execute("""
                INSERT INTO license_activations 
                (license_key, plan_type, order_id, user_email, timestamp, status, ip_address)
                VALUES (?, ?, ?, ?, ?, 'pending', ?)
            """, (
                request.license_key,
                request.plan_type,
                request.order_id,
                request.user_email,
                now.isoformat(),
                "web_payment"
            ))
            
            conn.commit()
        
        print(f"[LICENSE] Saved successfully: {request.license_key}")
        
        return LicenseActivationResponse(
            success=True,
            message="License key activated and saved successfully",
            license_key=request.license_key,
            is_valid=True
        )
        
    except Exception as e:
        print(f"[LICENSE] Activation error: {e}")
        return LicenseActivationResponse(
            success=False,
            message=f"Server error: {str(e)}",
            is_valid=False
        )


@app.get("/api/verify-license/{license_key}")
def verify_license(license_key: str):
    """
    التحقق من صلاحية كود الاشتراك
    
    يُستدعى من:
        - اللانشر عند إدخال الكود
    """
    try:
        # Sanitize input
        license_key = license_key.strip().upper()
        
        # Validate format
        license_pattern = r'^DKH-(MONTH|YEAR)-[A-Z0-9]{8}-[A-Z0-9]{4}$'
        if not re.match(license_pattern, license_key):
            return {"valid": False, "message": "Invalid format"}
        
        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT plan_type, is_used, expires_at FROM license_codes WHERE code = ?",
                (license_key,)
            )
            result = cursor.fetchone()
            
            if not result:
                return {"valid": False, "message": "License not found"}
            
            plan_type, is_used, expires_at = result
            
            # Check expiry
            if expires_at:
                expiry_date = datetime.fromisoformat(expires_at)
                if datetime.now() > expiry_date:
                    return {"valid": False, "message": "License expired", "expired": True}
            
            return {
                "valid": True,
                "plan_type": plan_type,
                "is_used": bool(is_used),
                "expires_at": expires_at,
                "message": "License is valid"
            }
            
    except Exception as e:
        print(f"[LICENSE] Verification error: {e}")
        return {"valid": False, "message": "Server error"}


# ========== Admin Endpoints ==========

@app.get("/admin/stats")
def get_stats(api_key: str = Depends(verify_api_key)):
    """إحصائيات للإدارة"""
    with db.get_connection() as conn:
        cursor = conn.cursor()
        
        # عدد الاشتراكات النشطة
        cursor.execute("SELECT COUNT(*) FROM subscriptions WHERE status = 'active'")
        active_count = cursor.fetchone()[0]
        
        # إجمالي الإيرادات
        cursor.execute("SELECT SUM(amount) FROM subscriptions WHERE status = 'active'")
        total_revenue = cursor.fetchone()[0] or 0
        
        # عدد webhook events
        cursor.execute("SELECT COUNT(*) FROM webhook_events WHERE processed = 0")
        pending_events = cursor.fetchone()[0]
        
        return {
            "active_subscriptions": active_count,
            "total_revenue_usd": total_revenue,
            "pending_webhook_events": pending_events,
            "timestamp": datetime.now().isoformat()
        }


# ========== License Verification Endpoint for Client ==========

class VerifyLicenseRequest(BaseModel):
    """طلب التحقق من كود التفعيل من اللانشر"""
    code: str
    user_id: str

class VerifyLicenseResponse(BaseModel):
    """رد التحقق من كود التفعيل"""
    valid: bool
    message: str
    plan_type: Optional[str] = None


@app.post("/api/verify-license", response_model=VerifyLicenseResponse)
def verify_license(request: VerifyLicenseRequest):
    """
    🔥 NEW: التحقق من كود التفعيل (يُستدعى من اللانcher)
    
    Args:
        code: كود التفعيل (DKH-MONTH-XXXX-XXXX أو DKH-YEAR-XXXX-XXXX)
        user_id: معرف المستخدم
    
    Returns:
        valid: هل الكود صالح
        message: وصف النتيجة
        plan_type: نوع الخطة (monthly/yearly) إذا كان صالحاً
    """
    try:
        code = request.code.strip().upper()
        user_id = sanitize_user_id(request.user_id)
        
        print(f"[VERIFY] Checking license: {code[:20]}... for user: {user_id[:20]}...")
        
        # ✅ التحقق من صيغة الكود
        license_pattern = r'^DKH-(MONTH|YEAR)-[A-Z0-9]{8}-[A-Z0-9]{4}$'
        if not re.match(license_pattern, code):
            return VerifyLicenseResponse(
                valid=False,
                message="Invalid license key format. Expected: DKH-MONTH-XXXX-XXXX or DKH-YEAR-XXXX-XXXX"
            )
        
        # ✅ البحث عن الكود في قاعدة البيانات
        with db.get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT id, plan_type, is_used, user_id, expires_at 
                FROM license_codes 
                WHERE code = ?
            """, (code,))
            
            row = cursor.fetchone()
            
            if not row:
                return VerifyLicenseResponse(
                    valid=False,
                    message="License key not found"
                )
            
            license_id, plan_type, is_used, existing_user_id, expires_at = row
            
            # ✅ التحقق من عدم استخدام الكود مسبقاً
            if is_used:
                if existing_user_id == user_id:
                    return VerifyLicenseResponse(
                        valid=True,
                        message="License already activated for this user",
                        plan_type=plan_type
                    )
                else:
                    return VerifyLicenseResponse(
                        valid=False,
                        message="License key already used by another user"
                    )
            
            # ✅ التحقق من عدم انتهاء الصلاحية
            if expires_at:
                expires = datetime.fromisoformat(expires_at)
                if datetime.now() > expires:
                    return VerifyLicenseResponse(
                        valid=False,
                        message="License key has expired"
                    )
            
            # ✅ تفعيل الكود لهذا المستخدم
            now = datetime.now().isoformat()
            cursor.execute("""
                UPDATE license_codes 
                SET is_used = 1, user_id = ?, used_at = ?
                WHERE id = ?
            """, (user_id, now, license_id))
            conn.commit()
            
            print(f"[VERIFY] License activated: {code} -> user: {user_id}, plan: {plan_type}")
            
            return VerifyLicenseResponse(
                valid=True,
                message="License activated successfully",
                plan_type=plan_type
            )
    
    except Exception as e:
        print(f"[VERIFY] Error: {e}")
        return VerifyLicenseResponse(
            valid=False,
            message=f"Error verifying license: {str(e)}"
        )


# ========== Run Server ==========
if __name__ == "__main__":
    import uvicorn
    
    print("="*60)
    print("🔐 Dakhira Pro Webhook Server")
    print("="*60)
    print(f"Database: {DATABASE_PATH}")
    print(f"PayPal Webhook ID: {PAYPAL_WEBHOOK_ID[:20]}..." if PAYPAL_WEBHOOK_ID else "⚠️ Not set!")
    print(f"PayPal Client ID: {os.getenv('PAYPAL_CLIENT_ID', '')[:20]}..." if os.getenv('PAYPAL_CLIENT_ID') else "⚠️ Not set!")
    print(f"PayPal Mode: {'Sandbox' if os.getenv('PAYPAL_SANDBOX', 'false').lower() == 'true' else 'Production'}")
    print("="*60)
    
    uvicorn.run(app, host="0.0.0.0", port=8000)
