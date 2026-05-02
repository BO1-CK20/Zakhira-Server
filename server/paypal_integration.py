"""
PayPal REST API Integration - Server-Side
نظام PayPal آمن - إنشاء طلبات من السيرفر (الطريقة الآمنة)

Security Features:
- Client-side: فقط Client ID (آمن للنشر)
- Server-side: Client Secret (مخفي تماماً)
- إنشاء الطلبات من السيرفر (Server-side order creation)
- عدم إرسال المبالغ من المتصفح (مكافحة التلاعب)

API Endpoints:
    POST /api/create-order          ← إنشاء طلب دفع
    POST /api/capture-order/{id}    ← تأكيد استلام الدفع

Author: Professional Secure Implementation
"""

import os
import base64
import requests
from typing import Dict, Optional, Any
from fastapi import HTTPException


class PayPalIntegration:
    """
    نظام PayPal آمن - Server-Side Integration
    
    Workflow:
        1. Frontend يرسل: user_id + plan_type
        2. Backend ينشئ Order (مع المبلغ الصحيح)
        3. Frontend يعرض PayPal button بالـ Order ID
        4. بعد الدفع، Backend يتحقق ويفعل الاشتراك
    """
    
    def __init__(self):
        # ⚠️ NEVER hardcode credentials - use environment variables
        self.client_id = os.getenv("PAYPAL_CLIENT_ID", "")
        self.client_secret = os.getenv("PAYPAL_CLIENT_SECRET", "")
        
        # URLs
        self.base_url = "https://api-m.paypal.com"  # Production
        if os.getenv("PAYPAL_SANDBOX", "false").lower() == "true":
            self.base_url = "https://api-m.sandbox.paypal.com"
        
        self.access_token: Optional[str] = None
    
    def _get_access_token(self) -> str:
        """
        الحصول على Access Token (يتجدد تلقائياً)
        """
        if not self.client_id or not self.client_secret:
            raise ValueError("PayPal credentials not configured!")
        
        auth = base64.b64encode(
            f"{self.client_id}:{self.client_secret}".encode()
        ).decode()
        
        headers = {
            "Authorization": f"Basic {auth}",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        
        data = {
            "grant_type": "client_credentials"
        }
        
        response = requests.post(
            f"{self.base_url}/v1/oauth2/token",
            headers=headers,
            data=data,
            timeout=30
        )
        
        if response.status_code != 200:
            raise HTTPException(
                status_code=500,
                detail=f"PayPal auth failed: {response.text}"
            )
        
        result = response.json()
        return result["access_token"]
    
    def create_order(self, user_id: str, plan_type: str) -> Dict[str, Any]:
        """
        إنشاء طلب دفع (Order) من السيرفر
        
        الأمان: المبلغ يُحدد هنا في السيرفر، ليس من المتصفح!
        """
        # الحصول على المبلغ من السيرvoir (مكافحة التلاعب)
        amounts = {
            "monthly": {"value": "5.33", "currency": "USD"},
            "yearly": {"value": "39.47", "currency": "USD"},
            "season": {"value": "1.00", "currency": "USD"}
        }
        
        if plan_type not in amounts:
            raise HTTPException(status_code=400, detail="Invalid plan type")
        
        amount = amounts[plan_type]
        
        # الحصول على access token
        access_token = self._get_access_token()
        
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        }
        
        payload = {
            "intent": "CAPTURE",
            "purchase_units": [
                {
                    "amount": amount,
                    "description": f"Dakhira Pro - {plan_type.title()} Subscription",
                    "custom_id": f"{user_id}_{plan_type}",  # مهم: يربط الطلب بالمستخدم
                    "invoice_id": f"DAKHIRA_{user_id}_{int(__import__('time').time())}",
                    "soft_descriptor": "DakhiraPro"
                }
            ],
            "application_context": {
                "brand_name": "Dakhira Pro",
                "locale": "ar-SA",
                "landing_page": "BILLING",  # أو "LOGIN"
                "shipping_preference": "NO_SHIPPING",
                "user_action": "PAY_NOW",
                "return_url": "https://zakhira-pro.carrd.co/success",
                "cancel_url": "https://zakhira-pro.carrd.co/cancel"
            }
        }
        
        response = requests.post(
            f"{self.base_url}/v2/checkout/orders",
            headers=headers,
            json=payload,
            timeout=30
        )
        
        if response.status_code not in [200, 201]:
            raise HTTPException(
                status_code=500,
                detail=f"PayPal order creation failed: {response.text}"
            )
        
        result = response.json()
        
        return {
            "order_id": result["id"],
            "status": result["status"],
            "plan_type": plan_type,
            "amount": amount["value"],
            "currency": amount["currency"],
            "approval_url": next(
                (link["href"] for link in result.get("links", []) 
                 if link["rel"] == "approve"),
                None
            )
        }
    
    def capture_order(self, order_id: str) -> Dict[str, Any]:
        """
        تأكيد استلام الدفع (Capture)
        
        يُستدعى بعد أن يدفع الزبون بنجاح
        """
        access_token = self._get_access_token()
        
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        }
        
        response = requests.post(
            f"{self.base_url}/v2/checkout/orders/{order_id}/capture",
            headers=headers,
            timeout=30
        )
        
        if response.status_code not in [200, 201]:
            raise HTTPException(
                status_code=500,
                detail=f"PayPal capture failed: {response.text}"
            )
        
        result = response.json()
        
        # استخراج المعلومات المهمة
        purchase_unit = result.get("purchase_units", [{}])[0]
        payment = purchase_unit.get("payments", {}).get("captures", [{}])[0]
        
        return {
            "order_id": result["id"],
            "status": result["status"],  # COMPLETED
            "capture_id": payment.get("id"),
            "amount": payment.get("amount", {}).get("value"),
            "currency": payment.get("amount", {}).get("currency_code"),
            "payer_email": result.get("payer", {}).get("email_address"),
            "payer_id": result.get("payer", {}).get("payer_id"),
            "custom_id": purchase_unit.get("custom_id"),
            "create_time": result.get("create_time"),
            "receipt_id": payment.get("receipt_id")
        }
    
    def get_order_details(self, order_id: str) -> Dict[str, Any]:
        """
        الحصول على تفاصيل الطلب (للتحقق)
        """
        access_token = self._get_access_token()
        
        headers = {
            "Authorization": f"Bearer {access_token}"
        }
        
        response = requests.get(
            f"{self.base_url}/v2/checkout/orders/{order_id}",
            headers=headers,
            timeout=30
        )
        
        if response.status_code != 200:
            raise HTTPException(status_code=404, detail="Order not found")
        
        return response.json()
    
    def verify_payment_by_email(self, email: str, amount: float, 
                               days_back: int = 7) -> bool:
        """
        البحث عن دفع مُنجز عبر PayPal API
        
        يُستخدم للتحقق من الدفعات في حالة فشل Webhook
        """
        access_token = self._get_access_token()
        
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        }
        
        # البحث في transactions
        from datetime import datetime, timedelta
        start_date = (datetime.now() - timedelta(days=days_back)).strftime("%Y-%m-%dT%H:%M:%SZ")
        end_date = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
        
        params = {
            "start_date": start_date,
            "end_date": end_date,
            "transaction_status": "S",
            "fields": "all"
        }
        
        response = requests.get(
            f"{self.base_url}/v1/reporting/transactions",
            headers=headers,
            params=params,
            timeout=30
        )
        
        if response.status_code != 200:
            return False
        
        transactions = response.json().get("transaction_details", [])
        
        for tx in transactions:
            payer_info = tx.get("payer_info", {})
            tx_amount = tx.get("transaction_info", {}).get("transaction_amount", {}).get("value", "0")
            
            if payer_info.get("email_address") == email:
                if float(tx_amount) >= amount * 0.99:  # هامش 1% للـ fees
                    return True
        
        return False


# ========== Factory Function ==========

def get_paypal_integration() -> PayPalIntegration:
    """الحصول على instance من PayPal Integration"""
    return PayPalIntegration()
