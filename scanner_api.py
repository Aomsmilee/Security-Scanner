import hashlib
import base64
import requests

# =========================================================
# ส่วนฟังก์ชันพื้นฐาน (Basic Utilities)
# =========================================================

def calculate_hash(file_bytes):
    """คำนวณค่า Hash (ลายนิ้วมือดิจิทัล) ของไฟล์ด้วยอัลกอริทึม SHA-256"""
    sha256_hash = hashlib.sha256()
    sha256_hash.update(file_bytes)
    return sha256_hash.hexdigest()

def verify_hash(file_bytes, original_hash):
    """ตรวจสอบความถูกต้องของไฟล์ โดยนำ Hash ที่คำนวณใหม่ไปเทียบกับ Hash ต้นฉบับ"""
    file_hash = calculate_hash(file_bytes)
    original_hash = original_hash.strip().lower()
    return file_hash.lower() == original_hash, file_hash

# =========================================================
# Engine: VirusTotal API (Main Scanner)
# =========================================================

def get_analysis_stats(response):
    """
    อ่านผลลัพธ์ (JSON) จาก VirusTotal และสรุปผล
    """
    if response.status_code == 200:
        data = response.json()
        stats = data['data']['attributes']['last_analysis_stats']
        malicious = stats['malicious']
        
        # ถ้าสแกนเจอว่าเป็นอันตรายแม้แต่ตัวเดียว
        if malicious > 0:
            return f"❌ อันตราย! พบมัลแวร์ {malicious} รายการ"
        else:
            return "✅ ปลอดภัย (ไม่พบสิ่งผิดปกติในฐานข้อมูล)"
            
    elif response.status_code == 404:
        # ไม่พบข้อมูลในระบบ VT (ไฟล์อาจจะใหม่เกินไป หรือไม่มีใครเคยรายงานว่าติดไวรัส)
        return "⚪ ไม่พบข้อมูลในระบบ (อาจเป็นไฟล์ใหม่ หรือ ยังไม่ถูกรายงานในฐานข้อมูล)"
        
    else:
        return f"⚠️ ระบบขัดข้อง (Error: {response.status_code})"

def check_virustotal_file(file_hash, api_key):
    """ส่งค่า Hash ของไฟล์ไปตรวจสอบกับฐานข้อมูล VirusTotal"""
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}
    response = requests.get(url, headers=headers)
    return get_analysis_stats(response)

def check_virustotal_url(target_url, api_key):
    """ส่ง URL ไปตรวจสอบกับฐานข้อมูล VirusTotal"""
    # VT บังคับให้แปลง URL เป็น Base64 ก่อน
    url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
    url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"x-apikey": api_key}
    response = requests.get(url, headers=headers)
    return get_analysis_stats(response)
