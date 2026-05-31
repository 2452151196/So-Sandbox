#!/usr/bin/env python3
import http.server
import json
import hashlib
import os
import base64
import random
import urllib.parse
import socket
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from flowchart_config import get_branch_instructions, update_branch_instructions

PORT = 8902
SECRET = 'dtzc-key-2024'
# 使用脚本所在目录的绝对路径
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_FILE = os.path.join(SCRIPT_DIR, 'server_data.json')

# 管理密码
ADMIN_PASSWORD = 'admin123'

# 数据存储
LICENSED_DEVICES = {}
CARD_KEYS = {}  # 卡密系统: {card_key: {expireDays, used, deviceId, createTime}}

def load_data():
    global LICENSED_DEVICES, CARD_KEYS
    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE, 'r') as f:
                data = json.load(f)
                LICENSED_DEVICES = data.get('LICENSED_DEVICES', {})
                CARD_KEYS = data.get('CARD_KEYS', {})
        except:
            LICENSED_DEVICES = {}
            CARD_KEYS = {}

def save_data():
    data = {
        'LICENSED_DEVICES': LICENSED_DEVICES,
        'CARD_KEYS': CARD_KEYS
    }
    with open(DATA_FILE, 'w') as f:
        json.dump(data, f)

def encrypt(text, key):
    """AES-256-CBC加密"""
    salt = os.urandom(8)
    iv = os.urandom(16)
    
    # PBKDF2派生密钥
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=10000,
        backend=default_backend()
    )
    derived_key = kdf.derive((key + salt.hex()).encode())
    
    # AES-256-CBC加密
    cipher = Cipher(algorithms.AES(derived_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # PKCS7 padding
    data = text.encode('utf-8')
    pad_len = 16 - (len(data) % 16)
    data += bytes([pad_len] * pad_len)
    
    encrypted = encryptor.update(data) + encryptor.finalize()
    
    # 组合：salt(8) + iv(16) + ciphertext
    combined = salt + iv + encrypted
    return base64.b64encode(combined).decode()


class DTZCHandler(http.server.BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        try:
            self.connection.settimeout(15)
        except Exception:
            pass

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
    
    def do_GET(self):
        try:
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path == '/api/DTZC':
                params = urllib.parse.parse_qs(parsed.query)
                params = {k: v[0] for k, v in params.items()}
                self.handle_dtzc(params)
            elif parsed.path == '/api/addDevice':
                params = urllib.parse.parse_qs(parsed.query)
                params = {k: v[0] for k, v in params.items()}
                self.handle_add_device(params)
            elif parsed.path == '/api/genCard':
                params = urllib.parse.parse_qs(parsed.query)
                params = {k: v[0] for k, v in params.items()}
                self.handle_gen_card(params)
            elif parsed.path == '/api/verifyCard':
                params = urllib.parse.parse_qs(parsed.query)
                params = {k: v[0] for k, v in params.items()}
                self.handle_verify_card(params)
            elif parsed.path == '/api/checkDevice':
                params = urllib.parse.parse_qs(parsed.query)
                params = {k: v[0] for k, v in params.items()}
                self.handle_check_device(params)
            elif parsed.path == '/api/flowchart':
                params = urllib.parse.parse_qs(parsed.query)
                params = {k: v[0] for k, v in params.items()}
                self.handle_flowchart(params)
            elif parsed.path == '/api/flowchartConfig':
                self.handle_flowchart_config()
            else:
                self.send_error(404)
        except socket.timeout:
            try:
                self.send_error(408)
            except Exception:
                pass
        except Exception:
            try:
                self.send_error(500)
            except Exception:
                pass
    
    def do_POST(self):
        try:
            if self.path == '/api/DTZC':
                content_length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(content_length).decode('utf-8', errors='replace')
                params = {}
                if body:
                    for pair in body.split('&'):
                        if '=' in pair:
                            k, v = pair.split('=', 1)
                            params[urllib.parse.unquote(k)] = urllib.parse.unquote(v)
                self.handle_dtzc(params)
            elif self.path == '/api/addDevice':
                content_length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(content_length).decode('utf-8', errors='replace')
                params = {}
                if body:
                    for pair in body.split('&'):
                        if '=' in pair:
                            k, v = pair.split('=', 1)
                            params[urllib.parse.unquote(k)] = urllib.parse.unquote(v)
                self.handle_add_device(params)
            elif self.path == '/api/genCard':
                content_length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(content_length).decode('utf-8', errors='replace')
                params = {}
                if body:
                    for pair in body.split('&'):
                        if '=' in pair:
                            k, v = pair.split('=', 1)
                            params[urllib.parse.unquote(k)] = urllib.parse.unquote(v)
                self.handle_gen_card(params)
            elif self.path == '/api/verifyCard':
                content_length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(content_length).decode('utf-8', errors='replace')
                params = {}
                if body:
                    for pair in body.split('&'):
                        if '=' in pair:
                            k, v = pair.split('=', 1)
                            params[urllib.parse.unquote(k)] = urllib.parse.unquote(v)
                self.handle_verify_card(params)
            else:
                self.send_error(404)
        except socket.timeout:
            try:
                self.send_error(408)
            except Exception:
                pass
        except Exception:
            try:
                self.send_error(500)
            except Exception:
                pass
    
    def handle_add_device(self, params):
        device_id = params.get('deviceId', '')
        password = params.get('password', '')
        expire_days = params.get('expireDays', '30')
        
        if password != ADMIN_PASSWORD:
            self.send_json({'ok': False, 'msg': 'invalid password'})
            return
        
        if not device_id:
            self.send_json({'ok': False, 'msg': 'missing deviceId'})
            return
        
        # 添加设备授权（默认30天过期）
        now = int(datetime.now().timestamp() * 1000)
        expire_at = now + int(expire_days) * 24 * 60 * 60 * 1000
        
        LICENSED_DEVICES[device_id] = {
            'expireAt': expire_at,
            'vip': True
        }
        
        save_data()
        print(f"[ADD DEVICE] {device_id} -> expires at {datetime.fromtimestamp(expire_at/1000)}")
        self.send_json({'ok': True, 'expireAt': expire_at})
    
    def handle_gen_card(self, params):
        password = params.get('password', '')
        count = int(params.get('count', '1'))
        expire_days = int(params.get('expireDays', '30'))
        
        if password != ADMIN_PASSWORD:
            self.send_json({'ok': False, 'msg': 'invalid password'})
            return
        
        cards = []
        for _ in range(count):
            # 生成16位卡密: 4位-4位-4位-4位
            parts = [''.join(random.choices('ABCDEFGHJKLMNPQRSTUVWXYZ23456789', k=4)) for _ in range(4)]
            card_key = '-'.join(parts)
            CARD_KEYS[card_key] = {
                'expireDays': expire_days,
                'used': False,
                'deviceId': None,
                'createTime': int(datetime.now().timestamp() * 1000)
            }
            cards.append(card_key)
        
        save_data()
        print(f"[GEN CARD] Generated {count} cards, {expire_days} days each")
        self.send_json({'ok': True, 'cards': cards})
    
    def handle_verify_card(self, params):
        card_key = params.get('cardKey', '').strip().upper()
        device_id = params.get('deviceId', '')
        fingerprint = params.get('fingerprint', '')
        
        if not card_key or not device_id:
            self.send_json({'ok': False, 'msg': 'missing params'}, fingerprint)
            return
        
        # 检查卡密
        card = CARD_KEYS.get(card_key)
        if not card:
            self.send_json({'ok': False, 'msg': 'invalid card'}, fingerprint)
            return
        
        if card['used']:
            self.send_json({'ok': False, 'msg': 'card already used'}, fingerprint)
            return
        
        # 使用卡密，授权设备
        now = int(datetime.now().timestamp() * 1000)
        expire_at = now + card['expireDays'] * 24 * 60 * 60 * 1000
        
        # 生成设备会话密钥（用于后续通信加密）
        session_key = hashlib.sha256(os.urandom(32)).hexdigest()[:32]
        
        LICENSED_DEVICES[device_id] = {
            'expireAt': expire_at,
            'vip': True,
            'cardKey': card_key,
            'sessionKey': session_key
        }
        
        # 标记卡密已使用
        card['used'] = True
        card['deviceId'] = device_id
        card['useTime'] = now
        
        save_data()
        print(f"[VERIFY CARD] {card_key} -> {device_id}, expires at {datetime.fromtimestamp(expire_at/1000)}")
        self.send_json({'ok': True, 'expireAt': expire_at, 'days': card['expireDays'], 'sessionKey': session_key}, fingerprint)
    
    def handle_check_device(self, params):
        device_id = params.get('deviceId', '')
        fingerprint = params.get('fingerprint', '')
        
        if not device_id:
            self.send_json({'ok': False, 'msg': 'missing deviceId'}, fingerprint)
            return
        
        device = LICENSED_DEVICES.get(device_id)
        if not device:
            self.send_json({'ok': False, 'msg': 'device not authorized'}, fingerprint)
            return
        
        now = int(datetime.now().timestamp() * 1000)
        if device.get('expireAt', 0) < now:
            self.send_json({'ok': False, 'msg': 'license expired', 'expired': True}, fingerprint)
            return
        
        self.send_json({
            'ok': True, 
            'msg': 'device authorized',
            'expireAt': device.get('expireAt'),
            'vip': device.get('vip', True)
        }, fingerprint)
    
    def handle_dtzc(self, params):
        device_id = params.get('deviceId', '')
        fingerprint = params.get('fingerprint', '')
        timestamp = params.get('timestamp', '')
        sign = params.get('sign', '')
        
        if not fingerprint or not timestamp or not sign:
            self.send_json({'ok': False, 'msg': 'missing params'})
            return
        
        # 签名验证
        expect = hashlib.md5(
            (fingerprint + timestamp + SECRET).encode()
        ).hexdigest()[:16]
        
        print(f"[SIGN] recv={sign}, expect={expect}, fp={fingerprint[:20]}..., ts={timestamp}")
        
        if sign != expect:
            self.send_json({'ok': False, 'msg': 'invalid sign'})
            return
        
        # 防重放：5分钟内有效
        now = int(datetime.now().timestamp() * 1000)
        if abs(now - int(timestamp)) > 5 * 60 * 1000:
            print(f"[EXPIRED] now={now}, ts={timestamp}, diff={abs(now - int(timestamp))}")
            self.send_json({'ok': False, 'msg': 'expired request'})
            return
        
        # 检查授权
        device = LICENSED_DEVICES.get(device_id)
        print(f"[AUTH] device_id={device_id}, found={device is not None}")
        if not device:
            self.send_json({'ok': False, 'trial': True})
            return
        
        if device.get('expireAt', 0) < now:
            print(f"[EXPIRED DEVICE] expireAt={device.get('expireAt')}, now={now}")
            self.send_json({'ok': False, 'expired': True})
            return
        
        # 生成加密数据
        cloud_data = {
            'symbol': encrypt('JNI_OnLoad', fingerprint),
            'maxCapture': encrypt('256', fingerprint),
            'pageSize': encrypt('4096', fingerprint)
        }
        
        print(f"[ENCRYPT] Generated data for {device_id}")
        # DTZC 数据字段已加密，外层不加密（客户端直接解析）
        self.send_json({'ok': True, 'data': cloud_data})
    
    def handle_flowchart(self, params):
        """生成函数流程图数据（基本块和边关系）"""
        so_path = params.get('soPath', '')
        func_addr = int(params.get('funcAddr', '0'), 16) if params.get('funcAddr', '').startswith('0x') else int(params.get('funcAddr', '0'))
        func_size = int(params.get('funcSize', '0'))
        fingerprint = params.get('fingerprint', '')
        device_id = params.get('deviceId', '')
        
        # 检查授权
        device = LICENSED_DEVICES.get(device_id)
        if not device or device.get('expireAt', 0) < int(datetime.now().timestamp() * 1000):
            self.send_json({'ok': False, 'msg': 'not authorized'}, fingerprint)
            return
        
        if not CAPSTONE_AVAILABLE:
            self.send_json({'ok': False, 'msg': 'capstone not available'}, fingerprint)
            return
        
        if not os.path.exists(so_path):
            self.send_json({'ok': False, 'msg': 'so file not found'}, fingerprint)
            return
        
        try:
            blocks = generate_flowchart_data(so_path, func_addr, func_size)
            self.send_json({'ok': True, 'blocks': blocks}, fingerprint)
        except Exception as e:
            print(f"[FLOWCHART ERROR] {e}")
            self.send_json({'ok': False, 'msg': str(e)}, fingerprint)
    
    def handle_flowchart_config(self):
        """获取流程图分支指令配置（加密返回）"""
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        device_id = params.get('deviceId', [''])[0]
        fingerprint = params.get('fingerprint', [''])[0]
        
        print(f"[FLOWCHART CONFIG] device_id={device_id}, fingerprint={fingerprint[:20]}...")
        print(f"[FLOWCHART CONFIG] LICENSED_DEVICES={list(LICENSED_DEVICES.keys())}")
        
        # 验证设备授权
        device = LICENSED_DEVICES.get(device_id)
        print(f"[FLOWCHART CONFIG] device found={device is not None}")
        if not device or device.get('expireAt', 0) < int(datetime.now().timestamp() * 1000):
            print(f"[FLOWCHART CONFIG] not authorized")
            self.send_json({'ok': False, 'msg': 'not authorized'}, fingerprint)
            return
        
        config = get_branch_instructions()
        print(f"[FLOWCHART CONFIG] Sending config with {len(config.get('branch_insns', []))} branch insns")
        self.send_json({'ok': True, 'config': config}, fingerprint)
    
    def handle_update_flowchart_config(self):
        """更新流程图分支指令配置（需要管理员密码）"""
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8')
        params = json.loads(body) if body else {}
        
        # 验证管理员密码
        if params.get('adminPass') != ADMIN_PASSWORD:
            self.send_response(403)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'ok': False, 'msg': 'unauthorized'}).encode())
            return
        
        new_branch = params.get('branch_insns', [])
        new_cond = params.get('cond_branch_insns', [])
        
        if update_branch_instructions(new_branch, new_cond):
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps({'ok': True, 'msg': 'config updated'}).encode())
        else:
            self.send_response(500)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'ok': False, 'msg': 'update failed'}).encode())
    
    def send_json(self, data, fingerprint=None):
        """发送JSON响应，如有指纹则加密"""
        if fingerprint:
            payload = json.dumps(data)
            encrypted = encrypt(payload, fingerprint)
            data = {'encrypted': True, 'payload': encrypted}

        raw = json.dumps(data).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Content-Length', str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)
    
    def log_message(self, format, *args):
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {args[0]}")



if __name__ == '__main__':
    load_data()
    print(f'Loaded {len(LICENSED_DEVICES)} authorized devices', flush=True)
    class _Server(http.server.ThreadingHTTPServer):
        daemon_threads = True
        allow_reuse_address = True

    server = _Server(('0.0.0.0', PORT), DTZCHandler)
    print(f'DTZC server running on port {PORT}', flush=True)
    print(f'Cloud URL: http://chahaoma.xyz:{PORT}/api/checkDevice?deviceId=test', flush=True)
    server.serve_forever()
