#!/usr/bin/env python3
"""
生成卡密工具 - 本地测试用
"""
import requests
import sys

SERVER_URL = "http://chahaoma.xyz:8902"
ADMIN_PASSWORD = "admin123"

def gen_card(count=1, days=30):
    """生成卡密"""
    url = f"{SERVER_URL}/api/genCard"
    params = {
        "password": ADMIN_PASSWORD,
        "count": count,
        "expireDays": days
    }
    
    try:
        resp = requests.get(url, params=params, timeout=5)
        data = resp.json()
        
        if data.get("ok"):
            print(f"✅ 成功生成 {count} 个卡密（有效期 {days} 天）：")
            print("=" * 50)
            for card in data.get("cards", []):
                print(f"卡密: {card}")
            print("=" * 50)
            print(f"\n激活地址: {SERVER_URL}")
        else:
            print(f"❌ 失败: {data.get('msg', '未知错误')}")
    except Exception as e:
        print(f"❌ 请求失败: {e}")
        print(f"请确认服务端已启动: python server.py")

if __name__ == "__main__":
    # 默认生成1个30天的卡密
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    days = int(sys.argv[2]) if len(sys.argv) > 2 else 30
    gen_card(count, days)
