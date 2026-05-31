const http = require('http');
const crypto = require('crypto');
const url = require('url');

const PORT = 8902;
const SECRET = 'dtzc-key-2024';

// 授权设备列表（可以改成数据库查询）
const LICENSED_DEVICES = {
    // 'device_id': { expireAt: 1735689600000, vip: true }
};

// AES-256-CBC加密
function encrypt(text, key) {
    const iv = crypto.randomBytes(16);
    const salt = crypto.randomBytes(8);
    const derivedKey = crypto.pbkdf2Sync(key + salt.toString('hex'), salt, 10000, 32, 'sha256');
    const cipher = crypto.createCipheriv('aes-256-cbc', derivedKey, iv);
    let encrypted = cipher.update(text, 'utf8', 'binary');
    encrypted += cipher.final('binary');
    const combined = Buffer.concat([salt, iv, Buffer.from(encrypted, 'binary')]);
    return combined.toString('base64');
}

const server = http.createServer((req, res) => {
    // CORS
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    
    if (req.method === 'OPTIONS') {
        res.writeHead(200);
        res.end();
        return;
    }

    const parsedUrl = url.parse(req.url, true);
    
    if (parsedUrl.pathname === '/api/DTZC') {
        // 获取参数（支持GET和POST）
        let params = parsedUrl.query;
        
        if (req.method === 'POST') {
            let body = '';
            req.on('data', chunk => { body += chunk; });
            req.on('end', () => {
                // 解析application/x-www-form-urlencoded
                if (body) {
                    body.split('&').forEach(pair => {
                        const [k, v] = pair.split('=');
                        params[decodeURIComponent(k)] = decodeURIComponent(v || '');
                    });
                }
                handleDTZC(params, res);
            });
        } else {
            handleDTZC(params, res);
        }
    } else {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'not found' }));
    }
});

function handleDTZC(params, res) {
    const { deviceId, fingerprint, timestamp, sign } = params;
    
    if (!fingerprint || !timestamp || !sign) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: false, msg: 'missing params' }));
        return;
    }
    
    // 签名验证
    const expect = crypto.createHash('md5')
        .update(fingerprint + timestamp + SECRET)
        .digest('hex').substring(0, 16);
    
    if (sign !== expect) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: false, msg: 'invalid sign' }));
        return;
    }
    
    // 防重放：5分钟内有效
    const now = Date.now();
    if (Math.abs(now - parseInt(timestamp)) > 5 * 60 * 1000) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: false, msg: 'expired request' }));
        return;
    }
    
    // 检查授权
    const device = LICENSED_DEVICES[deviceId];
    if (!device) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: false, trial: true }));
        return;
    }
    
    if (device.expireAt && device.expireAt < now) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: false, expired: true }));
        return;
    }
    
    // 生成加密数据
    const cloudData = {
        symbol: encrypt('JNI_OnLoad', fingerprint),
        maxCapture: encrypt('256', fingerprint),
        pageSize: encrypt('4096', fingerprint)
    };
    
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true, data: cloudData }));
}

server.listen(PORT, '0.0.0.0', () => {
    console.log(`DTZC server running on port ${PORT}`);
});
