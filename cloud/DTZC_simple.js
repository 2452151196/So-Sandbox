/**
 * DTZC - 极简版本
 * 就返回一个加密字符串，客户端解密后使用
 */

function onRequest(request, response, modules) {
    const crypto = require('crypto');
    const { deviceId, fingerprint, timestamp, sign } = request.body || {};
    
    // 使用设备指纹作为密钥
    const secret = 'dtzc-key-2024';
    const expect = crypto.createHash('md5').update(fingerprint + timestamp + secret).digest('hex').substring(0, 16);
    
    if (sign !== expect) {
        response.end(JSON.stringify({ ok: false }));
        return;
    }
    
    // 查是否授权
    const oData = modules.oData;
    oData.find({
        table: 'LicensedDevices',
        where: { deviceId: deviceId }  // 仍然用deviceId查询数据库
    }).then(function(data) {
        const result = JSON.parse(data);
        
        if (result.results.length === 0) {
            // 未授权：返回空或试用标记
            response.end(JSON.stringify({ 
                ok: false,
                trial: true 
            }));
            return;
        }
        
        const device = result.results[0];
        
        // 检查过期
        if (device.expireAt && device.expireAt < Date.now()) {
            response.end(JSON.stringify({ ok: false, expired: true }));
            return;
        }
        
        // ========== 核心：生成加密的必需数据 ==========
        // 使用设备指纹作为加密密钥
        const cloudData = {
            // 必需数据1: JNI_OnLoad字符串（加密）
            symbol: encrypt('JNI_OnLoad', fingerprint),
            
            // 必需数据2: MAX_CAPTURED数组大小（加密）
            maxCapture: encrypt('256', fingerprint),  // 默认256
            
            // 必需数据3: page_size（加密）
            pageSize: encrypt('4096', fingerprint)   // 默认4096
        };
        
        response.end(JSON.stringify({
            ok: true,
            data: cloudData
        }));
        
    }).catch(function(err) {
        response.end(JSON.stringify({ ok: false }));
    });
}

/**
 * 生成密钥字符串
 * 格式：功能标志 + 过期时间 + 校验
 */
function generateKey(deviceId, isVip) {
    // 功能标志：D=动态注册, F=流程图, X=高级xref
    const flags = isVip ? 'DFX' : 'D';  // VIP全开，普通只开动态注册
    
    // 7天后过期
    const expire = Date.now() + 7 * 24 * 60 * 60 * 1000;
    
    // 校验码
    const check = modules.oCrypto.md5(flags + expire + deviceId).substring(0, 8);
    
    // 最终密钥：D|1234567890|a1b2c3d4
    return `${flags}|${expire}|${check}`;
}

/**
 * AES-256-CBC加密
 */
function encrypt(text, key) {
    const crypto = require('crypto');
    
    // 生成随机IV（16字节）
    const iv = crypto.randomBytes(16);
    
    // 生成随机盐（8字节）
    const salt = crypto.randomBytes(8);
    
    // 派生密钥：PBKDF2(key + salt, 10000次)
    const derivedKey = crypto.pbkdf2Sync(key + salt.toString('hex'), salt, 10000, 32, 'sha256');
    
    // AES-256-CBC加密
    const cipher = crypto.createCipheriv('aes-256-cbc', derivedKey, iv);
    let encrypted = cipher.update(text, 'utf8', 'binary');
    encrypted += cipher.final('binary');
    
    // 组合：salt(8) + iv(16) + ciphertext
    const combined = Buffer.concat([salt, iv, Buffer.from(encrypted, 'binary')]);
    
    // Base64编码
    return combined.toString('base64');
}
