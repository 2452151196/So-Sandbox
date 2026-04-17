/**
 * DTZC - 极简版本
 * 就返回一个加密字符串，客户端解密后使用
 */

function onRequest(request, response, modules) {
    const { deviceId, timestamp, sign } = request.body || {};
    
    // 简单签名验证
    const secret = 'dtzc-key-2024';
    const expect = modules.oCrypto.md5(deviceId + timestamp + secret).substring(0, 16);
    
    if (sign !== expect) {
        response.end(JSON.stringify({ ok: false }));
        return;
    }
    
    // 查是否授权
    const oData = modules.oData;
    oData.find({
        table: 'LicensedDevices',
        where: { deviceId: deviceId }
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
        
        // ========== 核心：生成加密字符串 ==========
        // 这个字符串就是功能开关密钥
        const key = generateKey(deviceId, device.vip);
        
        response.end(JSON.stringify({
            ok: true,
            // 加密后的密钥（客户端用固定算法解密）
            data: encrypt(key, deviceId)
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
 * 简单XOR加密
 */
function encrypt(text, key) {
    let result = '';
    for (let i = 0; i < text.length; i++) {
        result += String.fromCharCode(
            text.charCodeAt(i) ^ key.charCodeAt(i % key.length)
        );
    }
    return Buffer.from(result).toString('base64');
}
