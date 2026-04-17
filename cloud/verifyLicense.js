/**
 * 许可证验证云函数
 * LeanCloud / AVOS Cloud 格式
 */

// 模拟数据库（实际应接LeanCloud数据库）
const licensedDevices = new Set([
    // 已付费设备的Device ID哈希
    'a1b2c3d4e5f6789...', 
    '9876543210fedcba...'
]);

// 服务器密钥（定期轮换）
const SERVER_KEY = 'your-rotating-key-2024';

function onRequest(request, response, modules) {
    const { deviceId, timestamp, sign, feature } = request.params;
    
    // ========== 1. 参数校验 ==========
    if (!deviceId || !timestamp || !sign || !feature) {
        response.error({
            code: 400,
            message: '缺少必要参数',
            authorized: false
        });
        return;
    }
    
    // ========== 2. 防重放攻击 ==========
    const now = Date.now();
    const clientTime = parseInt(timestamp);
    
    // 时间戳必须在 ±5分钟 范围内
    if (Math.abs(now - clientTime) > 300000) {
        response.error({
            code: 401,
            message: '请求已过期',
            authorized: false
        });
        return;
    }
    
    // 检查是否已使用过（需要Redis/数据库，这里简化）
    // TODO: 查Redis看timestamp+deviceId是否已存在
    
    // ========== 3. 签名验证 ==========
    // 客户端签名算法：SHA256(deviceId + timestamp + feature + secret)
    const crypto = modules.crypto;
    const expectedSign = crypto.hexMD5(  // 或SHA256
        deviceId + timestamp + feature + SERVER_KEY
    );
    
    if (sign !== expectedSign) {
        // 记录可疑请求（防破解尝试）
        console.warn(`[可疑] 签名错误: ${deviceId}, IP: ${request.meta.remoteAddress}`);
        
        response.error({
            code: 403,
            message: '签名验证失败',
            authorized: false
        });
        return;
    }
    
    // ========== 4. 设备授权检查 ==========
    const deviceHash = crypto.hexMD5(deviceId + SERVER_KEY);
    const isLicensed = licensedDevices.has(deviceHash);
    
    if (!isLicensed) {
        // 未付费设备
        response.success({
            code: 402,
            message: '设备未授权',
            authorized: false,
            // 可以返回试用信息
            trial: {
                enabled: true,
                daysLeft: 3,
                limitedFeatures: ['dynamic_register']  // 限制功能
            }
        });
        return;
    }
    
    // ========== 5. 生成动态密钥 ==========
    // 密钥包含：设备ID + 功能 + 过期时间 + 随机盐
    const expireTime = now + 7 * 24 * 60 * 60 * 1000;  // 7天有效期
    const salt = Math.random().toString(36).substring(2, 15);
    
    const licenseKey = crypto.hexMD5(
        deviceId + feature + expireTime + salt + SERVER_KEY
    );
    
    // 加密返回（防止中间人抓取密钥）
    const encryptedKey = encryptResponse(licenseKey, deviceId);
    
    // ========== 6. 记录日志 ==========
    console.log(`[授权] device: ${deviceId}, feature: ${feature}, expire: ${new Date(expireTime)}`);
    
    // ========== 7. 返回结果 ==========
    response.success({
        code: 200,
        message: '授权成功',
        authorized: true,
        
        // 加密的许可证密钥
        license: encryptedKey,
        
        // 过期时间戳
        expireAt: expireTime,
        
        // 允许的功能列表
        features: [
            'dynamic_register',
            'flowchart',
            'xref_advanced'
        ],
        
        // 下次刷新时间（建议24小时后）
        refreshAt: now + 24 * 60 * 60 * 1000
    });
}

/**
 * 简单XOR加密响应（防直接抓包）
 * 客户端需相同算法解密
 */
function encryptResponse(data, key) {
    let result = '';
    const keyBytes = key.split('').map(c => c.charCodeAt(0));
    
    for (let i = 0; i < data.length; i++) {
        const charCode = data.charCodeAt(i);
        const keyByte = keyBytes[i % keyBytes.length];
        result += String.fromCharCode(charCode ^ keyByte);
    }
    
    // Base64编码便于传输
    return Buffer.from(result).toString('base64');
}

/**
 * 密钥轮换任务（每天定时执行）
 * 需要另一个定时任务云函数调用
 */
function rotateKey() {
    // 生成新密钥
    const newKey = 'your-rotating-key-' + Date.now();
    // 保存到LeanCloud配置
    // 旧密钥保留24小时用于平滑过渡
    console.log('密钥已轮换:', new Date());
}

// 导出（LeanCloud需要）
module.exports = { onRequest, rotateKey };
