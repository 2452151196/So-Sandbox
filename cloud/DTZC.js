/**
 * DTZC
 * 动态注册功能验证与密钥下发
 */

const crypto = require('crypto');

// 服务器配置（实际应从环境变量读取）
const SERVER_SECRET = process.env.SERVER_SECRET || 'dtzc-2024-secret-key';
const KEY_VERSION = 'v2';

/**
 * DTZC
 * 验证设备授权并返回动态解密密钥
 * 
 * @param {Object} request - 请求对象
 * @param {Object} response - 响应对象
 * @param {Object} modules - 平台模块
 */
function DTZC(request, response, modules) {
    const { deviceId, timestamp, sign, version } = request.params;
    
    // ========== 参数校验 ==========
    if (!deviceId || !timestamp || !sign) {
        return response.error({
            code: 400,
            msg: '缺少必要参数',
            ok: false
        });
    }
    
    // ========== 时间校验（防重放）==========
    const now = Date.now();
    const ts = parseInt(timestamp);
    
    if (isNaN(ts) || Math.abs(now - ts) > 300000) {
        return response.error({
            code: 401,
            msg: '请求超时',
            ok: false
        });
    }
    
    // ========== 签名验证 ==========
    const payload = `${deviceId}:${timestamp}:${version || '1.0'}:${SERVER_SECRET}`;
    const expectSign = crypto.createHash('sha256').update(payload).digest('hex').substring(0, 16);
    
    if (sign !== expectSign) {
        console.warn(`[DTZC] 签名错误: ${deviceId}, IP: ${request.meta?.remoteAddress}`);
        return response.error({
            code: 403,
            msg: '验证失败',
            ok: false
        });
    }
    
    // ========== 设备授权查询 ==========
    const AV = modules.AV;
    const query = new AV.Query('LicensedDevices');
    query.equalTo('deviceId', deviceId);
    
    query.first().then(device => {
        if (!device) {
            // 未付费，返回试用
            return response.success({
                code: 402,
                msg: '未授权',
                ok: false,
                trial: {
                    enable: true,
                    leftDays: 3,
                    limited: true
                }
            });
        }
        
        // 检查是否过期
        const expireAt = device.get('expireAt');
        if (expireAt && expireAt < now) {
            return response.success({
                code: 402,
                msg: '授权已过期',
                ok: false,
                renew: true
            });
        }
        
        // ========== 生成动态密钥 ==========
        const expireTime = now + 7 * 24 * 60 * 60 * 1000;  // 7天
        const salt = crypto.randomBytes(8).toString('hex');
        
        // 密钥结构: SHA256(deviceId + expireTime + salt + secret)
        const keyRaw = `${deviceId}:${expireTime}:${salt}:${SERVER_SECRET}`;
        const licenseKey = crypto.createHash('sha256').update(keyRaw).digest('hex');
        
        // XOR加密后返回
        const encryptedKey = xorEncrypt(licenseKey, deviceId);
        
        // 记录日志
        console.log(`[DTZC] 授权成功: ${deviceId}, 过期: ${new Date(expireTime)}`);
        
        return response.success({
            code: 200,
            msg: '成功',
            ok: true,
            
            // 加密的许可证
            key: encryptedKey,
            
            // 元数据（客户端不解密，透传到SO层）
            meta: {
                deviceId: deviceId,
                expireAt: expireTime,
                version: KEY_VERSION,
                salt: salt
            },
            
            // 功能开关
            features: {
                dynamicRegister: true,
                flowchart: device.get('vip') || false,
                xrefAdvanced: device.get('vip') || false
            },
            
            // 下次刷新时间
            refresh: now + 24 * 60 * 60 * 1000
        });
        
    }).catch(err => {
        console.error('[DTZC] 查询失败:', err);
        return response.error({
            code: 500,
            msg: '服务器错误',
            ok: false
        });
    });
}

/**
 * XOR加密
 */
function xorEncrypt(data, key) {
    let result = '';
    for (let i = 0; i < data.length; i++) {
        const charCode = data.charCodeAt(i);
        const keyCode = key.charCodeAt(i % key.length);
        result += String.fromCharCode(charCode ^ keyCode);
    }
    return Buffer.from(result).toString('base64');
}

// 导出
module.exports = { DTZC };
