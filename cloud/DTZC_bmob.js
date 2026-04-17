/**
 * DTZC
 * 动态注册功能验证 - Bmob云函数版本
 */

/**
 * DTZC
 * @param {Object} request - 请求对象
 * @param {Object} response - 响应对象  
 * @param {Object} modules - Bmob模块
 */
function onRequest(request, response, modules) {
    // Bmob参数从 body 获取
    const body = request.body || {};
    const { deviceId, timestamp, sign, version } = body;
    
    // ========== 参数校验 ==========
    if (!deviceId || !timestamp || !sign) {
        response.end(JSON.stringify({
            code: 400,
            msg: '缺少必要参数',
            ok: false
        }));
        return;
    }
    
    // ========== 时间校验（防重放）==========
    const now = Date.now();
    const ts = parseInt(timestamp);
    
    if (isNaN(ts) || Math.abs(now - ts) > 300000) {
        response.end(JSON.stringify({
            code: 401,
            msg: '请求超时',
            ok: false
        }));
        return;
    }
    
    // ========== 签名验证 ==========
    const serverSecret = 'dtzc-2024-secret-key';  // 建议从环境变量读取
    const payload = `${deviceId}:${timestamp}:${version || '1.0'}:${serverSecret}`;
    const expectSign = modules.oCrypto.md5(payload).toLowerCase().substring(0, 16);
    
    if (sign !== expectSign) {
        console.log(`[DTZC] 签名错误: ${deviceId}`);
        response.end(JSON.stringify({
            code: 403,
            msg: '验证失败',
            ok: false
        }));
        return;
    }
    
    // ========== 查询授权设备 ==========
    const oData = modules.oData;
    const query = oData.find({
        table: 'LicensedDevices',
        where: { deviceId: deviceId }
    });
    
    query.then(function(data) {
        const result = JSON.parse(data);
        const results = result.results || [];
        
        if (results.length === 0) {
            // 未授权，返回试用
            response.end(JSON.stringify({
                code: 402,
                msg: '未授权',
                ok: false,
                trial: {
                    enable: true,
                    leftDays: 3,
                    limited: true
                }
            }));
            return;
        }
        
        const device = results[0];
        const expireAt = device.expireAt || 0;
        
        // 检查是否过期
        if (expireAt && expireAt < now) {
            response.end(JSON.stringify({
                code: 402,
                msg: '授权已过期',
                ok: false,
                renew: true
            }));
            return;
        }
        
        // ========== 生成动态密钥 ==========
        const expireTime = now + 7 * 24 * 60 * 60 * 1000;  // 7天
        const salt = Math.random().toString(36).substring(2, 18);
        
        // 密钥结构
        const keyRaw = `${deviceId}:${expireTime}:${salt}:${serverSecret}`;
        const licenseKey = modules.oCrypto.md5(keyRaw) + modules.oCrypto.md5(keyRaw + salt);
        
        // XOR加密
        const encryptedKey = xorEncrypt(licenseKey, deviceId);
        
        console.log(`[DTZC] 授权成功: ${deviceId}`);
        
        response.end(JSON.stringify({
            code: 200,
            msg: '成功',
            ok: true,
            
            // 加密密钥
            key: encryptedKey,
            
            // 元数据
            meta: {
                deviceId: deviceId,
                expireAt: expireTime,
                version: 'v2',
                salt: salt
            },
            
            // 功能开关
            features: {
                dynamicRegister: true,
                flowchart: device.vip === true,
                xrefAdvanced: device.vip === true
            },
            
            // 下次刷新
            refresh: now + 24 * 60 * 60 * 1000
        }));
        
    }).catch(function(err) {
        console.error('[DTZC] 查询失败:', err);
        response.end(JSON.stringify({
            code: 500,
            msg: '服务器错误',
            ok: false
        }));
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
    // Base64编码
    return Buffer.from(result).toString('base64');
}
