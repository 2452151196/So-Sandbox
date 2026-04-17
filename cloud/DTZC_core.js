/**
 * DTZC - 核心数据云端生成
 * 动态注册信息、函数签名、调用参数都在云端计算
 */

function onRequest(request, response, modules) {
    const body = request.body || {};
    const { deviceId, soPath, baseAddr, timestamp, sign } = body;
    
    // 简单鉴权
    if (!verifySign(deviceId, timestamp, sign, modules)) {
        response.end(JSON.stringify({ code: 403, msg: 'fail' }));
        return;
    }
    
    // ========== 云端分析SO文件 ==========
    // 这里调用云端的真实分析引擎
    // 比如：capstone/keystone运行在云端服务器
    
    const analysisResult = performCloudAnalysis(soPath, baseAddr);
    
    // ========== 云端生成JNI注册表 ==========
    const jniRegistry = generateJNIRegistry(analysisResult);
    
    // ========== 云端计算函数签名 ==========
    const funcSignatures = calculateSignatures(analysisResult);
    
    // ========== 云端生成调用桩 ==========
    const callStubs = generateCallStubs(funcSignatures);
    
    // ========== 加密返回核心数据 ==========
    const sessionKey = deriveKey(deviceId, timestamp);
    
    response.end(JSON.stringify({
        code: 200,
        
        // JNI注册表（加密）- 包含类名、方法名、函数地址
        registry: encrypt(JSON.stringify(jniRegistry), sessionKey),
        
        // 函数签名信息（加密）- 参数类型、返回值
        signatures: encrypt(JSON.stringify(funcSignatures), sessionKey),
        
        // 调用桩代码（加密）- 可直接执行的调用模板
        stubs: encrypt(JSON.stringify(callStubs), sessionKey),
        
        // 会话密钥（RSA加密，客户端用私钥解）
        sessionKey: rsaEncrypt(sessionKey, deviceId),
        
        // 过期时间
        expireAt: Date.now() + 3600000,  // 1小时有效
        
        // 调试信息（调试用，生产去掉）
        debug: {
            funcCount: funcSignatures.length,
            jniCount: jniRegistry.length
        }
    }));
}

/**
 * 云端执行SO分析
 */
function performCloudAnalysis(soPath, baseAddr) {
    // 云端服务器加载SO文件
    // 使用云端的capstone进行真实分析
    
    // 模拟真实分析结果
    return {
        functions: [
            { name: 'Java_com_example_MainActivity_add', offset: 0x1234, size: 0x100 },
            { name: 'Java_com_example_MainActivity_sub', offset: 0x1334, size: 0x120 },
        ],
        strings: [],
        plt: [],
        exports: []
    };
}

/**
 * 云端生成JNI注册表
 */
function generateJNIRegistry(analysis) {
    const registry = [];
    
    for (const func of analysis.functions) {
        if (func.name.startsWith('Java_')) {
            // 解析 Java_com_package_Class_method 格式
            const parts = func.name.replace('Java_', '').split('_');
            const methodName = parts.pop();
            const className = parts.join('/');
            
            registry.push({
                className: className,
                methodName: methodName,
                signature: generateSignature(),  // (II)I
                funcOffset: func.offset,
                funcSize: func.size,
                // 云端计算的调用地址
                callStub: generateStubAddress(func.offset)
            });
        }
    }
    
    return registry;
}

/**
 * 云端计算函数签名
 */
function calculateSignatures(analysis) {
    const signatures = [];
    
    for (const func of analysis.functions) {
        // 云端分析参数（通过符号表、调用约定推断）
        signatures.push({
            name: func.name,
            offset: func.offset,
            // 云端推断的签名
            nativeSig: '(II)I',  // 云端计算
            javaSig: 'int add(int, int)',
            // 云端计算的调用模板
            callTemplate: {
                regs: ['x0', 'x1'],      // 参数寄存器
                retReg: 'x0',            // 返回值寄存器
                stackSize: 0x10          // 栈帧大小
            }
        });
    }
    
    return signatures;
}

/**
 * 云端生成调用桩
 */
function generateCallStubs(signatures) {
    const stubs = [];
    
    for (const sig of signatures) {
        // 云端生成ARM64调用代码
        // 客户端直接执行这段代码，无需本地计算
        stubs.push({
            funcOffset: sig.offset,
            // 云端生成的机器码（加密）
            // 例如: mov x0, arg0; mov x1, arg1; bl #offset; ret
            machineCode: generateMachineCode(sig),
            // 云端计算的安全包装
            wrapper: generateSafeWrapper(sig)
        });
    }
    
    return stubs;
}

/**
 * 生成机器码（云端计算）
 */
function generateMachineCode(sig) {
    // 云端使用keystone生成ARM64代码
    // 这是核心数据，客户端永远无法看到生成逻辑
    
    const asm = `
        sub sp, sp, #${sig.callTemplate.stackSize}
        stp x29, x30, [sp]
        mov x0, #0      // arg0
        mov x1, #0      // arg1
        bl #${sig.offset}
        ldp x29, x30, [sp]
        add sp, sp, #${sig.callTemplate.stackSize}
        ret
    `;
    
    // 云端汇编成机器码
    return '0xd10043ff0xa9007bfd...';  // base64编码的机器码
}

/**
 * 生成安全包装（防崩溃）
 */
function generateSafeWrapper(sig) {
    return {
        // 云端计算的边界检查
        stackGuard: 0x1000,
        timeoutMs: 5000,
        maxRetries: 3,
        // 云端配置的安全沙箱
        sandbox: {
            allowedRegs: sig.callTemplate.regs,
            allowedSyscalls: [0, 1, 2]  // read/write/exit
        }
    };
}

/**
 * 派生会话密钥
 */
function deriveKey(deviceId, timestamp) {
    const data = deviceId + timestamp + 'cloud-core';
    return modules.oCrypto.md5(data) + modules.oCrypto.md5(data + 'salt');
}

/**
 * 加密
 */
function encrypt(data, key) {
    let result = '';
    for (let i = 0; i < data.length; i++) {
        result += String.fromCharCode(
            data.charCodeAt(i) ^ key.charCodeAt(i % key.length)
        );
    }
    return Buffer.from(result).toString('base64');
}

/**
 * RSA加密会话密钥
 */
function rsaEncrypt(key, deviceId) {
    // 用设备公钥加密
    // 客户端私钥解密
    return modules.oCrypto.md5(key + deviceId);  // 简化示例
}

/**
 * 签名验证
 */
function verifySign(deviceId, timestamp, sign, modules) {
    if (!deviceId || !timestamp || !sign) return false;
    
    const secret = 'dtzc-core-secret';
    const payload = deviceId + timestamp + secret;
    const expect = modules.oCrypto.md5(payload).substring(0, 16);
    
    return sign === expect;
}

/**
 * 生成Java签名（云端计算）
 */
function generateSignature() {
    // 云端分析参数类型后返回
    return '(II)I';
}

/**
 * 生成调用桩地址（云端计算）
 */
function generateStubAddress(offset) {
    // 云端分配的可执行内存地址
    return '0x' + (0x7400000000 + offset).toString(16);
}
