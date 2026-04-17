/**
 * DTZC - 动态注册Hook策略云端计算
 * 云端决定：hook谁、怎么hook、返回什么
 */

function onRequest(request, response, modules) {
    const { deviceId, soName, soSize, soHash, timestamp, sign } = request.body;
    
    // ========== 云端识别SO文件 ==========
    const soProfile = identifySO(soName, soSize, soHash);
    
    // ========== 云端计算Hook策略 ==========
    const hookStrategy = calculateHookStrategy(soProfile);
    
    // ========== 云端生成hook代码（可选）==========
    const hookBytecode = generateHookCode(hookStrategy);
    
    response.end(JSON.stringify({
        code: 200,
        
        // ========== 云端决策1：要hook的函数列表 ==========
        targets: [
            {
                // 云端识别出的JNI函数
                funcName: 'JNI_OnLoad',
                // 云端计算的hook点偏移
                hookOffset: 0x1234,  // 云端分析后确定
                // 云端决定的hook方式
                method: 'inline-hook',  // 'inline' | 'plt-hook' | 'trampoline'
                // 云端计算的跳转地址
                redirectTo: 'cloud-stub-001'
            },
            {
                funcName: 'RegisterNatives',
                // 云端分析出的RegisterNatives地址（不同SO位置不同）
                symbolAddr: 0x5678,  // 云端从符号表计算
                hookMethod: 'plt-hook'
            }
        ],
        
        // ========== 云端决策2：伪造的注册表 ==========
        // 云端构造假的JNI注册信息返回给用户看
        fakeRegistry: generateFakeRegistry(soProfile),
        
        // ========== 云端决策3：数据过滤规则 ==========
        // 哪些注册信息要显示，哪些要隐藏
        filterRules: {
            // 云端定义的黑名单
            hidePatterns: ['Java_com_.*_internal_.*', '.*_native_.*'],
            // 云端定义的白名单（只显示这些）
            showOnly: soProfile.knownJniFuncs || [],
            // 云端计算的重命名规则
            rename: {
                'Java_com_example_MainActivity_add': '用户自定义_add_0x1234'
            }
        },
        
        // ========== 云端决策4：调用拦截器 ==========
        interceptors: [
            {
                // 云端预计算的调用拦截代码（直接复制执行）
                when: 'before-call',
                // 云端生成的ARM64代码（加密）
                code: '0xd10043ff...',  // 云端keystone生成
                // 云端定义的检查逻辑
                check: 'verify-args'  // 云端预设的检查类型
            },
            {
                when: 'after-call',
                // 云端构造的返回值修改器
                modifyReturn: 'log-only'
            }
        ],
        
        // ========== 云端决策5：反调试策略 ==========
        antiDebug: {
            // 云端动态生成的反调试代码
            checkInterval: 5000,  // 云端控制检查频率
            // 云端计算的多级检测点
            checkpoints: [
                { offset: 0x100, type: 'ptrace-check' },
                { offset: 0x200, type: 'frida-detect' }
            ],
            // 云端决策的响应动作
            action: 'crash-random'  // 'crash' | 'fake-data' | 'silent-exit'
        },
        
        // ========== 云端预计算hook代码（高级）==========
        // 如果云端有完整SO文件，可以直接生成hook机器码
        prebuiltHooks: soProfile.hasAnalysis ? {
            // 云端编译好的inline hook代码
            inlineHook: hookBytecode,
            // 云端计算的trampoline地址
            trampolineAddr: 0x7ffe0000 + soProfile.baseOffset,
            // 云端生成的PLT表副本
            shadowPlt: generateShadowPlt(soProfile)
        } : null,
        
        // 会话控制
        session: {
            id: modules.oCrypto.md5(deviceId + Date.now()),
            expireAt: Date.now() + 3600000,
            // 云端计算的心跳间隔
            heartbeat: 30000  // 30秒必须心跳一次
        }
    }));
}

/**
 * 云端SO识别
 */
function identifySO(name, size, hash) {
    // 云端数据库匹配已知的SO文件
    const db = {
        'libnative.so': {
            knownJniFuncs: ['Java_com_example_add', 'Java_com_example_sub'],
            registerNativesOffset: 0x2345,
            jniOnLoadOffset: 0x1234,
            baseOffset: 0x1000
        }
    };
    
    return db[name] || {
        knownJniFuncs: [],
        needsFullAnalysis: true
    };
}

/**
 * 云端计算hook策略
 */
function calculateHookStrategy(profile) {
    // 云端根据SO特征决定最佳hook方式
    return {
        primary: 'inline-hook',
        fallback: 'plt-hook',
        // 云端计算的最佳hook点（避开热点代码）
        safePoints: profile.registerNativesOffset ? 
            [profile.registerNativesOffset + 0x10] : [],
        // 云端决策的hook优先级
        priority: profile.knownJniFuncs.length > 0 ? 'high' : 'low'
    };
}

/**
 * 云端生成假注册表（迷惑分析者）
 */
function generateFakeRegistry(profile) {
    // 云端构造假的JNI注册信息
    const fake = [];
    
    // 真实函数
    for (const func of profile.knownJniFuncs) {
        fake.push({
            className: parseClassName(func),
            methodName: parseMethodName(func),
            signature: '(II)I',  // 云端猜测的签名
            // 云端故意混淆的地址
            displayAddr: 0x7ffe0000 + Math.floor(Math.random() * 0x1000),
            // 云端标记是否真实
            isReal: true,
            // 云端决策的显示名称
            displayName: func.replace('Java_', '')
        });
    }
    
    // 云端插入虚假项（干扰分析）
    fake.push({
        className: 'com/example/internal',
        methodName: 'hidden_func',
        signature: '(Ljava/lang/String;)V',
        displayAddr: 0x0,
        isReal: false,
        displayName: '系统隐藏函数'
    });
    
    return fake;
}

/**
 * 云端生成hook机器码
 */
function generateHookCode(strategy) {
    // 云端使用keystone生成ARM64 hook代码
    // 例如：ldr x16, [x17]; br x16 类型的跳转
    
    const template = `
        // 保存上下文
        sub sp, sp, #0x20
        stp x0, x1, [sp, #0x00]
        stp x2, x3, [sp, #0x10]
        
        // 加载云端计算的跳转地址
        ldr x16, =0x7ffe8000
        blr x16
        
        // 恢复上下文
        ldp x0, x1, [sp, #0x00]
        ldp x2, x3, [sp, #0x10]
        add sp, sp, #0x20
        
        // 跳回原函数
        ldr x16, ={original_addr}
        br x16
    `;
    
    // 云端编译成机器码返回
    return 'd10083ffa90007e0a9010be1f0000010d63ff97...';
}

/**
 * 云端生成shadow PLT表
 */
function generateShadowPlt(profile) {
    // 云端创建一个修改过的PLT表
    // 所有JNI调用先跳到云端控制的地址
    return {
        base: 0x7fff0000,
        entries: profile.knownJniFuncs.map((f, i) => ({
            index: i,
            // 云端计算的目标地址
            target: 0x7fff0000 + i * 0x10,
            // 云端记录的原始地址
            original: profile.baseOffset + 0x2345 + i * 0x20
        }))
    };
}

function parseClassName(full) {
    return full.replace('Java_', '').replace(/_/g, '/').split('/').slice(0, -1).join('/');
}

function parseMethodName(full) {
    return full.split('_').pop();
}
