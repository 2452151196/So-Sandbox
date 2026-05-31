# =============================
# SoSandbox release 混淆规则
# =============================

# 混淆字典配置（实验性）
-obfuscationdictionary proguard-dic.txt
-classobfuscationdictionary proguard-dic.txt
-packageobfuscationdictionary proguard-dic.txt

# 保留调试映射需要的行号信息（便于用 mapping.txt 还原崩溃）
-keepattributes SourceFile,LineNumberTable

# JNI 关键规则：凡是包含 native 方法的类及方法名都不要改名
# 否则会导致 Java_xxx 符号找不到
-keepclasseswithmembernames class * {
    native <methods>;
}

# 保留 NativeInvoker（大量 JNI 入口集中在这里）
-keep class com.example.anative.core.NativeInvoker { *; }

# 保留包含 JNI 方法的 UI 类（当前有 native 声明）
-keep class com.example.anative.ui.RegisterNativesActivity { *; }
-keep class com.example.anative.ui.FlowChartFragment { *; }

# 保留 enum 的 values/valueOf（防止被错误裁剪）
-keepclassmembers enum * {
    public static **[] values();
    public static ** valueOf(java.lang.String);
}

# StringFog 运行时解密类必须保留，否则字符串解密崩溃
# 插件自动生成的 StringFog 类在 app 包名下
-keep class com.example.anative.StringFog { *; }
-keep class com.github.megatronking.stringfog.xor.StringFogImpl { *; }
-keep class com.github.megatronking.stringfog.IStringFog { *; }
-keepclassmembers class com.example.anative.StringFog {
    public static *** decrypt(...);
}

# 忽略一些常见库告警，避免 release 构建被无关 warning 阻断
-dontwarn org.conscrypt.**
-dontwarn javax.annotation.**
-dontwarn com.github.megatronking.stringfog.**