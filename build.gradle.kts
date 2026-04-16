// Top-level build file where you can add configuration options common to all sub-projects/modules.
plugins {
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.kotlin.android) apply false
}
val kotlinVersion = libs.versions.kotlin.get()

// 将获取到的字符串版本号设置到根项目的ext属性中
extra.set("kotlin_version", kotlinVersion)