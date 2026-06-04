buildscript {
    repositories {
        mavenCentral()
    }
    dependencies {
        classpath("com.github.megatronking.stringfog:gradle-plugin:5.2.0")
    }
}

plugins {
    alias(libs.plugins.android.application)
}

apply(plugin = "stringfog")

configure<com.github.megatronking.stringfog.plugin.StringFogExtension> {
    implementation = "com.github.megatronking.stringfog.xor.StringFogImpl"
    enable = true
    mode = com.github.megatronking.stringfog.plugin.StringFogMode.base64
    kg = com.github.megatronking.stringfog.plugin.kg.RandomKeyGenerator()
}



android {
    namespace = "com.example.anative"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.example.anative"
        minSdk = 26
        targetSdk = 34
        versionCode = 6
        versionName = "1.5"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        ndk {
            abiFilters += listOf("arm64-v8a")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
        debug {
            isMinifyEnabled = false
            isShrinkResources = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }
    buildFeatures {
        viewBinding = true
        buildConfig = true
    }
}

dependencies {
    // ELF解析
    implementation("net.fornwall:jelf:0.9.0")

    // PLT Hook
    implementation("com.bytedance:bytehook:1.0.10")

    // RecyclerView
    implementation("androidx.recyclerview:recyclerview:1.3.2")

    // CardView
    implementation("androidx.cardview:cardview:1.0.0")

    // StringFog XOR 加密实现（运行时解密用）
    implementation("com.github.megatronking.stringfog:xor:5.0.0")

    implementation(libs.appcompat)
    implementation(libs.material)
    implementation(libs.constraintlayout)
    testImplementation(libs.junit)
    androidTestImplementation(libs.ext.junit)
    androidTestImplementation(libs.espresso.core)
}
