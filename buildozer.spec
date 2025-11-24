[app] title = Bitcoin Toolkit package.name = bitcointoolkit package.domain = com.yourname

source.dir = . source.include_exts = py,png,jpg,kv,atlas

version = 1.0 requirements = python3,kivy,requests,ecdsa,mnemonic

android.api = 34 android.minapi = 23 android.build_tools_version = 34.0.0 android.ndk = 25b android.archs = arm64-v8a, armeabi-v7a

fullscreen = 0 orientation = portrait

[buildozer] log_level = 2 warn_on_root = 1 android.accept_sdk_license = True android.sdk_path = $ANDROID_HOME android.ndk_path = $ANDROID_NDK_HOME
