# SAF-LEP Android Port

This directory contains the native C++ code and sample Kotlin implementation for running SAF-LEP on Android.

## Directory Structure

```
android/
├── cpp/
│   ├── CMakeLists.txt     # NDK build configuration
│   └── native-lib.cpp     # JNI bridge between Java/Kotlin and C++
├── kotlin/
│   └── SafLepVpnService.kt  # Sample VpnService implementation
└── README.md              # This file
```

## Prerequisites

### 1. Android NDK

Install the NDK via Android Studio SDK Manager or download from:
https://developer.android.com/ndk/downloads

### 2. Boost for Android

You need to compile Boost libraries (System, Thread, Asio) for Android architectures.

**Recommended tool:** [Boost-for-Android](https://github.com/moritz-wundke/Boost-for-Android)

```bash
# Clone the builder
git clone https://github.com/moritz-wundke/Boost-for-Android.git
cd Boost-for-Android

# Build for Android (adjust NDK path)
./build-android.sh $NDK_ROOT --boost=1.83.0 --arch=arm64-v8a,armeabi-v7a,x86_64 \
    --with-libraries=system,thread
```

**Expected output structure:**
```
boost/
├── include/
│   └── boost/
│       ├── asio/
│       ├── system/
│       └── ...
└── lib/
    ├── arm64-v8a/
    │   ├── libboost_system.a
    │   └── libboost_thread.a
    ├── armeabi-v7a/
    │   └── ...
    └── x86_64/
        └── ...
```

## Integration Steps

### Step 1: Create Android Studio Project

1. Create a new **"Native C++"** project in Android Studio
2. Select C++ Standard: **C++17** or higher (the project uses C++23 features but can be adjusted)

### Step 2: Copy Source Files

Copy the following files to your project:

```
your-project/
└── app/
    └── src/
        └── main/
            ├── cpp/
            │   ├── CMakeLists.txt          # From android/cpp/
            │   ├── native-lib.cpp          # From android/cpp/
            │   ├── udp_tunnel/             # From root udp_tunnel/
            │   │   ├── tunnel.h
            │   │   ├── tunnel.cpp
            │   │   ├── android_tun.h
            │   │   ├── android_tun.cpp
            │   │   └── global_flags.h
            │   └── lep/                    # From root lep/
            │       ├── encryption.h
            │       └── low_entropy_protocol.h
            └── kotlin/
                └── com/example/saflep/
                    └── SafLepVpnService.kt  # From android/kotlin/
```

### Step 3: Configure build.gradle

In `app/build.gradle`:

```groovy
android {
    defaultConfig {
        // ...
        externalNativeBuild {
            cmake {
                cppFlags "-std=c++23"
                arguments "-DBOOST_ROOT=/path/to/your/boost"
            }
        }
        ndk {
            abiFilters 'arm64-v8a', 'armeabi-v7a', 'x86_64'
        }
    }

    externalNativeBuild {
        cmake {
            path "src/main/cpp/CMakeLists.txt"
            version "3.22.1"
        }
    }
}
```

### Step 4: Update AndroidManifest.xml

Add the VPN service declaration:

```xml
<manifest>
    <application>
        <!-- ... -->

        <service
            android:name=".SafLepVpnService"
            android:permission="android.permission.BIND_VPN_SERVICE"
            android:exported="false">
            <intent-filter>
                <action android:name="android.net.VpnService" />
            </intent-filter>
        </service>
    </application>
</manifest>
```

### Step 5: Request VPN Permission

Before starting the VPN, request user permission:

```kotlin
// In your Activity
private fun startVpn() {
    val intent = VpnService.prepare(this)
    if (intent != null) {
        // User hasn't granted VPN permission yet
        startActivityForResult(intent, VPN_REQUEST_CODE)
    } else {
        // Permission granted, start the service
        startVpnService()
    }
}

override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
    super.onActivityResult(requestCode, resultCode, data)
    if (requestCode == VPN_REQUEST_CODE && resultCode == RESULT_OK) {
        startVpnService()
    }
}

private fun startVpnService() {
    val intent = Intent(this, SafLepVpnService::class.java).apply {
        putExtra("server_ip", "your.server.ip")
        putExtra("server_port", 14578)
        putExtra("seed_key", "your-encryption-key")
        putExtra("vpn_address", "10.0.0.2")
        putExtra("vpn_prefix", 24)
    }
    startService(intent)
}
```

## Architecture Notes

### Routing Loop Prevention

Android's VpnService routes **all** traffic through the TUN interface, including the encrypted UDP packets destined for the VPN server. This creates an infinite loop.

**Solution:** The native code calls back to `VpnService.protect(socket)` to exclude the tunnel's UDP socket from VPN routing. This is handled automatically in `native-lib.cpp`.

### Background Execution

Android aggressively kills background processes. To keep the VPN running:

1. The service runs as a **Foreground Service** with a notification
2. Consider implementing a **WakeLock** for CPU-intensive operations
3. Handle `onRevoke()` gracefully when the user revokes VPN permission

### APK Size

Boost libraries can significantly increase APK size. To minimize:

1. Use `bcp` (Boost Copy) to extract only needed headers
2. Enable ProGuard/R8 for release builds
3. Use Android App Bundles to deliver architecture-specific libraries

## Troubleshooting

### Build Errors

**"Boost not found"**: Set the `BOOST_ROOT` environment variable or edit the path in `CMakeLists.txt`

**"Cannot find -lboost_system"**: Ensure Boost libraries are compiled for the correct Android ABI

### Runtime Errors

**"Failed to establish VPN interface"**: User may have denied VPN permission. Check `VpnService.prepare()` result.

**"VPN disconnects immediately"**: Check logcat for native errors. Common causes:
- Invalid server IP/port
- Network permission issues
- Socket protection failure

### Logging

Enable verbose mode for detailed logging:

```kotlin
intent.putExtra("verbose", true)
```

Then check logcat:
```bash
adb logcat -s SAF-LEP-JNI SAF-LEP-TUN
```

## Building Standalone (Without Android Studio)

For CI/CD or command-line builds:

```bash
# Set environment
export NDK_ROOT=/path/to/android-ndk
export BOOST_ROOT=/path/to/boost

# Configure
cd android/cpp
mkdir build && cd build
cmake -DCMAKE_TOOLCHAIN_FILE=$NDK_ROOT/build/cmake/android.toolchain.cmake \
      -DANDROID_ABI=arm64-v8a \
      -DANDROID_NATIVE_API_LEVEL=24 \
      -DBOOST_ROOT=$BOOST_ROOT \
      ..

# Build
make -j$(nproc)
```

## License

Same as the parent SAF-LEP project.
