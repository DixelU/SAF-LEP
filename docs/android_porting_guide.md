# Porting SAF-LEP to Android

This guide outlines the architectural changes and steps required to port the SAF-LEP C++ core to Android. Unlike Linux/Windows, Android does not provide root access to create network interfaces directly. Instead, we must use the Android `VpnService` API and bridge it to our C++ code via JNI.

## 1. Architecture Overview

| Component | Technology | Responsibility |
|-----------|------------|----------------|
| **UI / Service** | Kotlin / Java | Manages App lifecycle, Start/Stop buttons, and the `VpnService`. |
| **Network Interface** | Android `VpnService` | Creates the TUN interface and provides a **File Descriptor (FD)**. |
| **JNI Bridge** | C++ / JNI | Receives the FD from Java and passes it to the C++ core. |
| **Core Logic** | C++ (Native) | Runs the existing `p2p_tunnel`, `lep`, and fragmentation logic. |

## 2. Prerequisites

### Boost for Android
You must compile the Boost libraries (System, Thread, Asio) for Android architectures (`arm64-v8a`, `armeabi-v7a`, `x86_64`).
- **Recommended Tool**: [Boost-for-Android](https://github.com/moritz-wundke/Boost-for-Android)
- **Output**: Static libraries (`.a`) and headers.

### Android NDK
Ensure you have the NDK installed via Android Studio SDK Manager.

## 3. Implementation Steps

### Step A: Android Studio Project
1.  Create a new **"Native C++"** project in Android Studio.
2.  This will generate a `cpp` folder and a `CMakeLists.txt`.
3.  Copy your existing `udp_tunnel`, `lep`, and `global_flags.h` files into the `cpp` folder.

### Step B: CMake Configuration
Modify the Android `CMakeLists.txt` to:
1.  Include your source files.
2.  Link against the pre-built Boost libraries.
3.  Link `log` (Android logging) and `atomic`.

```cmake
cmake_minimum_required(VERSION 3.22.1)

project("saf-lep")

# Set Boost paths (adjust to where you put them)
set(BOOST_ROOT ${CMAKE_SOURCE_DIR}/../libs/boost)
include_directories(${BOOST_ROOT}/include)

add_library(saf-lep SHARED
    # JNI Bridge
    native-lib.cpp
    
    # Core Files
    udp_tunnel/tunnel.cpp
    udp_tunnel/linux_tun.cpp # We will adapt this
    # ... other files
)

find_library(log-lib log)

target_link_libraries(saf-lep
    ${log-lib}
    ${BOOST_ROOT}/lib/libboost_system.a
    ${BOOST_ROOT}/lib/libboost_thread.a
    # ...
)
```

### Step C: The Android TUN Adapter
You cannot use `open("/dev/net/tun")`. You must accept an existing File Descriptor.

1.  **Modify `vpn_interface`**: Add a constructor or method to accept an `int fd`.
2.  **Create `AndroidTunAdapter`** (or modify `LinuxTunAdapter`):
    *   **Constructor**: Takes `int fd`.
    *   **Open**: Does nothing (already open).
    *   **Read/Write**: Uses `read(fd, ...)` and `write(fd, ...)` (Standard Linux syscalls).
    *   **Close**: Do **NOT** close the FD in C++. Let Java handle it, or close it only if explicitly told.

### Step D: The JNI Bridge (`native-lib.cpp`)
This file connects Java to C++.

```cpp
#include <jni.h>
#include <string>
#include <thread>
#include "udp_tunnel/tunnel.h"

// Global instance (simplified)
std::unique_ptr<dixelu::udp::vpn_interface> vpn;

extern "C" JNIEXPORT void JNICALL
Java_com_example_saflep_MyVpnService_startNativeVpn(
        JNIEnv* env,
        jobject /* this */,
        jint tun_fd,
        jstring server_ip,
        jint server_port) {

    // 1. Convert Strings
    const char* ip_c = env->GetStringUTFChars(server_ip, 0);
    std::string ip_str(ip_c);
    env->ReleaseStringUTFChars(server_ip, ip_c);

    // 2. Initialize Tunnel
    // NOTE: You need to modify vpn_interface to accept the FD!
    auto tunnel = std::make_shared<dixelu::udp::p2p_tunnel>(0);
    vpn = std::make_unique<dixelu::udp::vpn_interface>(tunnel);
    
    // 3. Start (Pass FD instead of opening generic TUN)
    // You will need to refactor vpn::start to take the FD
    vpn->start_android(tun_fd, ip_str, server_port);
}

extern "C" JNIEXPORT void JNICALL
Java_com_example_saflep_MyVpnService_stopNativeVpn(JNIEnv* env, jobject /* this */) {
    if (vpn) vpn->stop();
}
```

### Step E: The Java Service (`MyVpnService.kt`)
This runs in the background and manages the connection.

```kotlin
class MyVpnService : VpnService() {
    
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // 1. Configure the VPN Interface
        val builder = Builder()
        builder.setSession("SAF-LEP")
        builder.addAddress("10.0.0.2", 24)
        builder.addRoute("0.0.0.0", 0) // Redirect all traffic
        builder.setMtu(1500)
        
        // 2. Create the interface
        val parcelFileDescriptor = builder.establish()
        
        if (parcelFileDescriptor != null) {
            val fd = parcelFileDescriptor.fd
            
            // 3. Start C++ in a separate thread
            Thread {
                startNativeVpn(fd, "1.2.3.4", 14578)
            }.start()
        }
        
        return START_STICKY
    }

    override fun onDestroy() {
        stopNativeVpn()
        super.onDestroy()
    }

    // JNI Methods
    external fun startNativeVpn(fd: Int, ip: String, port: Int)
    external fun stopNativeVpn()

    companion object {
        init {
            System.loadLibrary("saf-lep")
        }
    }
}
```

### Step F: AndroidManifest.xml
Register the service.

```xml
<service android:name=".MyVpnService"
         android:permission="android.permission.BIND_VPN_SERVICE">
    <intent-filter>
        <action android:name="android.net.VpnService"/>
    </intent-filter>
</service>
```

## 4. Key Challenges
1.  **Routing Loop**: Just like on Desktop, if you redirect `0.0.0.0/0` into the tunnel, the encrypted UDP packets to the server will also try to go through the tunnel.
    *   **Fix**: Use `VpnService.Builder.addRoute()` carefully, or use `protect(socket)` in Java.
    *   **Better Fix**: In C++, when you create the UDP socket, you can call a JNI method back to Java to call `VpnService.protect(int socketFd)`. This explicitly tells Android "let this socket bypass the VPN".

2.  **Keep-Alive**: Android kills background processes aggressively. You need a Foreground Service notification.

3.  **Boost Size**: Boost can be huge. Use `bcp` or careful linking to keep the APK size down.
