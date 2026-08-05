# SAF-LEP for Android

This is a complete command-line Android application. Android Studio is not
required to build it.

The app contains a small Java launcher and `VpnService`, plus the existing
C++23 tunnel core compiled with the Android NDK. The default APK contains both
`arm64-v8a` (physical devices) and `x86_64` (emulators and compatible devices).

## Prerequisites

- JDK 17 or newer
- Android SDK Platform 36 and Build Tools 36.0.0
- Android NDK 27.0.12077973
- CMake 3.22.1 and Ninja from the Android SDK
- Boost headers 1.69 or newer, or network access for the pinned Boost 1.87.0
  fallback

`BOOST_ROOT` may point either to a Boost root containing `include/boost` or
directly to the directory containing `boost/`. No Boost binaries are needed:
Boost.Asio and the used Boost.System API are header-only.

## Headless build

### Windows PowerShell

```powershell
cd android
$env:JAVA_HOME = 'C:\path\to\jdk-17-or-newer'
$env:ANDROID_HOME = "$env:LOCALAPPDATA\Android\Sdk"
$env:BOOST_ROOT = 'C:\path\to\boost-or-vcpkg-triplet'
.\gradlew.bat :app:assembleDebug --no-daemon
```

### Linux, macOS, or Termux

```bash
cd android
export JAVA_HOME=/path/to/jdk-17-or-newer
export ANDROID_HOME=/path/to/android-sdk
export BOOST_ROOT=/path/to/boost-or-system-prefix
./gradlew :app:assembleDebug --no-daemon
```

The first online build downloads the pinned Gradle distribution, Android
Gradle Plugin, AAPT2, and (only when `BOOST_ROOT` is absent) Boost headers.
Every version used by the project is pinned.

Output:

```text
app/build/outputs/apk/debug/app-debug.apk
```

Install it on a connected device with:

```powershell
.\gradlew.bat :app:installDebug --no-daemon
```

The initial `VpnService` consent dialog is an Android security requirement and
must be accepted on the device; compilation and installation remain headless.

## Offline builds

After Gradle and AGP are cached, the project can build offline. If AGP's AAPT2
artifact is not cached, point it at Build Tools 36.0.0 from the installed SDK.
For example in PowerShell:

```powershell
$aapt2 = "$env:ANDROID_HOME/build-tools/36.0.0/aapt2.exe"
$env:GRADLE_OPTS = "-Dorg.gradle.project.android.aapt2FromMavenOverride=$aapt2"
.\gradlew.bat :app:assembleDebug --no-daemon --offline
```

For a faster single-ABI build:

```powershell
$env:ORG_GRADLE_PROJECT_safLepAbis = 'arm64-v8a'
.\gradlew.bat :app:assembleDebug --no-daemon
```

Use `-PsafLepAbis=arm64-v8a` in POSIX shells. If `BOOST_ROOT` is not supplied,
the Boost fallback needs one successful online configure before offline builds.

## Source layout

```text
android/
|-- app/src/main/
|   |-- AndroidManifest.xml
|   `-- java/com/example/saflep/
|       |-- MainActivity.java
|       `-- SafLepVpnService.java
|-- cpp/
|   |-- CMakeLists.txt
|   `-- native-lib.cpp
|-- gradle/wrapper/
|-- build.gradle
|-- settings.gradle
`-- gradlew / gradlew.bat
```

The launcher offers both LEP v0 and LEP v1. LEP v0 remains the default for
compatibility with existing workflows; the client and server must select the
same scheme. The native bridge protects the UDP socket from VPN routing, and
the TUN adapter owns a duplicated file descriptor so shutdown cannot invalidate
the descriptor managed by Java.

## Logging

Enable **Verbose logging** in the launcher, then inspect:

```bash
adb logcat -s SAF-LEP-JNI SAF-LEP-TUN SafLepVpnService
```
