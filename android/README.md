# SAF-LEP for Android

This is a complete Android application that can be built from the command
line. Android Studio is not required.

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

The launcher offers LEP v0, LEP v1, and raw framing. LEP v0 remains the default
for compatibility with existing workflows; the client and server must select
the same scheme. Raw framing adds only a four-byte packet index and the launcher
requires a non-empty seed key for it. The native bridge protects the UDP socket
from VPN routing, and the TUN adapter owns a duplicated file descriptor so
shutdown cannot invalidate the descriptor managed by Java.

## Launcher settings and status

The launcher persists the server, port, LEP version, VPN addressing, and
logging settings in the app's private preferences. The seed key can be shown
while editing and can be remembered or removed independently. Android backup is
disabled for this app, but a remembered key is still stored locally on the
device rather than in a hardware-backed secret store.

The VPN address controls correspond to the desktop `--ip`, `--mask`, and
`--gw` values. Android's `VpnService` does not expose a next-hop gateway for a
TUN route, so the gateway field controls routing mode: a non-empty value
captures all IPv4 traffic, while an empty value captures only the configured
VPN subnet.

The activity status panel survives activity recreation and reports each setup
stage, the resolved server IP, local UDP port, peer traffic, UDP and TUN byte
counters, and packets discarded before a peer was available. The notification
and activity both provide a **Disconnect** action.

Server hostnames are resolved before the catch-all VPN route is installed, and
the native bridge receives the resulting numeric IPv4 endpoint. This prevents
the initial DNS lookup from being routed into a tunnel that is not ready yet.

If the panel says **Peer traffic: none yet**, the local TUN and UDP socket are
running but no datagram has returned from the server. Check that the server is
listening on UDP, its firewall/NAT exposes the selected port, and both sides use
the same LEP version and seed key. Rising `TUN->peer` and UDP TX counters with
zero UDP RX narrow the problem to the server/network path rather than Android's
VPN interface.

## Logging

Enable **Verbose logging** in the launcher, then inspect:

```bash
adb logcat -s SAF-LEP-JNI SAF-LEP-TUN SafLepVpnService
```
