# AndroidHardeningProtector

**360 Jiagu Style APK Protector for Android**

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue)](https://python.org)
[![Android](https://img.shields.io/badge/Android-8%2B-green)](https://android.com)

## 🛡️ Features

- ✅ **Method-level DEX encryption** (40% random methods - 360 style)
- ✅ **In-memory DEX loading** (no disk write, anti-dump)
- ✅ **Native decryption library** (.so with anti-debug)
- ✅ **Anti-debug techniques** (ptrace, TracerPid, Frida)
- ✅ **Native signature verification**
- ✅ **Multiple hiding techniques**:
  - Hide in fake .so sections (primary)
  - Hide in ZIP extra fields
  - Hide in ZIP comments
- ✅ **APK rebuilding with stub loader**

## 📋 Requirements

- Python 3.8+
- Android NDK r21+ (for native library)
- Java JDK 8+ (for signing)
- apksigner or jarsigner

## 🚀 Installation

```bash
# Clone repository
git clone https://github.com/yourusername/AndroidHardeningProtector
cd AndroidHardeningProtector

# Install Python dependencies
pip install -r requirements.txt

# Build native library
cd native
chmod +x build.sh
./build.sh
cd ..

# Download stub DEX (or compile from source)
# Pre-compiled stub is included in stub/smali/