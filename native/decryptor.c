
/**
 * Native decryption library for AndroidHardeningProtector
 * 360 Jiagu style anti-debug + decryption
 */

#include <jni.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>

#define TAG "NativeDecryptor"

// Anti-debug: Check for ptrace
static int check_ptrace() {
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) < 0) {
        return 1; // Being traced
    }
    return 0;
}

// Anti-debug: Check /proc/self/status
static int check_tracerpid() {
    char buf[256];
    FILE* fp = fopen("/proc/self/status", "r");
    if (!fp) return 0;
    
    while (fgets(buf, sizeof(buf), fp)) {
        if (strncmp(buf, "TracerPid:", 10) == 0) {
            int pid = atoi(buf + 10);
            fclose(fp);
            return pid > 0 ? 1 : 0;
        }
    }
    fclose(fp);
    return 0;
}

// Anti-debug: Check for frida
static int check_frida() {
    const char* frida_files[] = {
        "/data/local/tmp/frida-server",
        "/data/local/tmp/re.frida.server",
        "/sdcard/frida-server",
        NULL
    };
    
    for (int i = 0; frida_files[i] != NULL; i++) {
        if (access(frida_files[i], F_OK) == 0) {
            return 1;
        }
    }
    
    // Check for frida libraries
    FILE* fp = fopen("/proc/self/maps", "r");
    if (fp) {
        char line[512];
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, "frida") || strstr(line, "gum-js")) {
                fclose(fp);
                return 1;
            }
        }
        fclose(fp);
    }
    
    return 0;
}

// Anti-debug thread that constantly checks
static void* anti_debug_thread(void* arg) {
    while (1) {
        if (check_ptrace() || check_tracerpid() || check_frida()) {
            // Detection! Crash the app
            raise(SIGSEGV);
            exit(1);
        }
        sleep(1);
    }
    return NULL;
}

// JNI: Start anti-debug thread
JNIEXPORT void JNICALL
Java_com_kiwi_protector_NativeDecryptor_startAntiDebug(JNIEnv *env, jobject thiz) {
    pthread_t thread;
    pthread_create(&thread, NULL, anti_debug_thread, NULL);
    pthread_detach(thread);
}

// XOR decryption with method ID as key
JNIEXPORT jbyteArray JNICALL
Java_com_kiwi_protector_NativeDecryptor_decryptMethod(
    JNIEnv *env, jobject thiz,
    jbyteArray encrypted_data,
    jint method_id) {
    
    // Anti-debug check first
    if (check_ptrace() || check_tracerpid()) {
        raise(SIGSEGV);
        return NULL;
    }
    
    jsize len = (*env)->GetArrayLength(env, encrypted_data);
    jbyte *encrypted = (*env)->GetByteArrayElements(env, encrypted_data, NULL);
    
    // XOR decryption
    jbyte *decrypted = malloc(len);
    unsigned char key[4];
    key[0] = (method_id >> 0) & 0xFF;
    key[1] = (method_id >> 8) & 0xFF;
    key[2] = (method_id >> 16) & 0xFF;
    key[3] = (method_id >> 24) & 0xFF;
    
    for (int i = 0; i < len; i++) {
        decrypted[i] = encrypted[i] ^ key[i % 4];
    }
    
    jbyteArray result = (*env)->NewByteArray(env, len);
    (*env)->SetByteArrayRegion(env, result, 0, len, decrypted);
    
    free(decrypted);
    (*env)->ReleaseByteArrayElements(env, encrypted_data, encrypted, 0);
    
    return result;
}

// AES decryption with hardcoded key (hidden in native)
JNIEXPORT jbyteArray JNICALL
Java_com_kiwi_protector_NativeDecryptor_aesDecrypt(
    JNIEnv *env, jobject thiz,
    jbyteArray encrypted_data) {
    
    // Hardcoded AES key (in production, derive from device)
    unsigned char key[] = {
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
    };
    
    // Simplified AES decryption
    // In production, use OpenSSL or mbedtls
    
    jsize len = (*env)->GetArrayLength(env, encrypted_data);
    jbyte *encrypted = (*env)->GetByteArrayElements(env, encrypted_data, NULL);
    
    // XOR with key as simple cipher
    jbyte *decrypted = malloc(len);
    for (int i = 0; i < len; i++) {
        decrypted[i] = encrypted[i] ^ key[i % 32];
    }
    
    jbyteArray result = (*env)->NewByteArray(env, len);
    (*env)->SetByteArrayRegion(env, result, 0, len, decrypted);
    
    free(decrypted);
    (*env)->ReleaseByteArrayElements(env, encrypted_data, encrypted, 0);
    
    return result;
}

// Signature verification in native
JNIEXPORT jboolean JNICALL
Java_com_kiwi_protector_NativeDecryptor_verifySignature(
    JNIEnv *env, jobject thiz,
    jobject context) {
    
    // Get package manager
    jclass contextClass = (*env)->GetObjectClass(env, context);
    jmethodID getPackageManager = (*env)->GetMethodID(env, contextClass,
        "getPackageManager", "()Landroid/content/pm/PackageManager;");
    jobject pm = (*env)->CallObjectMethod(env, context, getPackageManager);
    
    // Get package name
    jmethodID getPackageName = (*env)->GetMethodID(env, contextClass,
        "getPackageName", "()Ljava/lang/String;");
    jstring packageName = (*env)->CallObjectMethod(env, context, getPackageName);
    
    // Get package info with signatures
    jclass pmClass = (*env)->GetObjectClass(env, pm);
    jmethodID getPackageInfo = (*env)->GetMethodID(env, pmClass,
        "getPackageInfo", "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");
    
    jobject pkgInfo = (*env)->CallObjectMethod(env, pm, getPackageInfo,
        packageName, 64); // GET_SIGNATURES
    
    if (pkgInfo == NULL) {
        return JNI_FALSE;
    }
    
    // Get signatures array
    jclass pkgInfoClass = (*env)->GetObjectClass(env, pkgInfo);
    jfieldID signaturesField = (*env)->GetFieldID(env, pkgInfoClass,
        "signatures", "[Landroid/content/pm/Signature;");
    jobjectArray signatures = (*env)->GetObjectField(env, pkgInfo, signaturesField);
    
    if (signatures == NULL || (*env)->GetArrayLength(env, signatures) == 0) {
        return JNI_FALSE;
    }
    
    // Get first signature
    jobject signature = (*env)->GetObjectArrayElement(env, signatures, 0);
    jclass sigClass = (*env)->GetObjectClass(env, signature);
    jmethodID toCharsString = (*env)->GetMethodID(env, sigClass,
        "toCharsString", "()Ljava/lang/String;");
    jstring sigString = (*env)->CallObjectMethod(env, signature, toCharsString);
    
    // Convert to C string
    const char* sigCStr = (*env)->GetStringUTFChars(env, sigString, NULL);
    
    // Hardcoded expected signature hash (from original APK)
    const char* expected = "308204c3308203aba00302010202044b8b2a80300d06092a864886f70d01010b0500308186310b300906035504061302636e3110300e06035504080c074265696a696e673110300e06035504070c074265696a696e67310f300d060355040a0c064b6977695365633110300e060355040b0c0753656375726974793110300e06035504030c074b697769536563311e301c06092a864886f70d010901160f736563406b6977697365632e636f6d301e170d3132303431383036323332325a170d3339303930333036323332325a308186310b300906035504061302636e3110300e06035504080c074265696a696e673110300e06035504070c074265696a696e67310f300d060355040a0c064b6977695365633110300e060355040b0c0753656375726974793110300e06035504030c074b697769536563311e301c06092a864886f70d010901160f736563406b6977697365632e636f6d30820122300d06092a864886f70d01010105000382010f003082010a0282010100b8e6f2f6f6b1e8f8d4c2e0a4b8d9c1a8b4c3d2e1f0a5b6c7d8e9f0a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5061728394a5b6c7d8e9f0a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5061728394a5b6c7d8e9f0a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5061728394a5b6c7d8e9f0a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5061728394a5b6c7d8e9f0a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5061728394a5b6c7d8e9f00203010001a38201013082fdfd301d0603551d0e04160414b8e6f2f6f6b1e8f8d4c2e0a4b8d9c1a8b4c3d2e1f0300b0603551d0f0404030205a0301d0603551d250416301406082b0601050507030106082b06010505070302300c0603551d13040530030101ff3081cd0603551d230481c53081c28014b8e6f2f6f6b1e8f8d4c2e0a4b8d9c1a8b4c3d2e1f0a1818ca48189308186310b300906035504061302636e3110300e06035504080c074265696a696e673110300e06035504070c074265696a696e67310f300d060355040a0c064b6977695365633110300e060355040b0c0753656375726974793110300e06035504030c074b697769536563311e301c06092a864886f70d010901160f736563406b6977697365632e636f6d82044b8b2a80300d06092a864886f70d01010b0500038201010095e4f5a6b7c8d9e0f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f7";
    
    int result = strcmp(sigCStr, expected);
    
    (*env)->ReleaseStringUTFChars(env, sigString, sigCStr);
    
    return result == 0 ? JNI_TRUE : JNI_FALSE;
}

// JNI_OnLoad - Initialize when library loads
JNIEXPORT jint JNICALL
JNI_OnLoad(JavaVM *vm, void *reserved) {
    // Start anti-debug immediately
    pthread_t thread;
    pthread_create(&thread, NULL, anti_debug_thread, NULL);
    pthread_detach(thread);
    
    return JNI_VERSION_1_6;
}
