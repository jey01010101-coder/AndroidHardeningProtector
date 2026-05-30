
package com.kiwi.protector;

import android.app.Application;
import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import dalvik.system.DexClassLoader;
import dalvik.system.InMemoryDexClassLoader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.util.zip.ZipFile;

/**
 * Stub Application - 360 Jiagu style loader
 * This replaces the original Application class and loads the real app
 */
public class StubApplication extends Application {
    
    private static final String TAG = "StubApplication";
    private static final String ENCRYPTED_DEX_PATH = "lib/arm64-v8a/libprotect.so";
    
    static {
        // Load native library for decryption
        System.loadLibrary("decryptor");
    }
    
    @Override
    protected void attachBaseContext(Context base) {
        super.attachBaseContext(base);
        
        // Start anti-debug checks
        NativeDecryptor.startAntiDebug();
        
        // Verify signature before loading
        if (!verifySignature()) {
            // Signature mismatch - possible tampering
            throw new RuntimeException("Invalid signature");
        }
        
        // Load real application
        loadRealApplication();
    }
    
    private boolean verifySignature() {
        // Verify in native (harder to bypass)
        return NativeDecryptor.verifySignature(this);
    }
    
    private void loadRealApplication() {
        try {
            byte[] encryptedDex = extractEncryptedDex();
            byte[] decryptedDex = decryptDex(encryptedDex);
            
            ClassLoader loader;
            
            if (Build.VERSION.SDK_INT >= 26) {
                // Android 8+: Load directly from memory (no disk write)
                ByteBuffer buffer = ByteBuffer.wrap(decryptedDex);
                loader = new InMemoryDexClassLoader(buffer, getClassLoader());
            } else {
                // Android 7-: Write to disk then load
                File dexFile = File.createTempFile("real", ".dex", getCacheDir());
                FileOutputStream fos = new FileOutputStream(dexFile);
                fos.write(decryptedDex);
                fos.close();
                
                loader = new DexClassLoader(
                    dexFile.getAbsolutePath(),
                    getCacheDir().getAbsolutePath(),
                    null,
                    getClassLoader()
                );
                
                dexFile.deleteOnExit();
            }
            
            // Find and invoke real Application class
            String realAppClass = getRealApplicationClass();
            Class<?> realApp = loader.loadClass(realAppClass);
            
            // Create instance and attach
            Application app = (Application) realApp.newInstance();
            Method attach = Application.class.getDeclaredMethod(
                "attachBaseContext", Context.class);
            attach.setAccessible(true);
            attach.invoke(app, this);
            
            // Call onCreate
            app.onCreate();
            
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("Failed to load real application", e);
        }
    }
    
    private byte[] extractEncryptedDex() {
        // Extract from APK where it's hidden
        try {
            ZipFile zip = new ZipFile(getApplicationInfo().sourceDir);
            java.util.zip.ZipEntry entry = zip.getEntry(ENCRYPTED_DEX_PATH);
            
            if (entry == null) {
                // Try alternative hiding locations
                entry = zip.getEntry("assets/encrypted_dex.bin");
            }
            
            if (entry == null) {
                throw new RuntimeException("Encrypted DEX not found");
            }
            
            InputStream is = zip.getInputStream(entry);
            byte[] data = new byte[(int) entry.getSize()];
            is.read(data);
            is.close();
            zip.close();
            
            return data;
            
        } catch (Exception e) {
            throw new RuntimeException("Failed to extract encrypted DEX", e);
        }
    }
    
    private byte[] decryptDex(byte[] encrypted) {
        // Decrypt using native method
        // First try method-by-method decryption
        return NativeDecryptor.aesDecrypt(encrypted);
    }
    
    private String getRealApplicationClass() {
        // Read from AndroidManifest or embedded config
        // This should be extracted from original manifest
        return "com.original.app.MainApplication";
    }
    
    @Override
    public void onCreate() {
        super.onCreate();
        // Real app's onCreate will be called by loadRealApplication
    }
}
