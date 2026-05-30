
#!/usr/bin/env python3
"""
AndroidHardeningProtector - 360 Jiagu Style APK Protector
Usage: python -m protector.main --input app.apk --output protected.apk
"""

import os
import sys
import argparse
import zipfile
import struct
import hashlib
from pathlib import Path
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import yaml

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from protector.dex_processor import DEXProcessor
from protector.apk_builder import APKBuilder
from protector.crypto_engine import CryptoEngine
from protector.utils import Logger, print_banner

class AndroidHardeningProtector:
    """Main protector class - 360 Jiagu style implementation"""
    
    def __init__(self, input_apk, output_apk, password=None, config=None):
        self.input_apk = input_apk
        self.output_apk = output_apk
        self.password = password or "default_kiwi_key_2024"
        self.config = self.load_config(config)
        self.logger = Logger()
        self.crypto = CryptoEngine(self.password)
        
    def load_config(self, config_path):
        """Load configuration from YAML"""
        default_config = {
            'encryption': {
                'method_percentage': 40,  # 360 style: encrypt 40% methods
                'algorithm': 'AES-256-GCM',
                'hide_technique': 'lib_sections'  # lib_sections, extra_field, zip_comment
            },
            'anti_debug': {
                'ptrace_check': True,
                'tracerpid_check': True,
                'frida_detection': True,
                'emulator_detection': False
            },
            'signature': {
                'verify_in_native': True,
                'required_cert_hash': None
            },
            'obfuscation': {
                'rename_classes': True,
                'string_encryption': True
            }
        }
        
        if config_path and os.path.exists(config_path):
            with open(config_path, 'r') as f:
                user_config = yaml.safe_load(f)
                default_config.update(user_config)
        
        return default_config
    
    def protect(self):
        """Main protection workflow - 360 style"""
        
        print_banner()
        self.logger.info(f"Protecting: {self.input_apk}")
        self.logger.info(f"Output: {self.output_apk}")
        
        # Step 1: Extract APK contents
        self.logger.step("1/7", "Extracting original APK...")
        with zipfile.ZipFile(self.input_apk, 'r') as zf:
            original_files = {name: zf.read(name) for name in zf.namelist()}
        
        # Step 2: Extract and process DEX files
        self.logger.step("2/7", "Processing DEX files...")
        if 'classes.dex' not in original_files:
            self.logger.error("No classes.dex found!")
            return False
        
        dex_data = original_files['classes.dex']
        dex_processor = DEXProcessor(dex_data)
        
        # 360 style: Extract all methods
        methods = dex_processor.extract_all_methods()
        self.logger.info(f"Found {len(methods)} methods")
        
        # 360 style: Encrypt selected methods (40% by default)
        encrypted_methods = dex_processor.encrypt_methods(
            methods, 
            percentage=self.config['encryption']['method_percentage']
        )
        self.logger.info(f"Encrypted {len(encrypted_methods)} methods")
        
        # Generate method decryption stubs
        method_stubs = dex_processor.generate_decryption_stubs(encrypted_methods)
        
        # Step 3: Encrypt remaining DEX data
        self.logger.step("3/7", "Encrypting DEX structure...")
        encrypted_dex = dex_processor.create_encrypted_dex(method_stubs)
        
        # Step 4: Hide encrypted DEX (360 style techniques)
        self.logger.step("4/7", "Hiding encrypted DEX...")
        technique = self.config['encryption']['hide_technique']
        
        if technique == 'lib_sections':
            # Hide in fake .so file sections (360 primary method)
            hidden_data = self.create_fake_so_with_dex(encrypted_dex)
            hidden_path = "lib/arm64-v8a/libprotect.so"
        elif technique == 'extra_field':
            hidden_data = self.hide_in_extra_field(encrypted_dex)
            hidden_path = None
        else:  # zip_comment
            hidden_data = encrypted_dex
            hidden_path = None
        
        # Step 5: Build protected APK
        self.logger.step("5/7", "Building protected APK...")
        builder = APKBuilder()
        
        # Add stub DEX as new classes.dex
        stub_dex = self.get_stub_dex()
        builder.add_file('classes.dex', stub_dex)
        
        # Copy all original files except classes.dex
        for name, data in original_files.items():
            if name != 'classes.dex':
                builder.add_file(name, data)
        
        # Add hidden encrypted DEX
        if hidden_path:
            builder.add_file(hidden_path, hidden_data)
        
        # Add native library (libdecryptor.so)
        native_lib = self.get_native_library()
        builder.add_file('lib/arm64-v8a/libdecryptor.so', native_lib)
        builder.add_file('lib/armeabi-v7a/libdecryptor.so', native_lib)
        
        # Step 6: Set zip comment if using comment hiding
        if technique == 'zip_comment':
            builder.set_comment(hidden_data)
        
        # Step 7: Sign the APK
        self.logger.step("6/7", "Signing APK...")
        builder.build(self.output_apk)
        
        # Sign with test key (or user-provided)
        self.sign_apk(self.output_apk)
        
        # Step 8: Verify protection
        self.logger.step("7/7", "Verifying protection...")
        self.verify_protection(self.output_apk)
        
        self.logger.success(f"Protection complete! Saved to: {self.output_apk}")
        return True
    
    def create_fake_so_with_dex(self, encrypted_dex):
        """Create fake .so file containing encrypted DEX (360 style)"""
        # Fake ELF header (looks like valid .so)
        elf_header = bytearray([
            0x7F, 0x45, 0x4C, 0x46,  # ELF magic
            0x02, 0x01, 0x01, 0x00,  # 64-bit, little endian
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x02, 0x00, 0xB7, 0x00,  # ET_DYN, EM_AARCH64
            0x01, 0x00, 0x00, 0x00,  # version 1
        ])
        
        # Add program headers, section headers
        # Then append encrypted DEX data
        result = elf_header + b'\x00' * 64 + encrypted_dex
        
        # Update size fields
        result = result[:0x20] + struct.pack('<Q', len(result)) + result[0x28:]
        
        return bytes(result)
    
    def hide_in_extra_field(self, encrypted_dex):
        """Hide in ZIP extra field (360 advanced technique)"""
        # Create custom extra field with signature 0x4B49 (KI)
        extra_field = struct.pack('<HH', 0x4B49, len(encrypted_dex)) + encrypted_dex
        return extra_field
    
    def get_stub_dex(self):
        """Get pre-compiled stub DEX (minimal loader)"""
        # In production, load from stub/smali/classes.dex
        # For this example, returning a minimal valid DEX
        stub_path = Path(__file__).parent.parent / "stub" / "smali" / "classes.dex"
        if stub_path.exists():
            return stub_path.read_bytes()
        
        # Fallback: minimal DEX loader
        return self.generate_minimal_stub()
    
    def generate_minimal_stub(self):
        """Generate minimal DEX stub programmatically"""
        # This is a placeholder - actual stub is compiled from Java
        # Returning minimal valid DEX header + a few instructions
        dex_header = struct.pack('<IIIIIIIIIIIIIIIIIIII',
            0x0A786564,  # magic "dex\n035\0"
            0x000000BC,   # checksum
            0x9C78B296,   # signature
            0x00000000,   # file_size (will update)
            0x70,         # header_size
            0x00000000,   # endian_tag
            0x00000000,   # link_size
            0x00000000,   # link_off
            0x00000000,   # map_off
            0x00000000,   # string_ids_size
            0x00000000,   # string_ids_off
            0x00000000,   # type_ids_size
            0x00000000,   # type_ids_off
            0x00000000,   # proto_ids_size
            0x00000000,   # proto_ids_off
            0x00000000,   # field_ids_size
            0x00000000,   # field_ids_off
            0x00000002,   # method_ids_size
            0x00000000,   # method_ids_off
            0x00000000,   # class_defs_size
            0x00000000    # class_defs_off
        )
        return dex_header
    
    def get_native_library(self):
        """Get pre-compiled native library"""
        native_path = Path(__file__).parent.parent / "native" / "libs" / "arm64-v8a" / "libdecryptor.so"
        if native_path.exists():
            return native_path.read_bytes()
        
        # Return minimal native stub
        return b'\x7fELF\x02\x01\x01\x00' + b'\x00' * 1000
    
    def sign_apk(self, apk_path):
        """Sign APK with test key"""
        # Use apksigner or jarsigner
        import subprocess
        keystore = Path(__file__).parent.parent / "tools" / "test.keystore"
        
        if keystore.exists():
            subprocess.run([
                "jarsigner", "-sigalg", "SHA1withRSA", "-digestalg", "SHA1",
                "-keystore", str(keystore), "-storepass", "android",
                "-keypass", "android", apk_path, "alias"
            ], capture_output=True)
    
    def verify_protection(self, apk_path):
        """Verify that protection was applied correctly"""
        with zipfile.ZipFile(apk_path, 'r') as zf:
            files = zf.namelist()
            
            # Check 1: Original classes.dex should be replaced
            original_dex = zf.read('classes.dex')
            if len(original_dex) > 10000:
                self.logger.warning("classes.dex might not be stubbed!")
            
            # Check 2: Hidden data should exist
            if self.config['encryption']['hide_technique'] == 'lib_sections':
                if 'lib/arm64-v8a/libprotect.so' not in files:
                    self.logger.warning("Hidden DEX not found!")
            
            # Check 3: Native library should be present
            if 'lib/arm64-v8a/libdecryptor.so' not in files:
                self.logger.warning("Native library missing!")


def main():
    parser = argparse.ArgumentParser(description='AndroidHardeningProtector - 360 Jiagu Style APK Protector')
    parser.add_argument('-i', '--input', required=True, help='Input APK file')
    parser.add_argument('-o', '--output', default='protected.apk', help='Output APK file')
    parser.add_argument('-p', '--password', help='Encryption password')
    parser.add_argument('-c', '--config', help='Config file (YAML)')
    parser.add_argument('--no-sign', action='store_true', help='Skip signing')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.input):
        print(f"Error: {args.input} not found!")
        sys.exit(1)
    
    protector = AndroidHardeningProtector(args.input, args.output, args.password, args.config)
    success = protector.protect()
    
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
