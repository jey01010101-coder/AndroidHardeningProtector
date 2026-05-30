#!/usr/bin/env python3
"""
DEX Processor - Extracts and encrypts individual methods (360 style)
"""

import struct
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

class DEXProcessor:
    """Process DEX files and extract methods for encryption"""
    
    def __init__(self, dex_data):
        self.dex_data = bytearray(dex_data)
        self.header = self.parse_header()
        self.methods = []
        
    def parse_header(self):
        """Parse DEX header"""
        if len(self.dex_data) < 0x70:
            raise ValueError("Invalid DEX file")
        
        # Check magic
        magic = self.dex_data[0:8]
        if not magic.startswith(b'dex\n'):
            raise ValueError("Not a valid DEX file")
        
        return {
            'magic': magic,
            'checksum': struct.unpack('<I', self.dex_data[0x08:0x0C])[0],
            'signature': self.dex_data[0x0C:0x20],
            'file_size': struct.unpack('<I', self.dex_data[0x20:0x24])[0],
            'header_size': struct.unpack('<I', self.dex_data[0x24:0x28])[0],
            'endian_tag': struct.unpack('<I', self.dex_data[0x28:0x2C])[0],
            'link_size': struct.unpack('<I', self.dex_data[0x2C:0x30])[0],
            'link_off': struct.unpack('<I', self.dex_data[0x30:0x34])[0],
            'map_off': struct.unpack('<I', self.dex_data[0x34:0x38])[0],
            'string_ids_size': struct.unpack('<I', self.dex_data[0x38:0x3C])[0],
            'string_ids_off': struct.unpack('<I', self.dex_data[0x3C:0x40])[0],
            'type_ids_size': struct.unpack('<I', self.dex_data[0x40:0x44])[0],
            'type_ids_off': struct.unpack('<I', self.dex_data[0x44:0x48])[0],
            'proto_ids_size': struct.unpack('<I', self.dex_data[0x48:0x4C])[0],
            'proto_ids_off': struct.unpack('<I', self.dex_data[0x4C:0x50])[0],
            'field_ids_size': struct.unpack('<I', self.dex_data[0x50:0x54])[0],
            'field_ids_off': struct.unpack('<I', self.dex_data[0x54:0x58])[0],
            'method_ids_size': struct.unpack('<I', self.dex_data[0x58:0x5C])[0],
            'method_ids_off': struct.unpack('<I', self.dex_data[0x5C:0x60])[0],
            'class_defs_size': struct.unpack('<I', self.dex_data[0x60:0x64])[0],
            'class_defs_off': struct.unpack('<I', self.dex_data[0x64:0x68])[0],
            'data_size': struct.unpack('<I', self.dex_data[0x68:0x6C])[0],
            'data_off': struct.unpack('<I', self.dex_data[0x6C:0x70])[0],
        }
    
    def extract_all_methods(self):
        """Extract all methods with their bytecode"""
        methods = []
        
        # Parse method IDs
        method_ids_off = self.header['method_ids_off']
        method_ids_size = self.header['method_ids_size']
        
        for i in range(method_ids_size):
            offset = method_ids_off + (i * 8)
            if offset + 8 > len(self.dex_data):
                break
                
            class_idx = struct.unpack('<H', self.dex_data[offset:offset+2])[0]
            proto_idx = struct.unpack('<H', self.dex_data[offset+2:offset+4])[0]
            name_idx = struct.unpack('<I', self.dex_data[offset+4:offset+8])[0]
            
            methods.append({
                'idx': i,
                'class_idx': class_idx,
                'proto_idx': proto_idx,
                'name_idx': name_idx,
                'bytecode': self.extract_method_bytecode(i)
            })
        
        self.methods = methods
        return methods
    
    def extract_method_bytecode(self, method_idx):
        """Extract bytecode for a specific method"""
        # Find code item for this method
        class_defs_off = self.header['class_defs_off']
        class_defs_size = self.header['class_defs_size']
        
        for i in range(class_defs_size):
            offset = class_defs_off + (i * 32)
            if offset + 32 > len(self.dex_data):
                break
                
            class_data_off = struct.unpack('<I', self.dex_data[offset+16:offset+20])[0]
            
            if class_data_off > 0:
                # Parse class data to find method
                bytecode = self.find_method_in_class_data(class_data_off, method_idx)
                if bytecode:
                    return bytecode
        
        return b''
    
    def find_method_in_class_data(self, class_data_off, target_method_idx):
        """Find method bytecode in class data section"""
        pos = class_data_off
        
        if pos >= len(self.dex_data):
            return b''
        
        # Skip static fields, instance fields
        static_fields_size = self.read_uleb128(pos)
        pos += self.get_uleb128_size(static_fields_size)
        
        for _ in range(static_fields_size):
            pos += self.skip_field(pos)
        
        instance_fields_size = self.read_uleb128(pos)
        pos += self.get_uleb128_size(instance_fields_size)
        
        for _ in range(instance_fields_size):
            pos += self.skip_field(pos)
        
        # Read direct methods
        direct_methods_size = self.read_uleb128(pos)
        pos += self.get_uleb128_size(direct_methods_size)
        
        for _ in range(direct_methods_size):
            method_idx_diff = self.read_uleb128(pos)
            pos += self.get_uleb128_size(method_idx_diff)
            access_flags = self.read_uleb128(pos)
            pos += self.get_uleb128_size(access_flags)
            code_off = self.read_uleb128(pos)
            pos += self.get_uleb128_size(code_off)
            
            # Check if this is our method
            if method_idx_diff == target_method_idx and code_off > 0:
                return self.extract_code_item(code_off)
        
        # Read virtual methods (similar logic)
        # ... (simplified for brevity)
        
        return b''
    
    def extract_code_item(self, code_off):
        """Extract code item bytecode"""
        if code_off + 16 > len(self.dex_data):
            return b''
        
        registers_size = struct.unpack('<H', self.dex_data[code_off:code_off+2])[0]
        ins_size = struct.unpack('<H', self.dex_data[code_off+2:code_off+4])[0]
        outs_size = struct.unpack('<H', self.dex_data[code_off+4:code_off+6])[0]
        tries_size = struct.unpack('<H', self.dex_data[code_off+6:code_off+8])[0]
        debug_info_off = struct.unpack('<I', self.dex_data[code_off+8:code_off+12])[0]
        insns_size = struct.unpack('<I', self.dex_data[code_off+12:code_off+16])[0]
        insns_off = code_off + 16
        
        # Extract actual bytecode instructions
        bytecode = self.dex_data[insns_off:insns_off + (insns_size * 2)]
        
        return bytes(bytecode)
    
    def encrypt_methods(self, methods, percentage=40):
        """Encrypt selected methods (360 style: random 40%)"""
        # Select methods to encrypt
        num_to_encrypt = int(len(methods) * percentage / 100)
        to_encrypt = random.sample(methods, min(num_to_encrypt, len(methods)))
        
        encrypted_methods = []
        
        for method in to_encrypt:
            if method['bytecode']:
                # XOR encryption with method index as key
                encrypted = self.xor_encrypt(method['bytecode'], method['idx'])
                method['encrypted_bytecode'] = encrypted
                method['is_encrypted'] = True
                encrypted_methods.append(method)
        
        return encrypted_methods
    
    def xor_encrypt(self, data, key):
        """XOR encryption with dynamic key (360 style)"""
        result = bytearray()
        key_bytes = key.to_bytes(4, 'little')
        
        for i, byte in enumerate(data):
            result.append(byte ^ key_bytes[i % 4])
        
        return bytes(result)
    
    def generate_decryption_stubs(self, encrypted_methods):
        """Generate decryption stubs for encrypted methods"""
        stubs = []
        
        for method in encrypted_methods:
            # Create stub that calls native decryption
            stub = self.create_decryption_stub(method)
            stubs.append({
                'method_idx': method['idx'],
                'stub_bytecode': stub
            })
        
        return stubs
    
    def create_decryption_stub(self, method):
        """Create a decryption stub (calls native library)"""
        # Generate smali code for stub
        stub_smali = f"""
        .method private static decryptMethod{method['idx']}([B)[B
            .locals 1
            const-string v0, "libdecryptor.so"
            invoke-static {{v0}}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
            invoke-static {{p0, {method['idx']}}}, Lcom/kiwi/NativeDecryptor;->decryptMethod([BI)[B
            move-result-object v0
            return-object v0
        .end method
        """
        
        # Convert smali to bytecode (simplified)
        # In production, use smali assembler
        return b'\x00' * 16  # Placeholder
    
    def create_encrypted_dex(self, method_stubs):
        """Create DEX with encrypted methods and decryption stubs"""
        # Replace original method bytecode with stubs
        modified_dex = bytearray(self.dex_data)
        
        for stub in method_stubs:
            # Overwrite method code with stub
            # This requires updating DEX offsets and sizes
            pass
        
        # Add native method declarations
        # Add decryption helper classes
        
        return bytes(modified_dex)
    
    # Helper methods for DEX parsing
    def read_uleb128(self, offset):
        """Read ULEB128 value from DEX"""
        result = 0
        shift = 0
        
        while True:
            if offset >= len(self.dex_data):
                return 0
            byte = self.dex_data[offset]
            offset += 1
            result |= (byte & 0x7F) << shift
            if (byte & 0x80) == 0:
                break
            shift += 7
        
        return result
    
    def get_uleb128_size(self, value):
        """Get size of ULEB128 encoded value"""
        if value == 0:
            return 1
        size = 0
        while value > 0:
            value >>= 7
            size += 1
        return size
    
    def skip_field(self, offset):
        """Skip field definition in class data"""
        # Skip field_idx_diff and access_flags
        pos = offset
        field_idx_diff = self.read_uleb128(pos)
        pos += self.get_uleb128_size(field_idx_diff)
        access_flags = self.read_uleb128(pos)
        pos += self.get_uleb128_size(access_flags)
        return pos - offset