import os
from PIL import Image

def analyze_png(img_path):
    print(f"Analyzing {img_path}...")
    try:
        img = Image.open(img_path)
        print(f"Format: {img.format}")
        print(f"Size: {img.size}")
        print(f"Mode: {img.mode}")
        print("Info:", img.info)
        
        # Let's inspect pixel values or LSB
        pixels = list(img.getdata())
        print(f"Total pixels: {len(pixels)}")
        
        # Check first 50 pixels
        print("First 50 pixels:", pixels[:50])
        
        # 1. Simple LSB extraction (bit 0 of all color channels concatenated)
        # We can extract LSB channel by channel or interleaved.
        # Let's try interleaved first: R, G, B, R, G, B...
        bits = []
        for p in pixels:
            if isinstance(p, int):
                # Grayscale
                bits.append(p & 1)
            else:
                # RGB / RGBA
                # Let's extract R, G, B (ignoring A if present, or including it? Let's check mode)
                channels = p[:3] # RGB
                for val in channels:
                    bits.append(val & 1)
        
        # Convert bits to bytes
        byte_data = bytearray()
        for i in range(0, len(bits), 8):
            byte = 0
            for j in range(8):
                if i + j < len(bits):
                    byte |= (bits[i + j] << (7 - j)) # MSB first
            byte_data.append(byte)
        
        print("LSB MSB-first (interleaved RGB) preview:")
        print(byte_data[:200])
        
        # Try LSB LSB-first
        byte_data_lsb = bytearray()
        for i in range(0, len(bits), 8):
            byte = 0
            for j in range(8):
                if i + j < len(bits):
                    byte |= (bits[i + j] << j) # LSB first
            byte_data_lsb.append(byte)
            
        print("LSB LSB-first (interleaved RGB) preview:")
        print(byte_data_lsb[:200])
        
        # Try extracting LSB from individual channels
        for ch_idx, ch_name in enumerate(["Red", "Green", "Blue"]):
            ch_bits = []
            for p in pixels:
                if isinstance(p, int):
                    break
                ch_bits.append(p[ch_idx] & 1)
            if not ch_bits:
                continue
                
            # MSB-first
            ch_byte_data = bytearray()
            for i in range(0, len(ch_bits), 8):
                byte = 0
                for j in range(8):
                    if i + j < len(ch_bits):
                        byte |= (ch_bits[i + j] << (7 - j))
                ch_byte_data.append(byte)
            print(f"LSB MSB-first ({ch_name} only) preview:")
            print(ch_byte_data[:100])
            
            # LSB-first
            ch_byte_data_lsb = bytearray()
            for i in range(0, len(ch_bits), 8):
                byte = 0
                for j in range(8):
                    if i + j < len(ch_bits):
                        byte |= (ch_bits[i + j] << j)
                ch_byte_data_lsb.append(byte)
            print(f"LSB LSB-first ({ch_name} only) preview:")
            print(ch_byte_data_lsb[:100])
            
    except Exception as e:
        print("Error:", e)

if __name__ == "__main__":
    analyze_png(r"D:\CTF_archives\Ewu_CTF_Final_onsite\Forensics\files\cover.png")
