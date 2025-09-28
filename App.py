import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import hashlib
import os
from typing import List, Tuple

class CryptoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Aplikasi Enkripsi dan Dekripsi")
        self.root.geometry("800x700")
        self.root.configure(bg='#f0f0f0')
        
        # Style
        style = ttk.Style()
        style.theme_use('clam')
        
        self.setup_ui()
        
    def setup_ui(self):
        # Title
        title_label = tk.Label(self.root, text="APLIKASI KRIPTOGRAFI", 
                              font=("Arial", 20, "bold"), bg='#f0f0f0', fg='#2c3e50')
        title_label.pack(pady=10)
        
        # Notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Create tabs
        self.create_caesar_tab()
        self.create_railfence_tab()
        self.create_block_cipher_tab()
        self.create_stream_cipher_tab()
        self.create_combined_tab()
        
    def create_caesar_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Caesar Cipher")
        
        # Input
        tk.Label(frame, text="Text:").pack(anchor="w", padx=10, pady=5)
        self.caesar_input = scrolledtext.ScrolledText(frame, height=4, width=80)
        self.caesar_input.pack(padx=10, pady=5)
        
        # Key
        key_frame = tk.Frame(frame)
        key_frame.pack(pady=5)
        tk.Label(key_frame, text="Key (shift):").pack(side="left", padx=10)
        self.caesar_key = tk.Entry(key_frame, width=10)
        self.caesar_key.pack(side="left", padx=5)
        self.caesar_key.insert(0, "3")
        
        # Buttons
        btn_frame = tk.Frame(frame)
        btn_frame.pack(pady=10)
        ttk.Button(btn_frame, text="Encrypt", 
                  command=lambda: self.caesar_process(True)).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Decrypt", 
                  command=lambda: self.caesar_process(False)).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Clear", 
                  command=self.clear_caesar).pack(side="left", padx=5)
        
        # Output
        tk.Label(frame, text="Result:").pack(anchor="w", padx=10, pady=5)
        self.caesar_output = scrolledtext.ScrolledText(frame, height=4, width=80)
        self.caesar_output.pack(padx=10, pady=5)
        
    def create_railfence_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Rail Fence")
        
        # Input
        tk.Label(frame, text="Text:").pack(anchor="w", padx=10, pady=5)
        self.railfence_input = scrolledtext.ScrolledText(frame, height=4, width=80)
        self.railfence_input.pack(padx=10, pady=5)
        
        # Key
        key_frame = tk.Frame(frame)
        key_frame.pack(pady=5)
        tk.Label(key_frame, text="Number of Rails:").pack(side="left", padx=10)
        self.railfence_key = tk.Entry(key_frame, width=10)
        self.railfence_key.pack(side="left", padx=5)
        self.railfence_key.insert(0, "3")
        
        # Buttons
        btn_frame = tk.Frame(frame)
        btn_frame.pack(pady=10)
        ttk.Button(btn_frame, text="Encrypt", 
                  command=lambda: self.railfence_process(True)).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Decrypt", 
                  command=lambda: self.railfence_process(False)).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Clear", 
                  command=self.clear_railfence).pack(side="left", padx=5)
        
        # Output
        tk.Label(frame, text="Result:").pack(anchor="w", padx=10, pady=5)
        self.railfence_output = scrolledtext.ScrolledText(frame, height=4, width=80)
        self.railfence_output.pack(padx=10, pady=5)
        
    def create_block_cipher_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Block Cipher (AES-like)")
        
        # Input
        tk.Label(frame, text="Text:").pack(anchor="w", padx=10, pady=5)
        self.block_input = scrolledtext.ScrolledText(frame, height=4, width=80)
        self.block_input.pack(padx=10, pady=5)
        
        # Key
        key_frame = tk.Frame(frame)
        key_frame.pack(pady=5)
        tk.Label(key_frame, text="Key:").pack(side="left", padx=10)
        self.block_key = tk.Entry(key_frame, width=30)
        self.block_key.pack(side="left", padx=5)
        self.block_key.insert(0, "mysecretkey12345")
        
        # Buttons
        btn_frame = tk.Frame(frame)
        btn_frame.pack(pady=10)
        ttk.Button(btn_frame, text="Encrypt", 
                  command=lambda: self.block_process(True)).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Decrypt", 
                  command=lambda: self.block_process(False)).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Clear", 
                  command=self.clear_block).pack(side="left", padx=5)
        
        # Output
        tk.Label(frame, text="Result:").pack(anchor="w", padx=10, pady=5)
        self.block_output = scrolledtext.ScrolledText(frame, height=4, width=80)
        self.block_output.pack(padx=10, pady=5)
        
    def create_stream_cipher_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Stream Cipher (RC4-like)")
        
        # Input
        tk.Label(frame, text="Text:").pack(anchor="w", padx=10, pady=5)
        self.stream_input = scrolledtext.ScrolledText(frame, height=4, width=80)
        self.stream_input.pack(padx=10, pady=5)
        
        # Key
        key_frame = tk.Frame(frame)
        key_frame.pack(pady=5)
        tk.Label(key_frame, text="Key:").pack(side="left", padx=10)
        self.stream_key = tk.Entry(key_frame, width=30)
        self.stream_key.pack(side="left", padx=5)
        self.stream_key.insert(0, "streamkey")
        
        # Buttons
        btn_frame = tk.Frame(frame)
        btn_frame.pack(pady=10)
        ttk.Button(btn_frame, text="Encrypt", 
                  command=lambda: self.stream_process(True)).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Decrypt", 
                  command=lambda: self.stream_process(False)).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Clear", 
                  command=self.clear_stream).pack(side="left", padx=5)
        
        # Output
        tk.Label(frame, text="Result:").pack(anchor="w", padx=10, pady=5)
        self.stream_output = scrolledtext.ScrolledText(frame, height=4, width=80)
        self.stream_output.pack(padx=10, pady=5)
        
    def create_combined_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Combined Method")
        
        # Input
        tk.Label(frame, text="Text:").pack(anchor="w", padx=10, pady=5)
        self.combined_input = scrolledtext.ScrolledText(frame, height=3, width=80)
        self.combined_input.pack(padx=10, pady=5)
        
        # Keys
        keys_frame = tk.Frame(frame)
        keys_frame.pack(pady=5)
        
        tk.Label(keys_frame, text="Caesar Key:").grid(row=0, column=0, padx=5)
        self.combined_caesar_key = tk.Entry(keys_frame, width=10)
        self.combined_caesar_key.grid(row=0, column=1, padx=5)
        self.combined_caesar_key.insert(0, "3")
        
        tk.Label(keys_frame, text="Rails:").grid(row=0, column=2, padx=5)
        self.combined_rails_key = tk.Entry(keys_frame, width=10)
        self.combined_rails_key.grid(row=0, column=3, padx=5)
        self.combined_rails_key.insert(0, "3")
        
        tk.Label(keys_frame, text="Block Key:").grid(row=1, column=0, padx=5, pady=5)
        self.combined_block_key = tk.Entry(keys_frame, width=20)
        self.combined_block_key.grid(row=1, column=1, columnspan=2, padx=5, pady=5)
        self.combined_block_key.insert(0, "blockkey123")
        
        tk.Label(keys_frame, text="Stream Key:").grid(row=1, column=3, padx=5, pady=5)
        self.combined_stream_key = tk.Entry(keys_frame, width=15)
        self.combined_stream_key.grid(row=1, column=4, padx=5, pady=5)
        self.combined_stream_key.insert(0, "streamkey")
        
        # Buttons
        btn_frame = tk.Frame(frame)
        btn_frame.pack(pady=10)
        ttk.Button(btn_frame, text="Encrypt All", 
                  command=lambda: self.combined_process(True)).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Decrypt All", 
                  command=lambda: self.combined_process(False)).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Clear", 
                  command=self.clear_combined).pack(side="left", padx=5)
        
        # Output
        tk.Label(frame, text="Result:").pack(anchor="w", padx=10, pady=5)
        self.combined_output = scrolledtext.ScrolledText(frame, height=3, width=80)
        self.combined_output.pack(padx=10, pady=5)
        
        # Process info
        tk.Label(frame, text="Process Info:").pack(anchor="w", padx=10, pady=5)
        self.combined_info = scrolledtext.ScrolledText(frame, height=4, width=80)
        self.combined_info.pack(padx=10, pady=5)
        
    # Caesar Cipher Implementation
    def caesar_encrypt(self, text: str, shift: int) -> str:
        result = ""
        for char in text:
            if char.isalpha():
                ascii_offset = 65 if char.isupper() else 97
                result += chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
            else:
                result += char
        return result
        
    def caesar_decrypt(self, text: str, shift: int) -> str:
        return self.caesar_encrypt(text, -shift)
        
    # Rail Fence Implementation
    def railfence_encrypt(self, text: str, rails: int) -> str:
        if rails == 1:
            return text
            
        fence = [[] for _ in range(rails)]
        rail = 0
        direction = 1
        
        for char in text:
            fence[rail].append(char)
            rail += direction
            
            if rail == rails - 1 or rail == 0:
                direction = -direction
                
        return ''.join(''.join(rail) for rail in fence)
        
    def railfence_decrypt(self, text: str, rails: int) -> str:
        if rails == 1:
            return text
            
        # Create pattern to find positions
        pattern = []
        rail = 0
        direction = 1
        
        for i in range(len(text)):
            pattern.append(rail)
            rail += direction
            if rail == rails - 1 or rail == 0:
                direction = -direction
                
        # Count chars per rail
        rail_counts = [0] * rails
        for r in pattern:
            rail_counts[r] += 1
            
        # Fill rails with encrypted text
        fence = [[] for _ in range(rails)]
        index = 0
        for rail_num in range(rails):
            fence[rail_num] = list(text[index:index + rail_counts[rail_num]])
            index += rail_counts[rail_num]
            
        # Read message
        result = []
        rail_indices = [0] * rails
        for rail_num in pattern:
            result.append(fence[rail_num][rail_indices[rail_num]])
            rail_indices[rail_num] += 1
            
        return ''.join(result)
        
    # Block Cipher (Simple AES-like implementation)
    def block_encrypt(self, text: str, key: str) -> str:
        # Pad text to multiple of 16
        padded = text + '\0' * (16 - len(text) % 16)
        
        # Generate key schedule from key
        key_bytes = self.generate_key_bytes(key, 16)
        
        result = []
        for i in range(0, len(padded), 16):
            block = padded[i:i+16]
            encrypted_block = self.encrypt_block(block, key_bytes)
            result.append(encrypted_block.hex())
            
        return ' '.join(result)
        
    def block_decrypt(self, text: str, key: str) -> str:
        try:
            blocks = text.split()
            key_bytes = self.generate_key_bytes(key, 16)
            
            result = []
            for block_hex in blocks:
                block_bytes = bytes.fromhex(block_hex)
                decrypted_block = self.decrypt_block(block_bytes, key_bytes)
                result.append(decrypted_block.decode('utf-8', errors='ignore'))
                
            return ''.join(result).rstrip('\0')
        except:
            return "Error: Invalid encrypted text"
            
    def generate_key_bytes(self, key: str, length: int) -> bytes:
        # Simple key derivation
        key_hash = hashlib.sha256(key.encode()).digest()
        return key_hash[:length]
        
    def encrypt_block(self, block: str, key: bytes) -> bytes:
        block_bytes = block.encode('utf-8')
        result = bytearray()
        for i in range(len(block_bytes)):
            result.append(block_bytes[i] ^ key[i % len(key)])
        return bytes(result)
        
    def decrypt_block(self, block: bytes, key: bytes) -> bytes:
        result = bytearray()
        for i in range(len(block)):
            result.append(block[i] ^ key[i % len(key)])
        return bytes(result)
        
    # Stream Cipher (RC4-like implementation)
    def stream_cipher(self, text: str, key: str) -> str:
        # Key Scheduling Algorithm (KSA)
        key_bytes = key.encode()
        S = list(range(256))
        j = 0
        
        for i in range(256):
            j = (j + S[i] + key_bytes[i % len(key_bytes)]) % 256
            S[i], S[j] = S[j], S[i]
            
        # Pseudo-Random Generation Algorithm (PRGA)
        i = j = 0
        result = []
        
        for char in text:
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            
            keystream_byte = S[(S[i] + S[j]) % 256]
            result.append(chr(ord(char) ^ keystream_byte))
            
        return ''.join(result)
        
    # Process functions
    def caesar_process(self, encrypt=True):
        try:
            text = self.caesar_input.get("1.0", tk.END).strip()
            shift = int(self.caesar_key.get())
            
            if encrypt:
                result = self.caesar_encrypt(text, shift)
            else:
                result = self.caesar_decrypt(text, shift)
                
            self.caesar_output.delete("1.0", tk.END)
            self.caesar_output.insert("1.0", result)
        except ValueError:
            messagebox.showerror("Error", "Key harus berupa angka!")
        except Exception as e:
            messagebox.showerror("Error", f"Terjadi kesalahan: {str(e)}")
            
    def railfence_process(self, encrypt=True):
        try:
            text = self.railfence_input.get("1.0", tk.END).strip()
            rails = int(self.railfence_key.get())
            
            if rails < 2:
                messagebox.showerror("Error", "Jumlah rails minimal 2!")
                return
                
            if encrypt:
                result = self.railfence_encrypt(text, rails)
            else:
                result = self.railfence_decrypt(text, rails)
                
            self.railfence_output.delete("1.0", tk.END)
            self.railfence_output.insert("1.0", result)
        except ValueError:
            messagebox.showerror("Error", "Jumlah rails harus berupa angka!")
        except Exception as e:
            messagebox.showerror("Error", f"Terjadi kesalahan: {str(e)}")
            
    def block_process(self, encrypt=True):
        try:
            text = self.block_input.get("1.0", tk.END).strip()
            key = self.block_key.get()
            
            if not key:
                messagebox.showerror("Error", "Key tidak boleh kosong!")
                return
                
            if encrypt:
                result = self.block_encrypt(text, key)
            else:
                result = self.block_decrypt(text, key)
                
            self.block_output.delete("1.0", tk.END)
            self.block_output.insert("1.0", result)
        except Exception as e:
            messagebox.showerror("Error", f"Terjadi kesalahan: {str(e)}")
            
    def stream_process(self, encrypt=True):
        try:
            text = self.stream_input.get("1.0", tk.END).strip()
            key = self.stream_key.get()
            
            if not key:
                messagebox.showerror("Error", "Key tidak boleh kosong!")
                return
                
            # Stream cipher is symmetric
            result = self.stream_cipher(text, key)
            
            # Convert to hex for display if contains non-printable chars
            if encrypt and any(ord(c) < 32 or ord(c) > 126 for c in result):
                result = result.encode('latin-1').hex()
            elif not encrypt and all(c in '0123456789abcdef' for c in text.lower()):
                try:
                    result = bytes.fromhex(text).decode('latin-1')
                    result = self.stream_cipher(result, key)
                except:
                    pass
                
            self.stream_output.delete("1.0", tk.END)
            self.stream_output.insert("1.0", result)
        except Exception as e:
            messagebox.showerror("Error", f"Terjadi kesalahan: {str(e)}")
            
    def combined_process(self, encrypt=True):
        try:
            text = self.combined_input.get("1.0", tk.END).strip()
            
            # Get keys
            caesar_shift = int(self.combined_caesar_key.get())
            rails = int(self.combined_rails_key.get())
            block_key = self.combined_block_key.get()
            stream_key = self.combined_stream_key.get()
            
            if rails < 2:
                messagebox.showerror("Error", "Jumlah rails minimal 2!")
                return
                
            if not block_key or not stream_key:
                messagebox.showerror("Error", "Semua key harus diisi!")
                return
                
            info_text = ""
            
            if encrypt:
                # Encryption order: Caesar -> Rail Fence -> Block -> Stream
                step1 = self.caesar_encrypt(text, caesar_shift)
                info_text += f"1. Caesar Cipher: {step1}\n"
                
                step2 = self.railfence_encrypt(step1, rails)
                info_text += f"2. Rail Fence: {step2}\n"
                
                step3 = self.block_encrypt(step2, block_key)
                info_text += f"3. Block Cipher: {step3}\n"
                
                result = self.stream_cipher(step3, stream_key)
                # Convert to hex if contains non-printable
                if any(ord(c) < 32 or ord(c) > 126 for c in result):
                    result = result.encode('latin-1').hex()
                info_text += f"4. Stream Cipher: {result}"
            else:
                # Decryption order: Stream -> Block -> Rail Fence -> Caesar
                step1 = text
                # Handle hex input
                if all(c in '0123456789abcdef' for c in text.lower()) and len(text) % 2 == 0:
                    try:
                        step1 = bytes.fromhex(text).decode('latin-1')
                    except:
                        pass
                
                step1 = self.stream_cipher(step1, stream_key)
                info_text += f"1. Stream Cipher: {step1}\n"
                
                step2 = self.block_decrypt(step1, block_key)
                info_text += f"2. Block Cipher: {step2}\n"
                
                step3 = self.railfence_decrypt(step2, rails)
                info_text += f"3. Rail Fence: {step3}\n"
                
                result = self.caesar_decrypt(step3, caesar_shift)
                info_text += f"4. Caesar Cipher: {result}"
                
            self.combined_output.delete("1.0", tk.END)
            self.combined_output.insert("1.0", result)
            
            self.combined_info.delete("1.0", tk.END)
            self.combined_info.insert("1.0", info_text)
            
        except ValueError:
            messagebox.showerror("Error", "Key numerik harus berupa angka!")
        except Exception as e:
            messagebox.showerror("Error", f"Terjadi kesalahan: {str(e)}")
            
    # Clear functions
    def clear_caesar(self):
        self.caesar_input.delete("1.0", tk.END)
        self.caesar_output.delete("1.0", tk.END)
        
    def clear_railfence(self):
        self.railfence_input.delete("1.0", tk.END)
        self.railfence_output.delete("1.0", tk.END)
        
    def clear_block(self):
        self.block_input.delete("1.0", tk.END)
        self.block_output.delete("1.0", tk.END)
        
    def clear_stream(self):
        self.stream_input.delete("1.0", tk.END)
        self.stream_output.delete("1.0", tk.END)
        
    def clear_combined(self):
        self.combined_input.delete("1.0", tk.END)
        self.combined_output.delete("1.0", tk.END)
        self.combined_info.delete("1.0", tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoApp(root)
    root.mainloop()