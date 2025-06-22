import tkinter as tk
from tkinter import ttk, messagebox
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode
import re

# --- Vigenere Helpers ---
def vigenere_encrypt(text, key):
    result = ""
    key = key.lower()
    for i, char in enumerate(text):
        if char.isalpha():
            shift = ord(key[i % len(key)].lower()) - ord('a')
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - base + shift) % 26 + base)
        else:
            result += char
    return result

def vigenere_decrypt(text, key):
    result = ""
    key = key.lower()
    for i, char in enumerate(text):
        if char.isalpha():
            shift = ord(key[i % len(key)].lower()) - ord('a')
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - base - shift) % 26 + base)
        else:
            result += char
    return result

# --- Caesar Cipher ---
def caesar(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - base + shift) % 26 + base)
        else:
            result += char
    return result

# --- AES Helpers ---
def pad(text):
    return text + (16 - len(text) % 16) * chr(16 - len(text) % 16)

def unpad(text):
    return text[:-ord(text[-1])]

def aes_encrypt(plain_text, password):
    key = password.ljust(16, '0').encode()[:16]
    cipher = AES.new(key, AES.MODE_ECB)
    ct_bytes = cipher.encrypt(pad(plain_text).encode())
    return b64encode(ct_bytes).decode()

def aes_decrypt(cipher_text, password):
    key = password.ljust(16, '0').encode()[:16]
    cipher = AES.new(key, AES.MODE_ECB)
    pt = cipher.decrypt(b64decode(cipher_text)).decode()
    return unpad(pt)

# --- GUI ---
class CipherGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 Text Encryption/Decryption Tool")
        self.root.geometry("750x600")

        self.cipher_type = tk.StringVar(value="Caesar")
        self.mode = tk.StringVar(value="Encrypt")

        self.key_label = tk.Label(root, text="Key/Shift/Password:", font=("Arial", 12))
        self.key_entry = tk.Entry(root, font=("Arial", 12), width=25)
        self.key_entry.insert(0, "3")

        self.text_input = tk.Text(root, height=10, width=85, font=("Courier New", 11))
        self.text_output = tk.Text(root, height=10, width=85, font=("Courier New", 11), bg="#f5f5f5")

        ttk.Label(root, text="Cipher Type:").pack()
        ttk.Combobox(root, textvariable=self.cipher_type, values=["Caesar", "Vigenere", "AES"], state="readonly").pack(pady=5)

        ttk.Label(root, text="Mode:").pack()
        ttk.Combobox(root, textvariable=self.mode, values=["Encrypt", "Decrypt", "Brute-Force (Caesar)"], state="readonly").pack(pady=5)

        self.key_label.pack()
        self.key_entry.pack(pady=5)

        tk.Label(root, text="Input Text:").pack()
        self.text_input.pack(pady=5)

        tk.Button(root, text="🔄 Convert", font=("Arial", 12), command=self.convert).pack(pady=10)

        tk.Label(root, text="Output Text:").pack()
        self.text_output.pack(pady=5)

    def convert(self):
        text = self.text_input.get("1.0", tk.END).strip()
        key = self.key_entry.get().strip()
        mode = self.mode.get()
        cipher = self.cipher_type.get()
        output = ""

        try:
            if cipher == "Caesar":
                if mode == "Encrypt":
                    output = caesar(text, int(key))
                elif mode == "Decrypt":
                    output = caesar(text, -int(key))
                elif mode == "Brute-Force (Caesar)":
                    output = "\n".join([f"Shift {s}: {caesar(text, -s)}" for s in range(1, 26)])

            elif cipher == "Vigenere":
                if not key.isalpha():
                    raise ValueError("Key must be alphabetic for Vigenere")
                if mode == "Encrypt":
                    output = vigenere_encrypt(text, key)
                else:
                    output = vigenere_decrypt(text, key)

            elif cipher == "AES":
                if not key:
                    raise ValueError("Password required for AES")
                if mode == "Encrypt":
                    output = aes_encrypt(text, key)
                else:
                    output = aes_decrypt(text, key)

            else:
                output = "Unsupported cipher."
        except Exception as e:
            output = f"❌ Error: {str(e)}"

        self.text_output.delete("1.0", tk.END)
        self.text_output.insert(tk.END, output)

# Run the app
if __name__ == "__main__":
    root = tk.Tk()
    CipherGUI(root)
    root.mainloop()