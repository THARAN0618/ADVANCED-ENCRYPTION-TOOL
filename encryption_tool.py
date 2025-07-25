import os
import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2

BLOCK_SIZE = AES.block_size  # 16 bytes

def pad(data):
    padding = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([padding] * padding)

def unpad(data):
    padding = data[-1]
    return data[:-padding]

def encrypt_file(file_path, password):
    try:
        with open(file_path, "rb") as f:
            data = f.read()

        salt = get_random_bytes(16)
        key = PBKDF2(password, salt, dkLen=32, count=1000000)
        iv = get_random_bytes(BLOCK_SIZE)

        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted_data = cipher.encrypt(pad(data))

        with open(file_path + ".enc", "wb") as f:
            f.write(salt + iv + encrypted_data)

        messagebox.showinfo("Success", f"File encrypted: {file_path}.enc")

    except Exception as e:
        messagebox.showerror("Error", str(e))


def decrypt_file(file_path, password):
    try:
        with open(file_path, "rb") as f:
            content = f.read()

        salt = content[:16]
        iv = content[16:32]
        encrypted_data = content[32:]

        key = PBKDF2(password, salt, dkLen=32, count=1000000)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(encrypted_data))

        output_path = file_path.replace(".enc", "") + ".dec"
        with open(output_path, "wb") as f:
            f.write(decrypted_data)

        messagebox.showinfo("Success", f"File decrypted: {output_path}")

    except Exception as e:
        messagebox.showerror("Error", "Decryption failed. Check password or file.")


def browse_file(entry):
    path = filedialog.askopenfilename()
    entry.delete(0, tk.END)
    entry.insert(0, path)


def create_gui():
    window = tk.Tk()
    window.title("AES-256 File Encryption Tool")
    window.geometry("400x250")
    window.resizable(False, False)

    tk.Label(window, text="🔐 File Encryption Tool (AES-256)", font=("Arial", 14)).pack(pady=10)

    tk.Label(window, text="Select File:").pack()
    file_entry = tk.Entry(window, width=40)
    file_entry.pack()
    tk.Button(window, text="Browse", command=lambda: browse_file(file_entry)).pack(pady=5)

    tk.Label(window, text="Enter Password:").pack()
    password_entry = tk.Entry(window, show="*", width=30)
    password_entry.pack(pady=5)

    tk.Button(window, text="Encrypt", width=15, command=lambda: encrypt_file(file_entry.get(), password_entry.get())).pack(pady=5)
    tk.Button(window, text="Decrypt", width=15, command=lambda: decrypt_file(file_entry.get(), password_entry.get())).pack(pady=5)

    window.mainloop()


if __name__ == "__main__":
    create_gui()
