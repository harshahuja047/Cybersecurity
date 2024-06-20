import tkinter as tk
from tkinter import messagebox, simpledialog
from Crypto.Cipher import AES, PKCS1_OAEP, DES
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import base64
import os

KEY_DIR = os.path.join(os.path.expanduser("~"), "Desktop")

class EncryptionApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Encryption Tool")

        self.label = tk.Label(master, text="Enter text to encrypt:")
        self.label.pack()

        self.text_entry = tk.Entry(master, width=50)
        self.text_entry.pack()

        self.encryption_algorithm = tk.StringVar()
        self.encryption_algorithm.set("AES")

        self.algorithm_label = tk.Label(master, text="Select encryption algorithm:")
        self.algorithm_label.pack()

        self.algorithm_option_menu = tk.OptionMenu(master, self.encryption_algorithm, "AES", "DES", "RSA")
        self.algorithm_option_menu.pack()

        self.encrypt_button = tk.Button(master, text="Encrypt", command=self.encrypt_text)
        self.encrypt_button.pack()

        self.label = tk.Label(master, text="Encrypted Text:")
        self.label.pack()

        self.encrypted_text = tk.Text(master, height=10, width=50)
        self.encrypted_text.pack()

        self.decrypt_button = tk.Button(master, text="Decrypt", command=self.decrypt_text)
        self.decrypt_button.pack()

        self.label = tk.Label(master, text="Decrypted Text:")
        self.label.pack()

        self.decrypted_text = tk.Text(master, height=10, width=50, state='disabled')
        self.decrypted_text.pack()

    def encrypt_text(self):
        try:
            plaintext = self.text_entry.get().encode('utf-8')
            algorithm = self.encryption_algorithm.get()

            if algorithm == "AES":
                key = get_random_bytes(16)  # Generate a random 128-bit key
                cipher = AES.new(key, AES.MODE_EAX)
                ciphertext, tag = cipher.encrypt_and_digest(plaintext)
                encrypted_data = cipher.nonce + ciphertext
                self.save_key_to_file(key, "AES")
            elif algorithm == "DES":
                key = get_random_bytes(8)  # Generate a random 64-bit key for DES
                cipher = DES.new(key, DES.MODE_ECB)
                # DES requires the plaintext to be a multiple of 8 bytes, so we pad it
                padded_plaintext = plaintext + b"\0" * (8 - len(plaintext) % 8)
                encrypted_data = cipher.encrypt(padded_plaintext)
                self.save_key_to_file(key, "DES")
            elif algorithm == "RSA":
                key = RSA.generate(2048)
                cipher = RSA.import_key(key.publickey().export_key())
                cipher = PKCS1_OAEP.new(cipher)
                encrypted_data = cipher.encrypt(plaintext)
                self.save_key_to_file(key.export_key("PEM"), "RSA")

            self.encrypted_text.delete(1.0, tk.END)
            self.encrypted_text.insert(tk.END, base64.b64encode(encrypted_data).decode('utf-8'))
            messagebox.showinfo("Key", "Key saved securely on Desktop")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def decrypt_text(self):
        try:
            encrypted_data = base64.b64decode(self.encrypted_text.get(1.0, tk.END))
            algorithm = self.encryption_algorithm.get()

            if algorithm == "AES":
                key_input = simpledialog.askstring("Enter Key", "Please enter the encryption key:")
                if not key_input:
                    return
                key = base64.b64decode(key_input)
                nonce_size = 16  # Nonce size for AES
                nonce = encrypted_data[:nonce_size]
                ciphertext = encrypted_data[nonce_size:]
                cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
                plaintext = cipher.decrypt(ciphertext)
            elif algorithm == "DES":
                key_input = simpledialog.askstring("Enter Key", "Please enter the encryption key:")
                if not key_input:
                    return
                key = base64.b64decode(key_input)
                cipher = DES.new(key, DES.MODE_ECB)
                plaintext = cipher.decrypt(encrypted_data).rstrip(b"\0")  # Remove padding
            elif algorithm == "RSA":
                key = self.load_key_from_file("RSA")
                if not key:
                    return
                key = RSA.import_key(key)
                cipher = PKCS1_OAEP.new(key)
                plaintext = cipher.decrypt(encrypted_data)

            self.decrypted_text.config(state='normal')
            self.decrypted_text.delete(1.0, tk.END)
            self.decrypted_text.insert(tk.END, plaintext.decode('utf-8'))
            self.decrypted_text.config(state='disabled')

            # Schedule the clear_text function to be called after 9 seconds
            self.master.after(9000, self.clear_text)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def clear_text(self):
        self.decrypted_text.config(state='normal')
        self.decrypted_text.delete(1.0, tk.END)
        self.decrypted_text.config(state='disabled')

    def save_key_to_file(self, key, algorithm):
        filename = os.path.join(KEY_DIR, f"{algorithm}_key.txt")
        with open(filename, "wb") as file:
            file.write(base64.b64encode(key))

    def load_key_from_file(self, algorithm):
        filename = os.path.join(KEY_DIR, f"{algorithm}_key.txt")
        if not os.path.exists(filename):
            messagebox.showerror("Error", "Key file does not exist.")
            return None
        with open(filename, "rb") as file:
            key = file.read()
        return base64.b64decode(key)

def main():
    if not os.path.exists(KEY_DIR):
        os.makedirs(KEY_DIR)

    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
