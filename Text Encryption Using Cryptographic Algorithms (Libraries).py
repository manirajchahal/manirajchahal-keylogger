from tkinter import Tk, Label, Button, Text, END, filedialog
from cryptography.fernet import Fernet, InvalidToken

# Global variable for cipher suite
cipher_suite = None

# Function to create a new cipher suite with a new key
def generate_key():
    global cipher_suite
    key = Fernet.generate_key()
    cipher_suite = Fernet(key)

# Function to load an existing key from a file
def load_key():
    global cipher_suite
    file_path = filedialog.askopenfilename(
        defaultextension=".key",
        filetypes=[("Key Files", "*.key"), ("All Files", "*.*")]
    )
    if file_path:
        try:
            with open(file_path, "rb") as file:
                key = file.read()
                # Validate the key by attempting encryption/decryption
                cipher_suite = Fernet(key)
                cipher_suite.encrypt(b"test")  # A simple encryption to validate the key
                output_text.delete("1.0", END)
                output_text.insert("1.0", "Key loaded and validated successfully!")
        except InvalidToken:
            output_text.delete("1.0", END)
            output_text.insert("1.0", "Invalid key!")
        except Exception as e:
            output_text.delete("1.0", END)
            output_text.insert("1.0", f"Failed to load key: {str(e)}")

# Function to save the current encryption key to a file
def save_key():
    if cipher_suite:
        file_path = filedialog.asksaveasfilename(
            defaultextension=".key",
            filetypes=[("Key Files", "*.key"), ("All Files", "*.*")]
        )
        if file_path:
            try:
                with open(file_path, "wb") as file:
                    file.write(cipher_suite._signing_key)
                output_text.delete("1.0", END)
                output_text.insert("1.0", "Key saved successfully!")
            except Exception as e:
                output_text.delete("1.0", END)
                output_text.insert("1.0", f"Failed to save key: {str(e)}")
    else:
        output_text.delete("1.0", END)
        output_text.insert("1.0", "No key to save.")

# Functions for encryption, decryption, and saving
def encrypt_text():
    if cipher_suite:
        plain_text = input_text.get("1.0", END).strip()
        if plain_text:
            encrypted = cipher_suite.encrypt(plain_text.encode())
            output_text.delete("1.0", END)
            output_text.insert("1.0", encrypted.decode())
        else:
            output_text.insert("1.0", "Enter text to encrypt.")
    else:
        output_text.insert("1.0", "No key available for encryption.")

def decrypt_text():
    if cipher_suite:
        encrypted_text = input_text.get("1.0", END).strip()
        if encrypted_text:
            try:
                decrypted = cipher_suite.decrypt(encrypted_text.encode())
                output_text.delete("1.0", END)
                output_text.insert("1.0", decrypted.decode())
            except InvalidToken:
                output_text.insert("1.0", "Decryption failed: Invalid token!")
            except Exception as e:
                output_text.insert("1.0", f"Decryption failed: {str(e)}")
        else:
            output_text.insert("1.0", "Enter text to decrypt.")
    else:
        output_text.insert("1.0", "No key available for decryption.")

def save_encrypted_text():
    encrypted_text = output_text.get("1.0", END).strip()
    if encrypted_text:
        file_path = filedialog.asksaveasfilename(
            defaultextension=".enc",
            filetypes=[("Encrypted Files", "*.enc"), ("All Files", "*.*")]
        )
        if file_path:
            try:
                with open(file_path, "wb") as file:
                    file.write(encrypted_text.encode())
                output_text.delete("1.0", END)
                output_text.insert("1.0", "Encrypted text saved successfully!")
            except Exception as e:
                output_text.insert("1.0", f"Failed to save file: {str(e)}")
    else:
        output_text.insert("1.0", "No encrypted text to save.")

def save_decrypted_text():
    decrypted_text = output_text.get("1.0", END).strip()
    if decrypted_text:
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
        )
        if file_path:
            try:
                with open(file_path, "w") as file:
                    file.write(decrypted_text)
                output_text.delete("1.0", END)
                output_text.insert("1.0", "Decrypted text saved successfully!")
            except Exception as e:
                output_text.insert("1.0", f"Failed to save file: {str(e)}")
    else:
        output_text.insert("1.0", "No decrypted text to save.")

# Function to encrypt a file
def encrypt_file():
    if cipher_suite:
        file_path = filedialog.askopenfilename(
            filetypes=[("All Files", "*.*")]
        )
        if file_path:
            try:
                with open(file_path, "rb") as file:
                    file_data = file.read()
                    encrypted_data = cipher_suite.encrypt(file_data)
                save_file_path = filedialog.asksaveasfilename(
                    defaultextension=".enc",
                    filetypes=[("Encrypted Files", "*.enc"), ("All Files", "*.*")]
                )
                if save_file_path:
                    with open(save_file_path, "wb") as enc_file:
                        enc_file.write(encrypted_data)
                    output_text.delete("1.0", END)
                    output_text.insert("1.0", "File encrypted and saved successfully!")
            except Exception as e:
                output_text.insert("1.0", f"Failed to encrypt file: {str(e)}")
    else:
        output_text.insert("1.0", "No key available for file encryption.")

# Function to decrypt a file
def decrypt_file():
    if cipher_suite:
        file_path = filedialog.askopenfilename(
            filetypes=[("Encrypted Files", "*.enc"), ("All Files", "*.*")]
        )
        if file_path:
            try:
                with open(file_path, "rb") as enc_file:
                    encrypted_data = enc_file.read()
                    decrypted_data = cipher_suite.decrypt(encrypted_data)
                save_file_path = filedialog.asksaveasfilename(
                    defaultextension=".txt",
                    filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
                )
                if save_file_path:
                    with open(save_file_path, "wb") as dec_file:
                        dec_file.write(decrypted_data)
                    output_text.delete("1.0", END)
                    output_text.insert("1.0", "File decrypted and saved successfully!")
            except InvalidToken:
                output_text.insert("1.0", "Decryption failed: Invalid token!")
            except Exception as e:
                output_text.insert("1.0", f"Failed to decrypt file: {str(e)}")
    else:
        output_text.insert("1.0", "No key available for file decryption.")

# Tkinter GUI setup
root = Tk()
root.title("Text Encryption & Decryption")
root.geometry("400x600")  # Define size

# Labels and text areas
Label(root, text="Input Text:").pack()
input_text = Text(root, height=5, width=40)
input_text.pack()

Label(root, text="Output Text:").pack()
output_text = Text(root, height=5, width=40)
output_text.pack()

# Buttons
Button(root, text="Generate Key", command=generate_key).pack()
Button(root, text="Load Key", command=load_key).pack()
Button(root, text="Save Key", command=save_key).pack()
Button(root, text="Encrypt", command=encrypt_text).pack()
Button(root, text="Decrypt", command=decrypt_text).pack()
Button(root, text="Save Encrypted Text", command=save_encrypted_text).pack()
Button(root, text="Save Decrypted Text", command=save_decrypted_text).pack()
Button(root, text="Encrypt File", command=encrypt_file).pack()
Button(root, text="Decrypt File", command=decrypt_file).pack()

# Run the Tkinter loop
root.mainloop()