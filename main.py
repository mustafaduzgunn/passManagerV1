#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import json
import base64
import pyperclip
import threading
import time
import platform
from getpass import getpass
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import secrets
import string

VAULT_FILE = "vault.dat"
SALT_SIZE = 16
PBKDF2_ITERATIONS = 200_000

def clear_clipboard():
    try:
        pyperclip.copy("")
        print("🧹 Panodaki şifre silindi.")
    except pyperclip.PyperclipException:
        print("⚠️ Pano temizlenemedi. pyperclip sistem aracını bulamadı.")

def generate_strong_password():
    length = 12
    symbols = "*.!@"
    all_chars = string.ascii_letters + string.digits + symbols
    while True:
        password = ''.join(secrets.choice(all_chars) for _ in range(length))
        if (any(c.islower() for c in password) and
            any(c.isupper() for c in password) and
            any(c.isdigit() for c in password) and
            any(c in symbols for c in password)):
            return password

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def load_vault(master_password: str):
    if not os.path.exists(VAULT_FILE):
        print("🆕 Yeni şifre kasası oluşturulacak.")
        salt = os.urandom(SALT_SIZE)
        key = derive_key(master_password, salt)
        fernet = Fernet(key)
        return {}, fernet, salt

    with open(VAULT_FILE, "rb") as f:
        file_data = f.read()
        salt = file_data[:SALT_SIZE]
        encrypted = file_data[SALT_SIZE:]

    key = derive_key(master_password, salt)
    fernet = Fernet(key)

    try:
        decrypted = fernet.decrypt(encrypted)
        vault = json.loads(decrypted.decode())
        return vault, fernet, salt
    except (InvalidToken, json.JSONDecodeError):
        return None, None, None

def save_vault(vault: dict, fernet: Fernet, salt: bytes):
    data = json.dumps(vault).encode()
    encrypted = fernet.encrypt(data)
    with open(VAULT_FILE, "wb") as f:
        f.write(salt + encrypted)

def check_clipboard_dependency():
    try:
        pyperclip.copy("test")
        pyperclip.paste()
    except pyperclip.PyperclipException:
        os_name = platform.system()
        print("⚠️ Pano kopyalama düzgün çalışmıyor.")
        if os_name == "Linux":
            print("💡 Linux'ta çalışması için şu komutlardan birini yüklemelisiniz:\n  sudo apt install xclip\n  veya\n  sudo apt install xsel")
        elif os_name == "Darwin":
            print("✅ macOS'ta pbcopy/pbpaste varsayılan olarak çalışmalıdır.")
        elif os_name == "Windows":
            print("✅ Windows'ta pyperclip otomatik çalışır.")

def main():
    print("🔐 CLI Parola Yöneticisi (Güvenli Sürüm)")
    check_clipboard_dependency()

    while True:
        master_pass = getpass("Ana parolanızı girin: ")
        vault, fernet, salt = load_vault(master_pass)
        if vault is not None:
            break
        print("❌ Hatalı parola. Lütfen tekrar deneyin.")

    simple_pin = getpass("🔑 Hızlı erişim için kısa bir PIN belirleyin (sadece bu oturum için): ")

    while True:
        print("\n[1] Ekle  [2] Listele  [3] Sil  [4] Şifreyi Kopyala  [5] Parola Oluştur  [q] Çıkış")
        choice = input("Seçim yapın: ")

        if choice == "1":
            service = input("Servis adı: ")
            username = input("Kullanıcı adı: ")
            password = getpass("Parola: ")
            vault[service] = {"username": username, "password": password}
            save_vault(vault, fernet, salt)
            print("✅ Kaydedildi.")

        elif choice == "2":
            for idx, (service, data) in enumerate(vault.items(), start=1):
                print(f"\n{idx}. 🧾 {service}")
                print(f"   👤 {data['username']}")
                print(f"   🔑 {'*' * len(data['password'])} (gizli)")

        elif choice == "3":
            to_delete = input("Silmek istediğiniz servis adı: ")
            if to_delete in vault:
                del vault[to_delete]
                save_vault(vault, fernet, salt)
                print("🗑️ Silindi.")
            else:
                print("🚫 Servis bulunamadı.")

        elif choice == "4":
            target = input("Şifresini panoya kopyalamak istediğiniz servis adı: ")
            if target in vault:
                pin_check = getpass("PIN kodunuzu girin: ")
                if pin_check == simple_pin:
                    try:
                        pyperclip.copy(vault[target]['password'])
                        print(f"📋 '{target}' için şifre panoya kopyalandı. (10 saniye içinde yapıştır)")
                        threading.Timer(10.0, clear_clipboard).start()
                    except pyperclip.PyperclipException:
                        print("⚠️ Pano kopyalama başarısız.")
                else:
                    print("❌ Hatalı PIN.")
            else:
                print("🚫 Servis bulunamadı.")

        elif choice == "5":
            password = generate_strong_password()
            print(f"\n🎯 Oluşturulan parola: {password}")
            try:
                pyperclip.copy(password)
                print("📋 Parola panoya kopyalandı (30 saniye sonra silinecek).")
                threading.Timer(30.0, clear_clipboard).start()
            except pyperclip.PyperclipException:
                print("⚠️ Pano kopyalama başarısız.")

        elif choice == "q":
            print("👋 Çıkılıyor...")
            break
        else:
            print("⚠️ Geçersiz seçim.")

if __name__ == "__main__":
    main()
