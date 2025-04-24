import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# Global In-Memory Storage and Session State
stored_data = {}
login_credentials = {"admin": "admin123"}  # Simple login user/pass
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
if 'authorized' not in st.session_state:
    st.session_state.authorized = True

# Generate or load a key
if 'fernet_key' not in st.session_state:
    st.session_state.fernet_key = Fernet.generate_key()
fernet = Fernet(st.session_state.fernet_key)

def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_text(text):
    return fernet.encrypt(text.encode()).decode()

def decrypt_text(cipher):
    return fernet.decrypt(cipher.encode()).decode()

def login_page():
    st.title("🔐 Login Required")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        if login_credentials.get(username) == password:
            st.session_state.authorized = True
            st.session_state.failed_attempts = 0
            st.success("Logged in successfully!")
        else:
            st.error("Invalid credentials")


def insert_data_page():
    st.title("📦 Insert Secure Data")
    key = st.text_input("Enter a unique key for this data")
    text = st.text_area("Enter your secret data")
    passkey = st.text_input("Enter a passkey", type="password")
    if st.button("Store Securely"):
        if key in stored_data:
            st.warning("This key already exists. Choose a new one.")
        else:
            encrypted_text = encrypt_text(text)
            hashed_passkey = hash_passkey(passkey)
            stored_data[key] = {"encrypted_text": encrypted_text, "passkey": hashed_passkey}
            st.success("Your data has been securely stored!")

def retrieve_data_page():
    if not st.session_state.authorized:
        login_page()
        return

    st.title("🔓 Retrieve Secure Data")
    key = st.text_input("Enter your unique data key")
    passkey = st.text_input("Enter your passkey", type="password")

    if st.button("Retrieve"):
        if key in stored_data:
            stored_passkey = stored_data[key]["passkey"]
            if hash_passkey(passkey) == stored_passkey:
                decrypted_text = decrypt_text(stored_data[key]["encrypted_text"])
                st.success("Data decrypted successfully!")
                st.code(decrypted_text)
                st.session_state.failed_attempts = 0
            else:
                st.session_state.failed_attempts += 1
                st.error(f"Incorrect passkey. Attempts left: {3 - st.session_state.failed_attempts}")
                if st.session_state.failed_attempts >= 3:
                    st.session_state.authorized = False
        else:
            st.warning("No data found for this key.")

def main():
    st.sidebar.title("🔐 Secure Storage System")
    choice = st.sidebar.radio("Navigate", ["Home", "Insert Data", "Retrieve Data"])

    if choice == "Home":
        st.title("🔒 Welcome to the Secure Data Encryption System")
        st.write("Choose an option from the sidebar to get started.")
    elif choice == "Insert Data":
        insert_data_page()
    elif choice == "Retrieve Data":
        retrieve_data_page()

if __name__ == "__main__":
    main()
