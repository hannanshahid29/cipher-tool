import base64
import hashlib
import streamlit as st
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2

# -----------------------------------------------------------------------------
# Page Configuration
# -----------------------------------------------------------------------------
st.set_page_config(
    page_title="CipherLab — Local Crypto Workspace",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# -----------------------------------------------------------------------------
# Cryptographic Functions
# -----------------------------------------------------------------------------

def caesar_cipher(text: str, shift: int, mode: str = "encrypt") -> str:
    if mode == "decrypt":
        shift = -shift
    result = []
    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            result.append(chr((ord(ch) - base + shift) % 26 + base))
        else:
            result.append(ch)
    return "".join(result)

def vigenere_cipher(text: str, key: str, mode: str = "encrypt") -> str:
    key_clean = [c.lower() for c in key if c.isalpha()]
    if not key_clean:
        raise ValueError("Key must contain at least one English alphabetical letter.")
    result = []
    k_idx = 0
    for ch in text:
        if ch.isalpha():
            shift = ord(key_clean[k_idx % len(key_clean)]) - ord('a')
            if mode == "decrypt":
                shift = -shift
            base = ord('A') if ch.isupper() else ord('a')
            result.append(chr((ord(ch) - base + shift) % 26 + base))
            k_idx += 1
        else:
            result.append(ch)
    return "".join(result)

def vigenere_autokey(text: str, key: str, mode: str = "encrypt") -> str:
    text_clean = [c.upper() for c in text if c.isalpha()]
    key_clean = [c.upper() for c in key if c.isalpha()]
    if not key_clean:
        raise ValueError("Key must contain at least one alphabetical letter.")
    
    res = []
    if mode == "encrypt":
        keystream = key_clean + text_clean
        for i in range(len(text_clean)):
            p = ord(text_clean[i]) - 65
            k = ord(keystream[i]) - 65
            c = (p + k) % 26
            res.append(chr(c + 65))
    else:
        keystream = list(key_clean)
        for i in range(len(text_clean)):
            c = ord(text_clean[i]) - 65
            k = ord(keystream[i]) - 65
            p = (c - k) % 26
            res.append(chr(p + 65))
            keystream.append(chr(p + 65))
    return "".join(res)

def vernam_cipher_slide_logic(text: str, key: str, mode: str = "encrypt") -> str:
    """Implements the specific Vernam XOR and subtract logic from the lecture slides."""
    text_clean = [c.upper() for c in text if c.isalpha()]
    key_clean = [c.upper() for c in key if c.isalpha()]
    if not key_clean:
        raise ValueError("Key must contain at least one alphabetical letter.")
    
    while len(key_clean) < len(text_clean):
        key_clean += key_clean 
        
    res = []
    for i in range(len(text_clean)):
        p = ord(text_clean[i]) - 65
        k = ord(key_clean[i]) - 65
        if mode == "encrypt":
            val = p ^ k
            if val >= 26:
                val -= 26
            res.append(chr(val + 65))
        else:
            cand1 = p ^ k
            cand2 = (p + 26) ^ k
            
            valid_p = []
            if 0 <= cand1 <= 25 and (cand1 ^ k) < 26:
                valid_p.append(cand1)
            if 0 <= cand2 <= 25 and (cand2 ^ k) >= 26:
                valid_p.append(cand2)
                
            if valid_p:
                res.append(chr(valid_p[0] + 65))
            else:
                res.append('?') 
    return "".join(res)

def rail_fence_cipher(text: str, key: int, mode: str = "encrypt") -> str:
    if key <= 1:
        return text
    
    if mode == "encrypt":
        rail = [['\n' for _ in range(len(text))] for _ in range(key)]
        dir_down = False
        row, col = 0, 0
        for i in range(len(text)):
            if (row == 0) or (row == key - 1):
                dir_down = not dir_down
            rail[row][col] = text[i]
            col += 1
            row += 1 if dir_down else -1
        result = []
        for i in range(key):
            for j in range(len(text)):
                if rail[i][j] != '\n':
                    result.append(rail[i][j])
        return "".join(result)
    else:
        rail = [['\n' for _ in range(len(text))] for _ in range(key)]
        dir_down = None
        row, col = 0, 0
        for i in range(len(text)):
            if row == 0: dir_down = True
            if row == key - 1: dir_down = False
            rail[row][col] = '*'
            col += 1
            row += 1 if dir_down else -1
        index = 0
        for i in range(key):
            for j in range(len(text)):
                if (rail[i][j] == '*' and index < len(text)):
                    rail[i][j] = text[index]
                    index += 1
        result = []
        row, col = 0, 0
        for i in range(len(text)):
            if row == 0: dir_down = True
            if row == key - 1: dir_down = False
            if rail[row][col] != '*':
                result.append(rail[row][col])
                col += 1
            row += 1 if dir_down else -1
        return "".join(result)

def keyed_transposition_cipher(text: str, key: str, mode: str = "encrypt") -> str:
    text_clean = text.replace(" ", "")
    if not key or not text_clean:
        return text
    
    key_order = sorted(list(enumerate(key)), key=lambda x: x[1])
    cols = len(key)
    
    if mode == "encrypt":
        grid = [text_clean[i:i+cols] for i in range(0, len(text_clean), cols)]
        if len(grid[-1]) < cols:
            grid[-1] += 'X' * (cols - len(grid[-1]))
        
        cipher = ""
        for idx, _ in key_order:
            for row in grid:
                cipher += row[idx]
        return cipher
    else:
        rows = len(text_clean) // cols
        grid = [[''] * cols for _ in range(rows)]
        idx = 0
        for orig_col, _ in key_order:
            for r in range(rows):
                if idx < len(text_clean):
                    grid[r][orig_col] = text_clean[idx]
                    idx += 1
        plain = ""
        for row in grid:
            plain += "".join(row)
        return plain.rstrip('X')

def otp_generate_key(length_in_bytes: int) -> str:
    raw_key = get_random_bytes(length_in_bytes)
    return base64.b64encode(raw_key).decode('utf-8')

def otp_encrypt(plaintext: str, key_b64: str) -> str:
    text_bytes = plaintext.encode('utf-8')
    try:
        key_bytes = base64.b64decode(key_b64.encode('utf-8'))
    except Exception:
        raise ValueError("Invalid One-Time Pad key format. Key must be valid Base64.")
    if len(key_bytes) < len(text_bytes):
        raise ValueError("OTP Key is too short. It must be at least as long as plaintext.")
    cipher_bytes = bytes([b ^ k for b, k in zip(text_bytes, key_bytes)])
    return base64.b64encode(cipher_bytes).decode('utf-8')

def otp_decrypt(ciphertext_b64: str, key_b64: str) -> str:
    try:
        cipher_bytes = base64.b64decode(ciphertext_b64.encode('utf-8'))
        key_bytes = base64.b64decode(key_b64.encode('utf-8'))
    except Exception:
        raise ValueError("Invalid Base64 format for ciphertext or key.")
    if len(key_bytes) < len(cipher_bytes):
        raise ValueError("OTP Key is too short.")
    plain_bytes = bytes([b ^ k for b, k in zip(cipher_bytes, key_bytes)])
    try:
        return plain_bytes.decode('utf-8')
    except Exception:
        raise ValueError("Decryption produced invalid text. Ensure the exact one-time pad key was used.")

def aes_256_gcm_encrypt(plaintext: str, passphrase: str) -> str:
    salt = get_random_bytes(16)
    key = PBKDF2(passphrase.encode('utf-8'), salt, dkLen=32, count=100000)
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))
    
    salt_b64 = base64.b64encode(salt).decode('utf-8')
    nonce_b64 = base64.b64encode(nonce).decode('utf-8')
    tag_b64 = base64.b64encode(tag).decode('utf-8')
    ct_b64 = base64.b64encode(ciphertext).decode('utf-8')
    return f"AES256GCM:v1:{salt_b64}:{nonce_b64}:{tag_b64}:{ct_b64}"

def aes_256_gcm_decrypt(cipher_envelope: str, passphrase: str) -> str:
    try:
        parts = cipher_envelope.strip().split(":")
        if len(parts) != 6 or parts[0] != "AES256GCM" or parts[1] != "v1":
            raise ValueError("Invalid format. Please paste an AES-256-GCM ciphertext generated by this tool.")
        salt = base64.b64decode(parts[2])
        nonce = base64.b64decode(parts[3])
        tag = base64.b64decode(parts[4])
        ciphertext = base64.b64decode(parts[5])
        
        key = PBKDF2(passphrase.encode('utf-8'), salt, dkLen=32, count=100000)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        decrypted = cipher.decrypt_and_verify(ciphertext, tag)
        return decrypted.decode('utf-8')
    except Exception:
        raise ValueError("Decryption failed. Verify the secret passphrase and ciphertext.")

def sha256_hash(text: str) -> str:
    return hashlib.sha256(text.encode('utf-8')).hexdigest()

# -----------------------------------------------------------------------------
# Main Application UI
# -----------------------------------------------------------------------------

# Header
col_logo, col_status = st.columns([4, 1])
col_logo.subheader("❖ CipherLab")
col_status.success("LOCAL CRYPTO WORKSPACE")

st.divider()

# Hero Section
st.caption("YOUR TEXT. YOUR CONTROL.")
st.title("Make every message more secure.")
st.write("Encrypt, decrypt, and hash text in one clean workspace. Explore classic ciphers, transpositions, one-time pads, and modern authenticated encryption.")

st.write("")

# Main Workspace
with st.container(border=True):
    col_ws, col_badge = st.columns([4, 1])
    col_ws.caption("WORKSPACE / 01")
    col_ws.subheader("Cryptography studio")
    col_badge.info("AES & OTP AVAILABLE")

    st.write("")
    
    # Action Mode
    mode = st.radio(
        "Action Mode",
        options=["Encrypt", "Decrypt", "Hash (SHA-256)"],
        horizontal=True
    )
    
    is_encrypt = mode == "Encrypt"
    is_decrypt = mode == "Decrypt"
    is_hash = mode == "Hash (SHA-256)"

    # Algorithm and Key Fields
    algo_choice = None
    shift_val = 3
    secret_key = ""

    if not is_hash:
        st.write("")
        c_algo, c_key = st.columns(2)
        
        with c_algo:
            algo_choice = st.selectbox(
                "ENCRYPTION ALGORITHM",
                options=[
                    "Choose an algorithm",
                    "Caesar Cipher (Substitution)",
                    "Vigenère Cipher (Polyalphabetic)",
                    "Vigenère Autokey Cipher",
                    "Vernam Cipher (Alphabetic XOR)",
                    "Rail Fence (Transposition)",
                    "Keyed Columnar (Transposition)",
                    "One-Time Pad (Perfect Secrecy)",
                    "AES-256-GCM (Modern)"
                ]
            )

        with c_key:
            if algo_choice == "Choose an algorithm":
                st.text_input("KEY REQUIREMENT", placeholder="Select an algorithm first", disabled=True)
                
            elif algo_choice in ["Caesar Cipher (Substitution)", "Rail Fence (Transposition)"]:
                shift_val = st.number_input(
                    "SHIFT / RAILS",
                    min_value=2, max_value=25, value=3, step=1,
                    help="Enter a numeric value."
                )
                
            elif algo_choice in ["Vigenère Cipher (Polyalphabetic)", "Vigenère Autokey Cipher", "Vernam Cipher (Alphabetic XOR)", "Keyed Columnar (Transposition)"]:
                secret_key = st.text_input(
                    "SECRET KEYWORD",
                    placeholder="e.g. SECRET",
                    help="Use alphabetical characters."
                )
                
            elif algo_choice == "One-Time Pad (Perfect Secrecy)":
                secret_key = st.text_input(
                    "BASE64 ONE-TIME PAD KEY",
                    placeholder="Paste base64 key here...",
                    help="Key must be random and equal to or longer than the text."
                )
                otp_len = st.number_input("Generate random key length (bytes):", min_value=16, value=32, step=16)
                if st.button("Generate Secure Random Key"):
                    st.code(otp_generate_key(int(otp_len)), language="text")
                    st.caption("Copy this key immediately and only use it once.")
                    
            elif algo_choice == "AES-256-GCM (Modern)":
                secret_key = st.text_input(
                    "SECRET PASSPHRASE",
                    type="password",
                    placeholder="Enter a passphrase (min 8 chars)",
                    help="Used to securely derive a 256-bit AES key."
                )

    # Text Input Area
    st.write("")
    max_chars = 30000 if is_decrypt else 10000
    input_label = "CIPHERTEXT" if is_decrypt else "PLAINTEXT"

    if "text_area_input" not in st.session_state:
        st.session_state.text_area_input = ""

    user_text = st.text_area(
        f"{input_label} (Max {max_chars:,} chars)",
        key="text_area_input",
        placeholder="Type or paste your text here...",
        max_chars=max_chars,
        height=130
    )

    # Control Buttons
    c_note, c_clear, c_submit = st.columns([5, 1.5, 2])
    c_note.caption("❖ Text is processed entirely locally.")
    
    if c_clear.button("Clear Text", use_container_width=True):
        st.session_state.text_area_input = ""
        st.rerun()

    action_label = f"{mode} Text"
    submitted = c_submit.button(action_label, type="primary", use_container_width=True)

    # Execution Logic
    result_output = ""
    has_success = False

    if submitted:
        if not user_text.strip():
            st.error("Please enter some text to process.")
        elif not is_hash and algo_choice == "Choose an algorithm":
            st.error("Please select an encryption algorithm.")
        elif not is_hash and algo_choice in ["Vigenère Cipher (Polyalphabetic)", "Vigenère Autokey Cipher", "Vernam Cipher (Alphabetic XOR)", "Keyed Columnar (Transposition)"] and not secret_key.strip():
            st.error("This algorithm requires a valid keyword.")
        elif not is_hash and algo_choice == "AES-256-GCM (Modern)" and len(secret_key) < 8:
            st.error("AES passphrase must be at least 8 characters long.")
        elif not is_hash and algo_choice == "One-Time Pad (Perfect Secrecy)" and not secret_key.strip():
            st.error("Please provide a valid Base64 One-Time Pad key.")
        else:
            try:
                op_mode = "encrypt" if is_encrypt else "decrypt"
                
                if is_hash:
                    result_output = sha256_hash(user_text)
                elif algo_choice == "Caesar Cipher (Substitution)":
                    result_output = caesar_cipher(user_text, int(shift_val), op_mode)
                elif algo_choice == "Rail Fence (Transposition)":
                    result_output = rail_fence_cipher(user_text, int(shift_val), op_mode)
                elif algo_choice == "Vigenère Cipher (Polyalphabetic)":
                    result_output = vigenere_cipher(user_text, secret_key, op_mode)
                elif algo_choice == "Vigenère Autokey Cipher":
                    result_output = vigenere_autokey(user_text, secret_key, op_mode)
                elif algo_choice == "Vernam Cipher (Alphabetic XOR)":
                    result_output = vernam_cipher_slide_logic(user_text, secret_key, op_mode)
                elif algo_choice == "Keyed Columnar (Transposition)":
                    result_output = keyed_transposition_cipher(user_text, secret_key, op_mode)
                elif algo_choice == "One-Time Pad (Perfect Secrecy)":
                    result_output = otp_encrypt(user_text, secret_key) if is_encrypt else otp_decrypt(user_text, secret_key)
                elif algo_choice == "AES-256-GCM (Modern)":
                    result_output = aes_256_gcm_encrypt(user_text, secret_key) if is_encrypt else aes_256_gcm_decrypt(user_text, secret_key)
                
                has_success = True
            except Exception as e:
                st.error(f"Error: {str(e)}")

    # Output Console
    st.write("")
    with st.container(border=True):
        out_title, out_badge = st.columns([6, 1])
        out_title.write(f"**{mode.upper()} OUTPUT**")
        
        if has_success:
            out_badge.success("SUCCESS")
            st.code(result_output, language="text")
            st.caption(f"{len(result_output)} characters · Processed successfully.")
        else:
            out_badge.warning("AWAITING INPUT")
            st.caption("Your result will appear here...")


# -----------------------------------------------------------------------------
# Educational Footnotes
# -----------------------------------------------------------------------------
st.write("---")
st.subheader("Under the Hood")

f1, f2, f3, f4 = st.columns(4)
with f1:
    with st.container(border=True):
        st.write("🛡️ **Transposition Ciphers**")
        st.write("Methods like Rail Fence and Columnar Transposition scramble the positions of plaintext letters without altering the letters themselves.")
with f2:
    with st.container(border=True):
        st.write("🔠 **Polyalphabetic Ciphers**")
        st.write("Vigenère, Autokey, and Vernam mask letter frequencies by applying shifting rules that change for every character based on a key.")
with f3:
    with st.container(border=True):
        st.write("🔐 **One-Time Pad**")
        st.write("Uses a completely random, non-repeating key XOR'ed against the message. It is the only cryptosystem proven to offer perfect secrecy.")
with f4:
    with st.container(border=True):
        st.write("🚀 **AES-256-GCM**")
        st.write("The modern gold standard. Combines a 256-bit passphrase-derived key with a fresh nonce for secure, authenticated military-grade encryption.")

st.write("")
st.caption("© CipherLab · Educational cryptography workspace · Built natively with Python & Streamlit")