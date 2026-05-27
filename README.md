# Cipher

A modern, browser-based symmetric encryption tool featuring PBKDF2 key derivation, a multi-round substitution-permutation network, HMAC authentication, and a clean UI.

## Features
* **Full Character Support:** Safely encrypts everything from standard text and paragraphs to emojis, numbers, and special punctuation (`!?"',.`).
* **Secure Key Derivation:** Uses PBKDF2 with 200,000 iterations to derive strong cryptographic keys from standard passwords.
* **Authenticated Encryption:** Applies an HMAC-SHA256 signature to verify message integrity and prevent tampering. If a ciphertext is modified in transit, the app catches it and refuses to decrypt.
* **100% Client-Side:** All cryptographic operations run locally in your browser using the native Web Crypto API. No data is ever sent to a server.
* **Modern UI:** Features a sleek, responsive design with keyboard shortcuts (`Ctrl+Enter` to process) and quick copy/paste functionality.

## Cryptographic Architecture
1. **Key Expansion:** The user-provided password is combined with a randomly generated 16-byte nonce. `PBKDF2` (SHA-256, 200k iterations) outputs a 96-byte derived key (`DK`).
2. **Key Splitting:** `DK` is split into three distinct materials:
   - `SUB_SEED` (32 bytes): Seeds a unique 256-byte substitution box (S-box).
   - `KS_MASTER` (32 bytes): Seeds the SHA-256 keystream generator.
   - `MAC_KEY` (32 bytes): Retained for the final HMAC signature verification.
3. **Encryption Core:** The plaintext is encoded to UTF-8 bytes and undergoes 3 rounds of encryption:
   - **Substitution & Addition:** Each byte is substituted using the S-box, offset by a SHA-256 keystream byte, and chained with the previous byte.
   - **Permutation:** The array is physically shuffled using a block-reversal algorithm to ensure strong diffusion.
4. **Authentication:** The nonce and the resulting ciphertext are signed using HMAC-SHA256.
5. **Encoding:** The final payload (Nonce + MAC Tag + Ciphertext) is encoded into a safe Base64 string for easy transport across messaging apps or email.

## Setup & Usage
Simply open `index.html` in any modern web browser.
1. Enter a secret key in the top field.
2. Select whether you want to **Encrypt** or **Decrypt**.
3. Type or paste your text into the input field.
4. Click the Process button (or hit `Ctrl+Enter`).

Alternatively, you can also go to https://cipher-yellowphantom364.vercel.app/.
