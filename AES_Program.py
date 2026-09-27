"""
Chương trình cài đặt thử nghiệm AES-128 (tự cài đặt, không dùng thư viện mã hóa sẵn).
Chức năng: Mã hóa / Giải mã.
Input: chuỗi 16 ký tự (16 byte) cho plaintext, hoặc 32 ký tự hex (16 byte) cho ciphertext.
Chuẩn tham chiếu: NIST FIPS-197.
"""

import sys
import io

# Ép stdout/stdin dùng UTF-8 để tránh lỗi UnicodeEncodeError trên một số console Windows.
if sys.stdout.encoding is None or sys.stdout.encoding.lower() != "utf-8":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
        sys.stdin.reconfigure(encoding="utf-8")
    except AttributeError:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8")

# ============================================================
# 1. BẢNG S-BOX VÀ INVERSE S-BOX (chuẩn FIPS-197)
# ============================================================
SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
]

INV_SBOX = [0] * 256
for i, v in enumerate(SBOX):
    INV_SBOX[v] = i

# Bảng hằng số vòng Rcon (chuẩn FIPS-197)
RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36]

NB = 4   # số cột của state (cố định = 4)
NK = 4   # số word 32-bit của khóa (AES-128 = 4)
NR = 10  # số round (AES-128 = 10)


# ============================================================
# 2. GIẢI THUẬT SINH KHÓA PHỤ (KEY EXPANSION)
# ============================================================
def sub_word(word):
    """Áp S-box lên từng byte của 1 word (list 4 byte)."""
    return [SBOX[b] for b in word]

def rot_word(word):
    """Xoay trái 1 byte: [a0,a1,a2,a3] -> [a1,a2,a3,a0]."""
    return word[1:] + word[:1]

def xor_words(w1, w2):
    return [a ^ b for a, b in zip(w1, w2)]

def key_expansion(key_bytes):
    """
    Sinh ra (NR+1) round key từ khóa gốc 16 byte.
    Trả về list các word (mỗi word là list 4 byte), tổng NB*(NR+1) word.
    """
    w = [list(key_bytes[4*i:4*i+4]) for i in range(NK)]

    for i in range(NK, NB * (NR + 1)):
        temp = list(w[i - 1])
        if i % NK == 0:
            temp = sub_word(rot_word(temp))
            temp[0] ^= RCON[i // NK - 1]
        w.append(xor_words(w[i - NK], temp))
    return w

def get_round_key(w, round_no):
    """Lấy round key thứ round_no (0..NR) dưới dạng ma trận 4x4 (state format)."""
    words = w[round_no*NB : round_no*NB + NB]
    round_key = [[0]*NB for _ in range(4)]
    for col in range(NB):
        for row in range(4):
            round_key[row][col] = words[col][row]
    return round_key


# ============================================================
# 3. CÁC PHÉP BIẾN ĐỔI TRÊN STATE
# ============================================================
def bytes_to_state(data):
    """16 byte -> ma trận state 4x4 (column-major theo FIPS-197)."""
    state = [[0]*4 for _ in range(4)]
    for i in range(16):
        state[i % 4][i // 4] = data[i]
    return state

def state_to_bytes(state):
    data = [0]*16
    for i in range(16):
        data[i] = state[i % 4][i // 4]
    return bytes(data)

def sub_bytes(state):
    return [[SBOX[b] for b in row] for row in state]

def inv_sub_bytes(state):
    return [[INV_SBOX[b] for b in row] for row in state]

def shift_rows(state):
    new_state = [row[:] for row in state]
    for r in range(1, 4):
        new_state[r] = state[r][r:] + state[r][:r]
    return new_state

def inv_shift_rows(state):
    new_state = [row[:] for row in state]
    for r in range(1, 4):
        new_state[r] = state[r][-r:] + state[r][:-r]
    return new_state

def xtime(a):
    """Nhân 1 byte với x (0x02) trong GF(2^8)."""
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF

def gmul(a, b):
    """Nhân 2 byte trong GF(2^8) (phương pháp peasant multiplication)."""
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return result

def mix_columns(state):
    new_state = [[0]*4 for _ in range(4)]
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        new_state[0][c] = gmul(col[0],2) ^ gmul(col[1],3) ^ col[2] ^ col[3]
        new_state[1][c] = col[0] ^ gmul(col[1],2) ^ gmul(col[2],3) ^ col[3]
        new_state[2][c] = col[0] ^ col[1] ^ gmul(col[2],2) ^ gmul(col[3],3)
        new_state[3][c] = gmul(col[0],3) ^ col[1] ^ col[2] ^ gmul(col[3],2)
    return new_state

def inv_mix_columns(state):
    new_state = [[0]*4 for _ in range(4)]
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        new_state[0][c] = gmul(col[0],14) ^ gmul(col[1],11) ^ gmul(col[2],13) ^ gmul(col[3],9)
        new_state[1][c] = gmul(col[0],9) ^ gmul(col[1],14) ^ gmul(col[2],11) ^ gmul(col[3],13)
        new_state[2][c] = gmul(col[0],13) ^ gmul(col[1],9) ^ gmul(col[2],14) ^ gmul(col[3],11)
        new_state[3][c] = gmul(col[0],11) ^ gmul(col[1],13) ^ gmul(col[2],9) ^ gmul(col[3],14)
    return new_state

def add_round_key(state, round_key):
    return [[state[r][c] ^ round_key[r][c] for c in range(4)] for r in range(4)]


# ============================================================
# 3b. HÀM HỖ TRỢ IN MA TRẬN STATE (phục vụ demo từng bước)
# ============================================================
def print_state(title, state):
    """In ma trận state 4x4 dạng hex, mỗi hàng 1 dòng."""
    print(f"  {title}:")
    for row in state:
        print("    " + " ".join(f"{b:02x}" for b in row))


# ============================================================
# 4. MÃ HÓA / GIẢI MÃ 1 KHỐI 16 BYTE
# ============================================================
def aes_encrypt_block(plaintext_bytes, key_bytes, verbose=False):
    w = key_expansion(key_bytes)
    state = bytes_to_state(plaintext_bytes)

    if verbose:
        print_state("Plaintext (initial state)", state)

    state = add_round_key(state, get_round_key(w, 0))
    if verbose:
        print(f"\nRound 0 (AddRoundKey only):")
        print_state("Round Key 0", get_round_key(w, 0))
        print_state("After AddRoundKey", state)

    for rnd in range(1, NR):
        show = (rnd == 1)  # chỉ in chi tiết round đầu tiên, các round giữa rút gọn
        if show:
            print(f"\nRound {rnd}:") if verbose else None
        elif verbose and rnd == 2:
            print(f"\n... (Round 2 to {NR - 1} follow the same pattern: "
                  f"SubBytes -> ShiftRows -> MixColumns -> AddRoundKey) ...")

        state = sub_bytes(state)
        if verbose and show:
            print_state("After SubBytes", state)
        state = shift_rows(state)
        if verbose and show:
            print_state("After ShiftRows", state)
        state = mix_columns(state)
        if verbose and show:
            print_state("After MixColumns", state)
        state = add_round_key(state, get_round_key(w, rnd))
        if verbose and show:
            print_state(f"Round Key {rnd}", get_round_key(w, rnd))
            print_state("After AddRoundKey", state)

    # Round cuối: không có MixColumns
    if verbose:
        print(f"\nRound {NR} (final round, no MixColumns):")
    state = sub_bytes(state)
    if verbose:
        print_state("After SubBytes", state)
    state = shift_rows(state)
    if verbose:
        print_state("After ShiftRows", state)
    state = add_round_key(state, get_round_key(w, NR))
    if verbose:
        print_state(f"Round Key {NR}", get_round_key(w, NR))
        print_state("After AddRoundKey (Ciphertext)", state)

    return state_to_bytes(state)

def aes_decrypt_block(ciphertext_bytes, key_bytes, verbose=False):
    w = key_expansion(key_bytes)
    state = bytes_to_state(ciphertext_bytes)

    if verbose:
        print_state("Ciphertext (initial state)", state)

    state = add_round_key(state, get_round_key(w, NR))
    if verbose:
        print(f"\nRound {NR} (AddRoundKey only):")
        print_state(f"Round Key {NR}", get_round_key(w, NR))
        print_state("After AddRoundKey", state)

    for rnd in range(NR - 1, 0, -1):
        show = (rnd == NR - 1)  # chỉ in chi tiết round đầu tiên gặp trong vòng lặp
        if show:
            print(f"\nRound {rnd}:") if verbose else None
        elif verbose and rnd == NR - 2:
            print(f"\n... (Round {NR - 2} down to 1 follow the same pattern: "
                  f"InvShiftRows -> InvSubBytes -> AddRoundKey -> InvMixColumns) ...")

        state = inv_shift_rows(state)
        if verbose and show:
            print_state("After InvShiftRows", state)
        state = inv_sub_bytes(state)
        if verbose and show:
            print_state("After InvSubBytes", state)
        state = add_round_key(state, get_round_key(w, rnd))
        if verbose and show:
            print_state(f"Round Key {rnd}", get_round_key(w, rnd))
            print_state("After AddRoundKey", state)
        state = inv_mix_columns(state)
        if verbose and show:
            print_state("After InvMixColumns", state)

    if verbose:
        print(f"\nRound 0 (final round, no InvMixColumns):")
    state = inv_shift_rows(state)
    if verbose:
        print_state("After InvShiftRows", state)
    state = inv_sub_bytes(state)
    if verbose:
        print_state("After InvSubBytes", state)
    state = add_round_key(state, get_round_key(w, 0))
    if verbose:
        print_state("Round Key 0", get_round_key(w, 0))
        print_state("After AddRoundKey (Plaintext)", state)

    return state_to_bytes(state)


# ============================================================
# 5. GIAO DIỆN DÒNG LỆNH: MENU MÃ HÓA / GIẢI MÃ
# ============================================================
def hex_to_bytes_safe(hex_str, expected_len=None, name="data"):
    hex_str = hex_str.strip().replace(" ", "")
    try:
        data = bytes.fromhex(hex_str)
    except ValueError:
        raise ValueError(f"{name} is not valid hex (only 0-9, a-f allowed).")
    if expected_len is not None and len(data) != expected_len:
        raise ValueError(f"{name} must be exactly {expected_len} bytes ({expected_len*2} hex chars), "
                          f"got {len(data)} bytes.")
    return data

# Khóa chuẩn theo NIST FIPS-197, Appendix B (dùng cố định, không yêu cầu người dùng nhập)
STANDARD_KEY_HEX = "000102030405060708090a0b0c0d0e0f"

def get_key():
    key_bytes = hex_to_bytes_safe(STANDARD_KEY_HEX, expected_len=16, name="Standard NIST key")
    print(f"(Using standard NIST FIPS-197 key: {STANDARD_KEY_HEX})")
    return key_bytes

def menu_encrypt():
    print("\n--- AES-128 ENCRYPTION ---")
    key_bytes = get_key()

    text = input("Enter text to encrypt (exactly 16 characters): ")
    plaintext_bytes = text.encode("utf-8")
    if len(plaintext_bytes) != 16:
        print(f"Error: text must be exactly 16 bytes (16 ASCII characters), got {len(plaintext_bytes)} bytes.")
        return

    print(f"\nPlaintext (as text):  {text}")
    print(f"Plaintext (as hex):   {plaintext_bytes.hex()}")

    ciphertext = aes_encrypt_block(plaintext_bytes, key_bytes, verbose=True)
    print("\n>>> Final encryption result (hex):")
    print(ciphertext.hex())

def menu_decrypt():
    print("\n--- AES-128 DECRYPTION ---")
    key_bytes = get_key()
    ct_hex = input("Enter ciphertext as hex (exactly 32 hex characters): ").strip()

    try:
        ciphertext_bytes = hex_to_bytes_safe(ct_hex, expected_len=16, name="Ciphertext")
    except ValueError as e:
        print(f"Error: {e}")
        return

    plaintext_bytes = aes_decrypt_block(ciphertext_bytes, key_bytes, verbose=True)
    print("\n>>> Final decryption result (hex):")
    print(plaintext_bytes.hex())
    try:
        print(">>> Decryption result (text):")
        print(plaintext_bytes.decode("utf-8"))
    except UnicodeDecodeError:
        print("(Decrypted data is not valid UTF-8 text, only the hex above is shown.)")

def main():
    print("=" * 50)
    print("   AES-128 EXPERIMENTAL IMPLEMENTATION")
    print("=" * 50)

    while True:
        print("\nSelect an option:")
        print("  1. Encrypt")
        print("  2. Decrypt")
        print("  0. Exit")
        choice = input("Your choice: ").strip()

        if choice == "1":
            menu_encrypt()
        elif choice == "2":
            menu_decrypt()
        elif choice == "0":
            print("Program ended.")
            break
        else:
            print("Invalid choice, please try again.")


if __name__ == "__main__":
    main()