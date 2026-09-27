# AES-128 Experimental Implementation

Chương trình cài đặt thử nghiệm **AES-128** bằng Python, tự triển khai các phép biến đổi của thuật toán AES và **không sử dụng thư viện mã hóa có sẵn**.

Chương trình hỗ trợ hai chức năng:

* **Mã hóa (Encryption)**
* **Giải mã (Decryption)**

Thuật toán được triển khai dựa trên chuẩn **NIST FIPS-197**.

---

## 1. Thông tin chương trình

| Thành phần       | Mô tả                    |
| ---------------- | ------------------------ |
| Ngôn ngữ         | Python 3                 |
| Thuật toán       | AES-128                  |
| Block size       | 128 bit (16 byte)        |
| Key size         | 128 bit (16 byte)        |
| Số vòng          | 10 vòng                  |
| Chế độ hoạt động | Xử lý từng block 16 byte |
| Input mã hóa     | Chuỗi đúng 16 byte       |
| Input giải mã    | Chuỗi hex đúng 32 ký tự  |
| Khóa             | Khóa chuẩn NIST FIPS-197 |

Khóa được sử dụng cố định trong chương trình:

```text
000102030405060708090a0b0c0d0e0f
```

Đây là khóa được sử dụng trong ví dụ chuẩn của **NIST FIPS-197**.

---

## 2. Cấu trúc chương trình

Chương trình được chia thành các thành phần chính:

### 2.1. S-Box và Inverse S-Box

Chương trình sử dụng:

* `SBOX`
* `INV_SBOX`

để thực hiện hai phép biến đổi:

```text
SubBytes
InvSubBytes
```

`INV_SBOX` được tạo từ `SBOX` thay vì sử dụng thư viện mã hóa bên ngoài.

---

### 2.2. Key Expansion

Hàm:

```python
key_expansion(key_bytes)
```

thực hiện quá trình mở rộng khóa AES-128 từ khóa gốc 16 byte thành:

```text
11 round keys
```

tương ứng với:

```text
Round 0 → Round 10
```

Các thao tác chính gồm:

* `RotWord`
* `SubWord`
* XOR
* `Rcon`

Các hàm liên quan:

```python
sub_word()
rot_word()
xor_words()
key_expansion()
get_round_key()
```

---

### 2.3. Biểu diễn State

AES biểu diễn mỗi block 16 byte dưới dạng ma trận:

```text
4 × 4 byte
```

Chương trình sử dụng:

```python
bytes_to_state()
state_to_bytes()
```

để chuyển đổi giữa chuỗi byte và ma trận State theo cách sắp xếp **column-major** của AES.

---

### 2.4. Các phép biến đổi AES

#### Mã hóa

Mỗi vòng AES sử dụng các phép biến đổi:

```text
SubBytes
    ↓
ShiftRows
    ↓
MixColumns
    ↓
AddRoundKey
```

Riêng vòng cuối:

```text
SubBytes
    ↓
ShiftRows
    ↓
AddRoundKey
```

Vòng cuối **không thực hiện MixColumns**.

#### Giải mã

Quá trình giải mã sử dụng các phép biến đổi ngược:

```text
InvShiftRows
    ↓
InvSubBytes
    ↓
AddRoundKey
    ↓
InvMixColumns
```

Vòng cuối của quá trình giải mã cũng không thực hiện `InvMixColumns`.

---

## 3. Phép nhân trong GF(2^8)

Chương trình tự triển khai phép nhân trong trường hữu hạn GF(2^8) thông qua hàm:

```python
gmul(a, b)
```

Ngoài ra có hàm:

```python
xtime(a)
```

dùng để thực hiện phép nhân một byte với `0x02`.

Các phép toán này được sử dụng trong:

```text
MixColumns
InvMixColumns
```

Chương trình không sử dụng thư viện mã hóa AES có sẵn.

---

## 4. Mã hóa

Để thực hiện mã hóa:

1. Chạy chương trình.
2. Chọn:

```text
1. Encrypt
```

3. Nhập chuỗi có đúng **16 byte**.

Ví dụ:

```text
Two One Nine Two
```

Chương trình sẽ hiển thị:

* Plaintext dạng text
* Plaintext dạng hex
* State ban đầu
* Round Key
* Kết quả sau các bước của round đầu tiên
* Kết quả mã hóa cuối cùng dưới dạng hex

Kết quả cuối cùng được in theo dạng:

```text
>>> Final encryption result (hex):
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

---

## 5. Giải mã

Để thực hiện giải mã:

1. Chạy chương trình.
2. Chọn:

```text
2. Decrypt
```

3. Nhập ciphertext dưới dạng **32 ký tự hex**.

Ví dụ:

```text
69c4e0d86a7b0430d8cdb78070b4c55a
```

Chương trình sẽ thực hiện quá trình giải mã và hiển thị:

* Ciphertext ban đầu
* Round Key
* Các bước biến đổi của round
* Plaintext dạng hex
* Plaintext dạng text nếu dữ liệu giải mã hợp lệ UTF-8

---

## 6. Ví dụ kiểm tra theo NIST FIPS-197

Chương trình sử dụng khóa chuẩn:

```text
000102030405060708090a0b0c0d0e0f
```

Một bộ dữ liệu kiểm thử AES-128 tiêu chuẩn:

### Key

```text
000102030405060708090a0b0c0d0e0f
```

### Plaintext

```text
00112233445566778899aabbccddeeff
```

### Expected Ciphertext

```text
69c4e0d86a7b0430d8cdb78070b4c55a
```

Đây là bộ giá trị dùng để kiểm tra tính đúng đắn của quá trình mã hóa AES-128.

---

## 7. Chạy chương trình

Yêu cầu:

```text
Python 3.x
```

Chạy bằng lệnh:

```bash
python AES_program.py
```

Trên một số hệ thống có thể sử dụng:

```bash
python3 AES_program.py
```

Sau khi chạy, chương trình hiển thị menu:

```text
==================================================
   AES-128 EXPERIMENTAL IMPLEMENTATION
==================================================

Select an option:
  1. Encrypt
  2. Decrypt
  0. Exit
```

---

## 8. Xử lý dữ liệu đầu vào

### Mã hóa

Plaintext phải có chính xác:

```text
16 byte
```

Chương trình kiểm tra độ dài sau khi mã hóa chuỗi thành UTF-8.

Nếu dữ liệu không đủ 16 byte hoặc vượt quá 16 byte, chương trình sẽ báo lỗi.

### Giải mã

Ciphertext phải có chính xác:

```text
16 byte = 32 ký tự hex
```

Chương trình kiểm tra:

* Dữ liệu có phải hex hợp lệ hay không.
* Độ dài có đúng 16 byte hay không.

---

## 9. Hiển thị quá trình AES

Chương trình có chế độ hiển thị chi tiết thông qua tham số:

```python
verbose=True
```

Khi chạy mã hóa hoặc giải mã từ menu, chương trình hiển thị các bước biến đổi của State để phục vụ mục đích **học tập, minh họa và kiểm tra thuật toán**.

Đối với các round ở giữa, chương trình chỉ hiển thị tóm tắt để tránh output quá dài.

---

## 10. Các file trong repository

```text
.
├── AES_program.py
└── README.md
```

### `AES_program.py`

Chứa toàn bộ mã nguồn cài đặt AES-128, bao gồm:

* S-Box / Inverse S-Box
* Key Expansion
* SubBytes / InvSubBytes
* ShiftRows / InvShiftRows
* MixColumns / InvMixColumns
* AddRoundKey
* AES-128 Encryption
* AES-128 Decryption
* Command-line interface

### `README.md`

Tài liệu hướng dẫn cài đặt, chạy chương trình và mô tả các thành phần chính của chương trình.

---

## 11. Tham chiếu

Thuật toán AES được triển khai dựa trên tài liệu:

**NIST, FIPS PUB 197 — Advanced Encryption Standard (AES).**

Mục đích của chương trình là phục vụ **học tập và thực nghiệm thuật toán AES-128**. Chương trình không nhằm thay thế các thư viện mật mã được kiểm chứng và sử dụng trong các hệ thống thực tế.
