from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
import os
import argparse

# Định nghĩa thư mục sẽ lưu trữ các khóa bảo mật
KEY_STORAGE_DIR = "Key"

def encrypt_file(file_path, key_file_name, user_key=None):
    """
    Mã hóa một tệp tin bằng AES trong chế độ EAX.
    Khóa sẽ được lưu vào một tệp riêng trong thư mục KEY_STORAGE_DIR.

    Args:
        file_path (str): Đường dẫn đến tệp tin cần mã hóa.
        key_file_name (str): Tên tệp tin sẽ dùng để lưu khóa (chỉ tên, không bao gồm đường dẫn thư mục).
        user_key (str, optional): Khóa AES 128-bit (32 ký tự hex) do người dùng cung cấp.
                                   Nếu None, một khóa ngẫu nhiên sẽ được tạo.
    Raises:
        FileNotFoundError: Nếu tệp tin cần mã hóa không tồn tại.
        ValueError: Nếu định dạng khóa không hợp lệ hoặc độ dài khóa sai.
        OSError: Nếu có lỗi khi xóa tệp gốc.
    """
    # Kiểm tra tệp tin cần mã hóa có tồn tại không
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"File could not be found: {file_path}")

    # Tạo thư mục lưu khóa nếu chưa tồn tại.
    # exist_ok=True đảm bảo không báo lỗi nếu thư mục đã có.
    os.makedirs(KEY_STORAGE_DIR, exist_ok=True)
    
    # Xây dựng đường dẫn đầy đủ đến tệp khóa
    full_key_path = os.path.join(KEY_STORAGE_DIR, key_file_name)

    # Sử dụng khóa do người dùng nhập hoặc tạo khóa ngẫu nhiên
    if user_key:
        try:
            # Chuyển đổi chuỗi hex thành bytes
            key = bytes.fromhex(user_key)
        except ValueError:
            raise ValueError("Invalid key format: key must be a hex string (e.g., 'abcdef0123456789abcdef0123456789')")
        if len(key) != 16: # AES-128 yêu cầu khóa 16 bytes
            raise ValueError("Key must be exactly 16 bytes (32 hex characters) for AES-128.")
    else:
        # Tạo khóa ngẫu nhiên 16 bytes (128 bit)
        key = get_random_bytes(16)

    # Tạo đối tượng mã hóa AES ở chế độ EAX.
    # EAX là chế độ mã hóa xác thực (Authenticated Encryption with Associated Data - AEAD),
    # cung cấp cả bảo mật (riêng tư) và tính toàn vẹn dữ liệu.
    cipher = AES.new(key, AES.MODE_EAX)

    # Đọc toàn bộ nội dung tệp gốc vào bộ nhớ
    with open(file_path, 'rb') as f:
        plaintext = f.read()

    # Mã hóa dữ liệu và tạo tag xác thực.
    # ciphertext là dữ liệu đã mã hóa.
    # tag là mã xác thực dùng để kiểm tra tính toàn vẹn khi giải mã.
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    # Ghi file mã hóa gồm nonce, tag, ciphertext.
    # Nonce (Number used once) là một giá trị ngẫu nhiên duy nhất được sử dụng cho mỗi lần mã hóa.
    # Nonce cần được lưu cùng với ciphertext để giải mã, nhưng không cần bảo mật.
    encrypted_file_path = file_path + ".aes"
    with open(encrypted_file_path, 'wb') as f:
        # Ghi nonce (16 bytes), tag (16 bytes), và ciphertext theo thứ tự
        [f.write(x) for x in (cipher.nonce, tag, ciphertext)]
    print(f"File encrypted and saved as: {encrypted_file_path}")

    # Ghi khóa vào tệp riêng trong thư mục KEY_STORAGE_DIR.
    # Tệp khóa này cần được bảo mật cẩn thận!
    with open(full_key_path, 'wb') as f:
        f.write(key)
    print(f"Encryption key saved to: {full_key_path}")

    # Xoá tệp gốc để chỉ còn lại tệp đã mã hóa
    try:
        os.remove(file_path)
        print("Original file deleted successfully.")
    except OSError as e:
        print(f"Error deleting original file {file_path}: {e}. You may need to delete it manually.")


def decrypt_file(file_path, key_file_name):
    """
    Giải mã một tệp tin đã được mã hóa bằng AES trong chế độ EAX.
    Khóa sẽ được đọc từ một tệp trong thư mục KEY_STORAGE_DIR.

    Args:
        file_path (str): Đường dẫn đến tệp tin đã mã hóa (.aes).
        key_file_name (str): Tên tệp tin chứa khóa (chỉ tên, không bao gồm đường dẫn thư mục).

    Raises:
        FileNotFoundError: Nếu tệp tin đã mã hóa hoặc tệp khóa không tồn tại.
        ValueError: Nếu độ dài khóa không hợp lệ, tệp mã hóa bị hỏng,
                    hoặc khóa không đúng/thông điệp bị giả mạo.
        IOError: Nếu có lỗi khi đọc tệp mã hóa.
        Exception: Nếu có lỗi giải mã không mong muốn.
    """
    # Xây dựng đường dẫn đầy đủ đến tệp khóa trong thư mục KEY_STORAGE_DIR
    full_key_path = os.path.join(KEY_STORAGE_DIR, key_file_name)

    # Kiểm tra tệp tin đã mã hóa và tệp khóa có tồn tại không
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"Encrypted file could not be found: {file_path}")

    if not os.path.isfile(full_key_path):
        raise FileNotFoundError(f"Key file could not be found at: {full_key_path}. Make sure it exists in the '{KEY_STORAGE_DIR}' folder.")

    # Đọc khóa từ tệp
    with open(full_key_path, 'rb') as f:
        key = f.read()

    # Kiểm tra độ dài khóa đã đọc có đúng 16 bytes không
    if len(key) != 16:
        raise ValueError(f"Invalid key length in file '{full_key_path}': Key must be 16 bytes for AES-128. Found {len(key)} bytes.")

    # Đọc nonce, tag, ciphertext từ tệp đã mã hóa
    try:
        with open(file_path, 'rb') as f:
            nonce = f.read(16)      # Đọc 16 bytes đầu tiên cho nonce
            tag = f.read(16)        # Đọc 16 bytes tiếp theo cho tag
            ciphertext = f.read()   # Đọc phần còn lại cho ciphertext
    except Exception as e:
        raise IOError(f"Error reading encrypted file {file_path}: {e}")

    # Kiểm tra nếu các phần cần thiết (nonce, tag) không đủ dữ liệu
    if not nonce or not tag:
        raise ValueError("The encrypted file is empty or corrupted (missing nonce/tag).")
    
    # Có thể thêm cảnh báo nếu ciphertext rỗng, trường hợp file gốc rỗng
    if not ciphertext and (len(nonce) == 16 and len(tag) == 16):
        print(f"Warning: Ciphertext in '{file_path}' is empty. This might indicate an empty original file.")


    # Tạo đối tượng giải mã AES ở chế độ EAX với khóa và nonce đã đọc
    cipher = AES.new(key, AES.MODE_EAX, nonce)

    # Giải mã và kiểm tra tính toàn vẹn của dữ liệu.
    # Nếu tag không khớp, một ValueError sẽ được ném ra.
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError:
        # Lỗi này thường xảy ra nếu khóa không đúng, hoặc dữ liệu bị giả mạo/hỏng
        raise ValueError("Key incorrect or message corrupted. Decryption failed due to authentication tag mismatch.")
    except Exception as e:
        raise Exception(f"Decryption failed unexpectedly: {e}")

    # Xác định đường dẫn cho tệp tin đã giải mã.
    # Nếu tệp mã hóa kết thúc bằng '.aes', loại bỏ nó.
    # Nếu không, thêm '.decrypted' vào cuối.
    output_file_path = file_path[:-4] if file_path.endswith('.aes') else file_path + ".decrypted"
    with open(output_file_path, 'wb') as f:
        f.write(plaintext)
    print(f"File decrypted successfully to: {output_file_path}")


if __name__ == '__main__':
    # Cấu hình đối số dòng lệnh
    parser = argparse.ArgumentParser(
        description="Encrypt or decrypt files using AES encryption. "
                    f"Keys are managed in the '{KEY_STORAGE_DIR}' folder."
    )
    parser.add_argument(
        'file_path',
        type=str,
        help='Path to the file to be encrypted/decrypted.'
    )
    parser.add_argument(
        'key_file_name',
        type=str,
        help=f'The filename for the encryption key (e.g., "my_secret_key.bin"). '
             f'The key will be saved/read from the "{KEY_STORAGE_DIR}/" folder.'
    )
    parser.add_argument(
        '-d', '--decrypt',
        action='store_true',
        help='Set this flag to decrypt the file. Otherwise, it will encrypt.'
    )
    parser.add_argument(
        '-k', '--key',
        type=str,
        help='Optional: A 32-character hex key (AES-128) to use instead of a randomly generated one. '
             'Only applicable for encryption.'
    )

    args = parser.parse_args()

    try:
        if args.decrypt:
            print(f"\n--- Starting Decryption ---")
            print(f"Attempting to decrypt '{args.file_path}' using key filename '{args.key_file_name}' from folder '{KEY_STORAGE_DIR}'...")
            decrypt_file(args.file_path, args.key_file_name)
            print(f"--- Decryption Complete ---")
        else:
            print(f"\n--- Starting Encryption ---")
            user_key = args.key
            if not user_key:
                # Hỏi người dùng có muốn nhập key thủ công không
                choice = input("Do you want to manually enter the 32-character hex key (AES-128)? (y/n): ").strip().lower()
                if choice == 'y':
                    user_key = input("Enter 32-character hex key: ").strip()
            
            print(f"Attempting to encrypt '{args.file_path}' and save key with filename '{args.key_file_name}' into folder '{KEY_STORAGE_DIR}'...")
            encrypt_file(args.file_path, args.key_file_name, user_key)
            print(f"--- Encryption Complete ---")

    except (FileNotFoundError, ValueError, IOError, Exception) as e:
        print(f"\nAn error occurred: {e}")
        print("Please ensure file paths are correct, and for decryption, that the key file exists and matches the encrypted data.")

