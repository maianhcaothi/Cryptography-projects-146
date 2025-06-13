import tkinter as tk
from tkinter import filedialog, messagebox
import os
import sys

# Định nghĩa thư mục sẽ lưu trữ các khóa bảo mật, phải khớp với KEY_STORAGE_DIR trong aes_file_encryption.py
KEY_STORAGE_DIR = "Key"

# Thêm thư mục hiện tại vào sys.path để cho phép import aes_file_encryption.py
# nếu nó không nằm trong Python path
script_dir = os.path.dirname(os.path.abspath(__file__))
if script_dir not in sys.path:
    sys.path.append(script_dir)

try:
    # Import các hàm từ script mã hóa/giải mã file
    from aes_file_encryption import encrypt_file, decrypt_file
except ImportError:
    messagebox.showerror("Import Error", f"Could not find 'aes_file_encryption.py'.\n"
                                         f"Please ensure 'aes_file_encryption.py' is in the same directory as this script, or in your Python path.\n"
                                         f"Expected location: {os.path.join(script_dir, 'aes_file_encryption.py')}")
    sys.exit(1)

class AESGUI:
    def __init__(self, master):
        self.master = master
        master.title("AES Encrypt/Decrypt")
        master.geometry("550x480") # Kích thước cửa sổ
        master.resizable(False, False) # Không cho phép thay đổi kích thước cửa sổ
        master.configure(bg="#f0f0f0") # Màu nền nhẹ nhàng

        # Tiêu đề
        self.title_label = tk.Label(master, text="AES File Encryption/Decryption Tool", font=("Arial", 16, "bold"), bg="#f0f0f0", fg="#333")
        self.title_label.pack(pady=15)

        # Khung cho các trường nhập liệu chính
        self.input_frame = tk.Frame(master, bg="#f0f0f0")
        self.input_frame.pack(pady=10, padx=20, fill="x", expand=True) # expand=True để khung lấp đầy không gian

        # Cấu hình các cột trong input_frame để đảm bảo các ô nhập liệu và nút cân đối
        self.input_frame.grid_columnconfigure(0, weight=0) # Cột nhãn
        self.input_frame.grid_columnconfigure(1, weight=1) # Cột ô nhập liệu - cho phép mở rộng
        self.input_frame.grid_columnconfigure(2, weight=0) # Cột nút duyệt

        # --- Trường cho Tệp gốc (để mã hóa) ---
        self.original_file_path_label = tk.Label(self.input_frame, text="Original File (to encrypt):", font=("Arial", 10), bg="#f0f0f0")
        self.original_file_path_label.grid(row=0, column=0, sticky="w", pady=5)
        # Giảm chiều rộng của ô Entry
        self.original_file_path_entry = tk.Entry(self.input_frame, width=35, font=("Arial", 10)) 
        self.original_file_path_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew") # sticky="ew" để ô lấp đầy không gian
        self.original_file_path_entry.bind("<KeyRelease>", self.auto_suggest_key_filename)
        self.browse_original_button = tk.Button(self.input_frame, text="Browse...", command=self.browse_original_file, font=("Arial", 9))
        self.browse_original_button.grid(row=0, column=2, padx=5, pady=5)

        # --- Trường cho Tệp đã mã hóa (để giải mã) ---
        self.encrypted_file_path_label = tk.Label(self.input_frame, text="Encrypted File (to decrypt):", font=("Arial", 10), bg="#f0f0f0")
        self.encrypted_file_path_label.grid(row=1, column=0, sticky="w", pady=5)
        # Giảm chiều rộng của ô Entry
        self.encrypted_file_path_entry = tk.Entry(self.input_frame, width=35, font=("Arial", 10))
        self.encrypted_file_path_entry.grid(row=1, column=1, padx=5, pady=5, sticky="ew")
        self.browse_encrypted_button = tk.Button(self.input_frame, text="Browse...", command=self.browse_encrypted_file, font=("Arial", 9))
        self.browse_encrypted_button.grid(row=1, column=2, padx=5, pady=5)

        # --- Tên tệp Khóa (chung cho cả mã hóa và giải mã file) ---
        self.key_filename_label = tk.Label(self.input_frame, text="Key Filename (in 'Key' folder):", font=("Arial", 10), bg="#f0f0f0")
        self.key_filename_label.grid(row=2, column=0, sticky="w", pady=5)
        # Giảm chiều rộng của ô Entry
        self.key_filename_entry = tk.Entry(self.input_frame, width=35, font=("Arial", 10))
        self.key_filename_entry.grid(row=2, column=1, padx=5, pady=5, sticky="ew")
        self.browse_key_button = tk.Button(self.input_frame, text="Browse Key...", command=self.browse_key_file, font=("Arial", 9))
        self.browse_key_button.grid(row=2, column=2, padx=5, pady=5)
        # Giá trị mặc định ban đầu cho tên tệp khóa
        self.key_filename_entry.insert(0, "default_key.bin")


        # Khung cho các tùy chọn Khóa (chỉ dùng cho Mã hóa)
        self.key_option_frame = tk.LabelFrame(self.input_frame, text="Key Options (for Encryption only)", font=("Arial", 10, "bold"), bg="#f0f0f0", bd=2, relief="groove")
        self.key_option_frame.grid(row=3, column=0, columnspan=3, sticky="ew", pady=10) # span 3 cột để lấp đầy ngang

        self.key_choice_var = tk.StringVar(value="random") # Mặc định là tạo khóa ngẫu nhiên

        self.random_key_radio = tk.Radiobutton(self.key_option_frame, text="Generate Random Key", variable=self.key_choice_var, value="random",
                                                command=self.toggle_custom_key_entry, bg="#f0f0f0", font=("Arial", 10))
        self.random_key_radio.pack(anchor="w", padx=10, pady=5)

        self.custom_key_radio = tk.Radiobutton(self.key_option_frame, text="Enter Custom Key (32 hex chars)", variable=self.key_choice_var, value="custom",
                                                command=self.toggle_custom_key_entry, bg="#f0f0f0", font=("Arial", 10))
        self.custom_key_radio.pack(anchor="w", padx=10, pady=5)

        # Trường nhập khóa tùy chỉnh (ban đầu bị vô hiệu hóa)
        # Giảm chiều rộng của ô Entry này
        self.custom_key_entry = tk.Entry(self.key_option_frame, width=35, font=("Arial", 10), state="disabled")
        self.custom_key_entry.pack(anchor="w", padx=20, pady=5)

        # Các nút hành động
        self.button_frame = tk.Frame(master, bg="#f0f0f0")
        self.button_frame.pack(pady=20)

        self.encrypt_button = tk.Button(self.button_frame, text="Encrypt File", command=self.encrypt_action,
                                         font=("Arial", 11, "bold"), bg="#4CAF50", fg="white", width=15)
        self.encrypt_button.pack(side="left", padx=10)

        self.decrypt_button = tk.Button(self.button_frame, text="Decrypt File", command=self.decrypt_action,
                                         font=("Arial", 11, "bold"), bg="#2196F3", fg="white", width=15)
        self.decrypt_button.pack(side="left", padx=10)

        # Khu vực trạng thái
        self.status_label = tk.Label(master, text="", fg="blue", font=("Arial", 10), bg="#f0f0f0")
        self.status_label.pack(pady=10)

    def auto_suggest_key_filename(self, event=None):
        """Tự động gợi ý tên tệp khóa dựa trên tên tệp gốc được chọn."""
        file_path = self.original_file_path_entry.get()
        if file_path:
            file_basename = os.path.basename(file_path)
            # Loại bỏ phần mở rộng .aes nếu người dùng vô tình chọn tệp .aes làm tệp gốc
            if file_basename.lower().endswith(".aes"):
                file_basename = file_basename[:-4]

            # Tạo tên tệp khóa gợi ý (ví dụ: "document_key.bin")
            suggested_key_filename = f"{os.path.splitext(file_basename)[0]}_key.bin"
            
            current_key_entry_value = self.key_filename_entry.get()
            # Cập nhật tên tệp khóa nếu nó trống, là giá trị mặc định,
            # hoặc phù hợp với một gợi ý tự động trước đó (chứa "_key.bin")
            # Tránh ghi đè nếu người dùng đã nhập tên khóa khác
            if not current_key_entry_value or \
               current_key_entry_value == "default_key.bin" or \
               "_key.bin" in current_key_entry_value: # Đây là một cách đơn giản để kiểm tra gợi ý cũ
                self.key_filename_entry.delete(0, tk.END)
                self.key_filename_entry.insert(0, suggested_key_filename)

    def browse_original_file(self):
        """Mở hộp thoại để người dùng chọn tệp tin gốc để mã hóa."""
        file_path = filedialog.askopenfilename()
        if file_path:
            self.original_file_path_entry.delete(0, tk.END)
            self.original_file_path_entry.insert(0, file_path)
            self.auto_suggest_key_filename() # Gợi ý tên tệp khóa ngay sau khi chọn tệp

    def browse_encrypted_file(self):
        """Mở hộp thoại để người dùng chọn tệp tin đã mã hóa để giải mã."""
        file_path = filedialog.askopenfilename(filetypes=[("AES Encrypted Files", "*.aes"), ("All files", "*.*")])
        if file_path:
            self.encrypted_file_path_entry.delete(0, tk.END)
            self.encrypted_file_path_entry.insert(0, file_path)

    def browse_key_file(self):
        """
        Mở hộp thoại để người dùng chọn/lưu tên tệp khóa.
        Sẽ mở mặc định trong thư mục KEY_STORAGE_DIR.
        """
        # Đảm bảo thư mục KEY_STORAGE_DIR tồn tại trước khi mở hộp thoại
        os.makedirs(KEY_STORAGE_DIR, exist_ok=True)
        
        # Sử dụng asksaveasfilename để cho phép người dùng nhập tên tệp mới hoặc chọn tệp đã có
        # initialdir sẽ đặt thư mục mặc định là KEY_STORAGE_DIR
        key_full_path = filedialog.asksaveasfilename(
            defaultextension=".bin",
            initialdir=os.path.join(os.getcwd(), KEY_STORAGE_DIR),
            title="Select/Create Key Filename",
            filetypes=[("Binary Key Files", "*.bin"), ("All files", "*.*")]
        )
        if key_full_path:
            # Lấy chỉ tên tệp từ đường dẫn đầy đủ
            key_filename = os.path.basename(key_full_path)
            self.key_filename_entry.delete(0, tk.END)
            self.key_filename_entry.insert(0, key_filename)

    def toggle_custom_key_entry(self):
        """Chuyển đổi trạng thái của trường nhập khóa tùy chỉnh (bật/tắt)."""
        if self.key_choice_var.get() == "custom":
            self.custom_key_entry.config(state="normal")
        else:
            self.custom_key_entry.config(state="disabled")
            self.custom_key_entry.delete(0, tk.END) # Xóa nội dung khi vô hiệu hóa

    def encrypt_action(self):
        """Xử lý hành động mã hóa tệp tin."""
        original_file_path = self.original_file_path_entry.get()
        key_file_name = self.key_filename_entry.get() # Lấy tên tệp khóa, không phải đường dẫn đầy đủ
        user_key = None

        if not original_file_path:
            messagebox.showerror("Error", "Please select an original file to encrypt.")
            return

        if not key_file_name:
            messagebox.showerror("Error", f"Please enter a filename for the encryption key. It will be saved in the '{KEY_STORAGE_DIR}' folder.")
            return

        if self.key_choice_var.get() == "custom":
            user_key = self.custom_key_entry.get()
            if not user_key:
                messagebox.showerror("Error", "Please enter a custom key (32 hex characters).")
                return
            if len(user_key) != 32:
                messagebox.showerror("Error", "Custom key must be 32 hex characters (16 bytes).")
                return
            try:
                bytes.fromhex(user_key) # Kiểm tra xem chuỗi có phải hex hợp lệ không
            except ValueError:
                messagebox.showerror("Error", "Custom key is not a valid hex string.")
                return

        try:
            self.status_label.config(text="Encrypting...", fg="orange")
            self.master.update_idletasks() # Cập nhật giao diện ngay lập tức

            # Gọi hàm mã hóa từ script aes_file_encryption.py
            # Truyền tên tệp khóa, không phải đường dẫn đầy đủ
            encrypt_file(original_file_path, key_file_name, user_key)
            
            encrypted_output_path = original_file_path + ".aes" # Đường dẫn tệp đã mã hóa
            full_key_path_display = os.path.join(KEY_STORAGE_DIR, key_file_name) # Đường dẫn đầy đủ để hiển thị

            messagebox.showinfo("Success", f"File encrypted successfully!\n"
                                          f"Encrypted file: {encrypted_output_path}\n"
                                          f"Key saved at: {full_key_path_display}")
            self.status_label.config(text="Encryption complete!", fg="green")
            
            # Tự động điền tệp đã mã hóa vào trường giải mã
            self.encrypted_file_path_entry.delete(0, tk.END)
            self.encrypted_file_path_entry.insert(0, encrypted_output_path)

        except (FileNotFoundError, ValueError, OSError, Exception) as e:
            messagebox.showerror("Error", f"Encryption failed: {e}")
            self.status_label.config(text=f"Error: {e}", fg="red")

    def decrypt_action(self):
        """Xử lý hành động giải mã tệp tin."""
        encrypted_file_path = self.encrypted_file_path_entry.get()
        key_file_name = self.key_filename_entry.get() # Lấy tên tệp khóa

        if not encrypted_file_path:
            messagebox.showerror("Error", "Please select an encrypted file to decrypt.")
            return

        if not key_file_name:
            messagebox.showerror("Error", f"Please enter the key filename. It should be in the '{KEY_STORAGE_DIR}' folder.")
            return

        # Vẫn giữ cảnh báo nếu tệp không có đuôi .aes
        if not encrypted_file_path.lower().endswith(".aes"):
            response = messagebox.askyesno("Warning", "The selected file does not have a '.aes' extension. Are you sure you want to proceed with decryption?\n\nDecrypted file will be saved with '.decrypted' suffix.")
            if not response:
                return

        try:
            self.status_label.config(text="Decrypting...", fg="orange")
            self.master.update_idletasks() # Cập nhật giao diện ngay lập tức

            # Gọi hàm giải mã từ script aes_file_encryption.py
            decrypt_file(encrypted_file_path, key_file_name)
            
            # Xác định tên tệp đã giải mã để hiển thị
            decrypted_file_name = encrypted_file_path[:-4] if encrypted_file_path.lower().endswith('.aes') else encrypted_file_path + ".decrypted"
            messagebox.showinfo("Success", f"File decrypted successfully!\nDecrypted file: {decrypted_file_name}")
            self.status_label.config(text="File decryption complete!", fg="green")

        except (FileNotFoundError, ValueError, IOError, Exception) as e:
            messagebox.showerror("Error", f"Decryption failed: {e}")
            self.status_label.config(text=f"Error: {e}", fg="red")

if __name__ == "__main__":
    # Tạo thư mục KEY_STORAGE_DIR nếu nó chưa tồn tại khi ứng dụng khởi chạy
    os.makedirs(KEY_STORAGE_DIR, exist_ok=True)
    
    root = tk.Tk()
    app = AESGUI(root)
    root.mainloop()
