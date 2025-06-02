import tkinter as tk
from tkinter import ttk, messagebox
from Aes_work import AES
import os
from aes_visualizer import AesVisualizer

class AesGui:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("AES 加解密工具")
        self.window.geometry("900x700")  # 調整視窗大小
        
        # 設定視窗最小尺寸
        self.window.minsize(800, 600)
        
        # 配置根視窗的網格權重
        self.window.grid_rowconfigure(0, weight=1)
        self.window.grid_columnconfigure(0, weight=1)
        
        # 建立主要框架並置中
        self.main_frame = ttk.Frame(self.window, padding="20")
        self.main_frame.grid(row=0, column=0, sticky="nsew")
        
        # 配置主框架的網格權重
        self.main_frame.grid_columnconfigure(1, weight=1)
        
        # 調整標籤寬度以對齊
        label_width = 15
        
        # 金鑰輸入區
        ttk.Label(self.main_frame, text="金鑰 (hex):", width=label_width).grid(row=0, column=0, sticky="e", padx=5)
        key_frame = ttk.Frame(self.main_frame)
        key_frame.grid(row=0, column=1, sticky="ew", pady=10)
        
        self.key_var = tk.StringVar()
        self.key_entry = ttk.Entry(key_frame, textvariable=self.key_var, width=60)  # 加寬輸入框
        self.key_entry.pack(side=tk.LEFT, padx=5)
        
        # 金鑰長度選擇
        self.key_length = tk.StringVar(value="128")
        key_length_combo = ttk.Combobox(key_frame, 
                                      textvariable=self.key_length,
                                      values=["128", "192", "256"],
                                      width=6,
                                      state="readonly")
        key_length_combo.pack(side=tk.LEFT, padx=5)
        
        # 綁定金鑰長度變更事件
        key_length_combo.bind('<<ComboboxSelected>>', lambda e: self.generate_random_key())
        
        ttk.Button(key_frame, text="產生金鑰", command=self.generate_random_key).pack(side=tk.LEFT, padx=5)
        
        # 明文/密文輸入區
        ttk.Label(self.main_frame, text="輸入文字:", width=label_width).grid(row=1, column=0, sticky="e", padx=5)
        input_frame = ttk.Frame(self.main_frame)
        input_frame.grid(row=1, column=1, sticky="ew", pady=10)
        
        mode_frame = ttk.Frame(input_frame)
        mode_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # 輸入模式選擇
        self.input_mode = tk.StringVar(value="hex")
        ttk.Label(mode_frame, text="輸入格式:").pack(side=tk.LEFT)
        ttk.Radiobutton(mode_frame, text="Hex", variable=self.input_mode, 
                       value="hex", command=self.on_mode_change).pack(side=tk.LEFT, padx=10)
        ttk.Radiobutton(mode_frame, text="String", variable=self.input_mode, 
                       value="string", command=self.on_mode_change).pack(side=tk.LEFT, padx=10)
        
        # 輸入文字區
        self.input_text = tk.Text(input_frame, height=6, width=60)
        self.input_text.pack(fill=tk.X, padx=5)
        
        # 設定預設測資並確保格式對應
        self.input_mode.set("hex")  # 強制設定為 hex 模式
        self.input_text.insert("1.0", "48 65 6C 6C 6F 20 57 6F 72 6C 64")  # "Hello World" 的 hex

        # 設定預設金鑰
        self.key_var.set("2B 7E 15 16 28 AE D2 A6 AB F7 15 88 09 CF 4F 3C")
        
        # 在建立輸出區域之前先定義 output_mode
        self.output_mode = tk.StringVar(value="hex")
        
        # 輸出區域
        ttk.Label(self.main_frame, text="輸出結果:", width=label_width).grid(row=2, column=0, sticky="e", padx=5)
        output_frame = ttk.Frame(self.main_frame)
        output_frame.grid(row=2, column=1, sticky="ew", pady=10)
        
        mode_frame = ttk.Frame(output_frame)
        mode_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # 輸出格式選擇
        ttk.Label(mode_frame, text="輸出格式:").pack(side=tk.LEFT)
        ttk.Radiobutton(mode_frame, text="Hex", variable=self.output_mode, 
                       value="hex", command=self.convert_output).pack(side=tk.LEFT, padx=10)
        ttk.Radiobutton(mode_frame, text="String", variable=self.output_mode,
                       value="string", command=self.convert_output).pack(side=tk.LEFT, padx=10)
        
        self.output_text = tk.Text(output_frame, height=6, width=60)
        self.output_text.pack(fill=tk.X, padx=5)
        
        # 按鈕區域置中
        button_frame = ttk.Frame(self.main_frame)
        button_frame.grid(row=3, column=0, columnspan=2, pady=20)
        
        for text, command in [("加密", self.encrypt), ("解密", self.decrypt), ("清除", self.clear)]:
            ttk.Button(button_frame, text=text, command=command, width=15).pack(side=tk.LEFT, padx=10)
            
        # 新增加解密過程視覺化區域
        process_frame = ttk.LabelFrame(self.main_frame, text="加解密過程", padding="10")
        process_frame.grid(row=4, column=0, columnspan=2, sticky="ew", pady=10)
        
        # 建立Canvas用於繪製過程，增加高度
        self.process_canvas = tk.Canvas(process_frame, height=200, bg='white')  # 從 150 改為 200
        self.process_canvas.pack(fill=tk.X, padx=5, pady=5)
        
        # 在 Canvas 外加入 Scrollbar
        scrollbar = ttk.Scrollbar(process_frame, orient="vertical", command=self.process_canvas.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.process_canvas.configure(yscrollcommand=scrollbar.set)
        self.process_canvas.bind('<Configure>', lambda e: self.process_canvas.configure(scrollregion=self.process_canvas.bbox("all")))
        
        # 加入控制按鈕
        control_frame = ttk.Frame(process_frame)
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # 使用 class variables 儲存按鈕參考
        self.next_button = ttk.Button(control_frame, text="下一步", 
                                    command=lambda: self.visualizer.next_step())
        self.next_button.pack(side=tk.LEFT, padx=5)
        
        self.auto_button = ttk.Button(control_frame, text="自動", 
                                    command=lambda: self.visualizer.auto_play())
        self.auto_button.pack(side=tk.LEFT, padx=5)
        
        self.pause_button = ttk.Button(control_frame, text="暫停", 
                                     command=lambda: self.visualizer.pause())
        self.pause_button.pack(side=tk.LEFT, padx=5)
        
        # 初始化視覺化器
        self.visualizer = AesVisualizer(self.process_canvas)
        
        # 初始化過程顯示狀態
        self.animation_speed = 500  # 動畫速度(毫秒)
        
    def hex_to_bytes(self, hex_str):
        """將十六進制字串轉換為位元組"""
        hex_str = hex_str.replace(" ", "")
        return bytes.fromhex(hex_str)

    def bytes_to_hex(self, byte_data):
        """將位元組轉換為十六進制字串"""
        return " ".join(f"{b:02x}" for b in byte_data)

    def str_to_bytes(self, text):
        """將字符串轉換為位元組"""
        # 如果是 hex 模式，使用原有的轉換方法
        if self.input_mode.get() == "hex":
            return self.hex_to_bytes(text)
        # 如果是 string 模式，直接編碼
        return text.encode('utf-8')

    def encrypt(self):
        try:
            # 獲取並驗證輸入
            input_text = self.input_text.get("1.0", "end-1c").strip()
            print(f"輸入內容(長度={len(input_text)}):", input_text)
            
            if not input_text:
                messagebox.showerror("錯誤", "請輸入要加密的文字")
                return
            
            # 驗證並處理金鑰
            key = self.key_var.get().strip()
            key_length = int(self.key_length.get())
            required_hex_chars = key_length // 4  # 計算需要的十六進制字符數
            
            print("使用金鑰:", key)
            if not key or len(key.replace(" ", "")) != required_hex_chars:
                messagebox.showerror("錯誤", f"金鑰格式錯誤，{key_length}位元金鑰需要{required_hex_chars}個十六進制字符")
                return
            
            key = [int(b) for b in self.hex_to_bytes(key)]
            
            # 處理明文
            try:
                if self.input_mode.get() == "hex":
                    # 檢查hex格式
                    clean_hex = input_text.replace(" ", "")
                    if not all(c in '0123456789ABCDEFabcdef' for c in clean_hex):
                        messagebox.showerror("錯誤", "十六進制格式不正確")
                        return
                    plaintext = list(self.hex_to_bytes(input_text))
                else:
                    plaintext = list(input_text.encode('utf-8'))
                
                print(f"原始數據(hex): {' '.join(f'{b:02X}' for b in plaintext)}")  # 改用大寫十六進制
                
            except Exception as e:
                messagebox.showerror("錯誤", f"輸入格式錯誤: {str(e)}")
                return
            
            # PKCS7 填充
            padding_length = 16 - (len(plaintext) % 16)
            padded_data = plaintext + [padding_length] * padding_length
            print(f"填充後數據(hex): {' '.join(f'{b:02X}' for b in padded_data)}")  # 改用大寫十六進制
            
            # 加密處理
            aes = AES(key)
            ciphertext = bytearray()
            process_steps = []
            
            # 修改步驟記錄格式
            process_steps.append(["初始狀態", self.format_block(plaintext)])
            process_steps.append(["填充處理", self.format_block(padded_data)])
            
            # 分塊加密
            for i in range(0, len(padded_data), 16):
                block = padded_data[i:i+16].copy()
                block_num = i // 16
                state = aes.get_state_matrix(block)
                
                # 記錄初始狀態
                process_steps.append([f"區塊 {block_num}", "輸入", "", self.format_matrix(state)])
                
                # 初始輪金鑰加法
                state = aes.add_round_key(state, aes.round_keys[0])
                process_steps.append([f"區塊 {block_num}", "Round 0", "AddRoundKey", self.format_matrix(state)])
                
                # 主要回合
                for round in range(1, aes.rounds):
                    # 記錄每個步驟的狀態
                    state = aes.sub_bytes(state)
                    process_steps.append([f"區塊 {block_num}", f"Round {round}", "SubBytes", self.format_matrix(state)])
                    
                    state = aes.shift_rows(state)
                    process_steps.append([f"區塊 {block_num}", f"Round {round}", "ShiftRows", self.format_matrix(state)])
                    
                    state = aes.mix_columns(state)
                    process_steps.append([f"區塊 {block_num}", f"Round {round}", "MixColumns", self.format_matrix(state)])
                    
                    state = aes.add_round_key(state, aes.round_keys[round])
                    process_steps.append([f"區塊 {block_num}", f"Round {round}", "AddRoundKey", self.format_matrix(state)])
                
                # 最後一輪
                state = aes.sub_bytes(state)
                process_steps.append([f"區塊 {block_num}", "Final Round", "SubBytes", self.format_matrix(state)])
                
                state = aes.shift_rows(state)
                process_steps.append([f"區塊 {block_num}", "Final Round", "ShiftRows", self.format_matrix(state)])
                
                state = aes.add_round_key(state, aes.round_keys[aes.rounds])
                process_steps.append([f"區塊 {block_num}", "Final Round", "AddRoundKey", self.format_matrix(state)])
                
                # 轉換回位元組並加入密文
                encrypted_block = aes.state_to_bytes(state)
                ciphertext.extend(encrypted_block)
            
            # 記錄最終結果
            result = self.bytes_to_hex(ciphertext)
            process_steps.append(["最終結果", result])
            
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert("1.0", result)
            
            # 更新視覺化
            self.visualizer.animate_process(process_steps, self.window, self.animation_speed)
            
        except Exception as e:
            print(f"加密錯誤: {str(e)}")
            messagebox.showerror("錯誤", f"加密過程出錯: {str(e)}")

    def pad_data(self, data):
        """PKCS7填充，並記錄填充過程"""
        padding_length = 16 - (len(data) % 16)
        padded = data + [padding_length] * padding_length
        return padded

    def format_output(self, data):
        """根據輸出模式格式化數據"""
        mode = self.output_mode.get()
        
        if mode == "hex":
            return self.bytes_to_hex(bytes(data))
        elif mode == "string":
            try:
                return bytes(data).decode('utf-8')
            except UnicodeDecodeError:
                return self.bytes_to_hex(bytes(data))
        else:  # auto mode
            try:
                # 嘗試解碼為字符串，如果失敗則顯示為十六進制
                if self.input_mode.get() == "string":
                    return bytes(data).decode('utf-8')
                return self.bytes_to_hex(bytes(data))
            except UnicodeDecodeError:
                return self.bytes_to_hex(bytes(data))

    def decrypt(self):
        try:
            # 強制更新 Text widget 的內容
            self.input_text.update_idletasks()
            self.window.update_idletasks()
            
            # 驗證並處理金鑰
            key = self.key_var.get().strip()
            key_length = int(self.key_length.get())
            required_hex_chars = key_length // 4  # 計算需要的十六進制字符數
            
            if not key or len(key.replace(" ", "")) != required_hex_chars:
                messagebox.showerror("錯誤", f"金鑰格式錯誤，{key_length}位元金鑰需要{required_hex_chars}個十六進制字符")
                return
            
            key = [int(b) for b in self.hex_to_bytes(key)]
            
            # 獲取最新的輸入文字
            input_text = self.input_text.get("1.0", "end-1c").strip()
            if not input_text:
                messagebox.showerror("錯誤", "請輸入要解密的文字")
                return
            
            # 根據輸入模式處理文字
            try:
                if self.input_mode.get() == "hex":
                    ciphertext = list(self.hex_to_bytes(input_text))
                else:
                    ciphertext = list(input_text.encode('utf-8'))
            except Exception as e:
                messagebox.showerror("錯誤", f"輸入格式錯誤: {str(e)}")
                return
            
            if len(ciphertext) % 16 != 0:
                messagebox.showerror("錯誤", "密文長度必須是16的倍數")
                return
            
            # 每次解密都建立新的 AES 實例
            aes = AES(key)
            plaintext = bytearray()  # 確保在這裡初始化 plaintext
            
            process_steps = []
            process_steps.append(["密文(hex)", [f"{b:02X}" for b in ciphertext]])
            
            for i in range(0, len(ciphertext), 16):
                block = ciphertext[i:i+16].copy()
                block_num = i // 16
                state = aes.get_state_matrix(block)
                
                # 記錄初始狀態
                process_steps.append([f"區塊 {block_num}", "輸入", "", self.format_matrix(state)])
                
                # 初始輪金鑰加法，加上 (inv) 標記
                state = aes.add_round_key(state, aes.round_keys[aes.rounds])
                process_steps.append([f"區塊 {block_num}", "Round 0", "(inv)AddRoundKey", self.format_matrix(state)])
                
                # 主要回合，解密順序與加密相反
                for round in range(aes.rounds-1, 0, -1):
                    # 逆行位移
                    state = aes.inv_shift_rows(state)
                    process_steps.append([f"區塊 {block_num}", f"Round {aes.rounds-round}", "InvShiftRows", self.format_matrix(state)])
                    
                    # 逆字節替換
                    state = aes.inv_sub_bytes(state)
                    process_steps.append([f"區塊 {block_num}", f"Round {aes.rounds-round}", "InvSubBytes", self.format_matrix(state)])
                    
                    # 輪密鑰加，加上 (inv) 標記
                    state = aes.add_round_key(state, aes.round_keys[round])
                    process_steps.append([f"區塊 {block_num}", f"Round {aes.rounds-round}", "(inv)AddRoundKey", self.format_matrix(state)])
                    
                    # 逆列混合
                    state = aes.inv_mix_columns(state)
                    process_steps.append([f"區塊 {block_num}", f"Round {aes.rounds-round}", "InvMixColumns", self.format_matrix(state)])
                
                # 最後一輪
                state = aes.inv_shift_rows(state)
                process_steps.append([f"區塊 {block_num}", "Final Round", "InvShiftRows", self.format_matrix(state)])
                
                state = aes.inv_sub_bytes(state)
                process_steps.append([f"區塊 {block_num}", "Final Round", "InvSubBytes", self.format_matrix(state)])
                
                state = aes.add_round_key(state, aes.round_keys[0])
                process_steps.append([f"區塊 {block_num}", "Final Round", "(inv)AddRoundKey", self.format_matrix(state)])
                
                # 轉換回位元組並加入明文
                decrypted_block = aes.state_to_bytes(state)
                plaintext.extend(decrypted_block)
            
            # 移除填充並記錄
            if plaintext:
                process_steps.append(["padding前明文(hex)", [f"{b:02X}" for b in plaintext]])
                padding_length = plaintext[-1]
                if 0 < padding_length <= 16:
                    if all(x == padding_length for x in plaintext[-padding_length:]):
                        plaintext = plaintext[:-padding_length]
                        process_steps.append(["移除padding後明文(hex)", [f"{b:02X}" for b in plaintext]])
            
            # 更新輸出並播放動畫
            result = self.format_output(plaintext)
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert("1.0", result)
            self.visualizer.animate_process(process_steps, self.window, self.animation_speed)
            
        except Exception as e:
            messagebox.showerror("錯誤", f"解密過程出錯: {str(e)}")

    def clear(self):
        """清除輸入和輸出，但保留金鑰"""
        # 保存當前金鑰
        current_key = self.key_var.get()
        
        # 清除輸入和輸output_text區域
        self.input_text.delete("1.0", tk.END)
        self.output_text.delete("1.0", tk.END)
        
        # 如果有金鑰就恢復金鑰，沒有就產生新的
        if current_key:
            self.key_var.set(current_key)
        else:
            self.generate_random_key()

    def generate_random_key(self):
        """產生指定長度的隨機金鑰"""
        try:
            # 根據選擇的位元長度計算位元組數
            key_bytes = int(self.key_length.get()) // 8
            # 使用 os.urandom 生成密碼學安全的隨機位元組
            random_key = os.urandom(key_bytes)
            # 轉換為十六進制並更新到輸入框
            self.key_var.set(self.bytes_to_hex(random_key))
        except Exception as e:
            messagebox.showerror("錯誤", f"產生金鑰失敗: {str(e)}")
            
    def convert_output(self):
        """當輸出格式改變時轉換輸出文字"""
        try:
            output_text = self.output_text.get("1.0", "end-1c").strip()
            if not output_text:
                return
                
            # 先檢查目前的文字格式
            is_hex = all(c in '0123456789ABCDEFabcdef ' for c in output_text)
            
            # 如果要轉成 hex 且目前不是 hex
            if self.output_mode.get() == "hex" and not is_hex:
                try:
                    data = output_text.encode('utf-8')
                    hex_text = self.bytes_to_hex(data)
                    self.output_text.delete("1.0", tk.END)
                    self.output_text.insert("1.0", hex_text)
                except:
                    # 如果無法轉成 hex，回復到 string 模式
                    self.output_mode.set("string")
                    messagebox.showwarning("警告", "無法轉換為十六進制格式")
                    
            # 如果要轉成 string 且目前是 hex
            elif self.output_mode.get() == "string" and is_hex:
                try:
                    data = self.hex_to_bytes(output_text)
                    text = data.decode('utf-8')
                    self.output_text.delete("1.0", tk.END)
                    self.output_text.insert("1.0", text)
                except:
                    # 如果無法轉成 string，維持 hex 模式
                    self.output_mode.set("hex")
                    messagebox.showwarning("警告", "此十六進制內容無法轉換為文字")
                    
        except Exception as e:
            print(f"轉換輸出格式時發生錯誤: {str(e)}")

    def on_mode_change(self, *args):
        """當輸入模式改變時轉換輸入文字"""
        try:
            # 取得當前輸入文字
            current_text = self.input_text.get("1.0", "end-1c").strip()
            if not current_text:
                return
            
            # 檢查當前模式
            current_mode = self.input_mode.get()
            is_hex = all(c in '0123456789ABCDEFabcdef ' for c in current_text)
            
            # 轉換到 hex 模式
            if current_mode == "hex" and not is_hex:
                try:
                    # 如果當前是字串，轉换為 hex
                    data = current_text.encode('utf-8')
                    hex_text = self.bytes_to_hex(data)
                    self.input_text.delete("1.0", tk.END)
                    self.input_text.insert("1.0", hex_text)
                except Exception as e:
                    # 如果轉換失敗，使用預設值
                    self.input_text.delete("1.0", tk.END)
                    self.input_text.insert("1.0", "48 65 6C 6C 6F 20 57 6F 72 6C 64")
                    messagebox.showwarning("警告", "格式轉換失敗，已恢復 hex 預設值")
            
            # 轉換到 string 模式
            elif current_mode == "string" and is_hex:
                try:
                    # 如果當前是 hex，轉換為字串
                    data = self.hex_to_bytes(current_text)
                    text = data.decode('utf-8')
                    self.input_text.delete("1.0", tk.END)
                    self.input_text.insert("1.0", text)
                except Exception as e:
                    # 如果轉換失敗，使用預設值
                    self.input_text.delete("1.0", tk.END)
                    self.input_text.insert("1.0", "Hello World")
                    messagebox.showwarning("警告", "格式轉換失敗，已恢復字串預設值")
            
        except Exception as e:
            print(f"輸入模式切換錯誤: {str(e)}")
            self.input_mode.set("hex")  # 發生錯誤時回到 hex 模式

    def format_block(self, block):
        """格式化位元組區塊為易讀格式"""
        if isinstance(block, list) and len(block) <= 16:
            return [f"{b:02X}" for b in block] + ["00"] * (16 - len(block))  # 補足16個元素
        return [f"{b:02X}" for b in block]

    def format_matrix(self, matrix):
        """格式化 4x4 矩陣為易讀格式"""
        formatted = []
        for i in range(4):
            for j in range(4):
                formatted.append(f"{matrix[i][j]:02X}")
        return formatted  # 確保返回16個元素的列表

if __name__ == "__main__":
    try:
        gui = AesGui()
        gui.window.mainloop()
    except Exception as e:
        print(f"程式啟動失敗: {str(e)}")
        raise
