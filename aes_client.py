import os
import sys
import argparse
import socket
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from Aes_work import AES

class AESBaseClient:
    """基礎AES客戶端功能"""
    def __init__(self, host='127.0.0.1', port=12345):
        self.host = host
        self.port = port
        self.socket = None
        self.aes = None
        self.connected = False
        
    def format_bytes(self, data):
        """統一使用十六進制顯示位元組值"""
        return [hex(b)[2:].upper().zfill(2) for b in data]
    
    def encrypt_message(self, message):
        """加密訊息，支援 ECB 和 CBC 模式，使用 PKCS7 填充"""
        data = list(message.encode('utf-8'))
        print(f"原始數據(hex): {self.format_bytes(data)}")  # 顯示十六進制
        
        padding_length = 16 - (len(data) % 16)
        padded_data = data + [padding_length] * padding_length  # PKCS7 填充
        print(f"填充後數據(hex): {self.format_bytes(padded_data)}")  # 顯示十六進制
        
        if hasattr(self, 'use_iv_var') and self.use_iv_var.get():
            # CBC 模式加密
            iv = list(os.urandom(16))
            encrypted = iv[:]
            prev_block = iv
            for i in range(0, len(padded_data), 16):
                block = padded_data[i:i+16]
                xored = [b1 ^ b2 for b1, b2 in zip(block, prev_block)]
                encrypted_block = self.aes.encrypt_block(xored)
                encrypted.extend(encrypted_block)
                prev_block = encrypted_block
        else:
            # ECB 模式加密
            encrypted = []
            for i in range(0, len(padded_data), 16):
                block = padded_data[i:i+16]
                encrypted.extend(self.aes.encrypt_block(block))
        return encrypted

    def decrypt_message(self, encrypted_data):
        """解密訊息，自動檢測模式並處理 PKCS7 填充"""
        try:
            # 嘗試 CBC 模式解密
            if len(encrypted_data) > 16 and len(encrypted_data) % 16 == 0:
                iv = encrypted_data[:16]
                cipher_blocks = encrypted_data[16:]
                decrypted = []
                prev_block = iv
                
                for i in range(0, len(cipher_blocks), 16):
                    block = cipher_blocks[i:i+16]
                    decrypted_block = self.aes.decrypt_block(block)
                    plain_block = [b1 ^ b2 for b1, b2 in zip(decrypted_block, prev_block)]
                    decrypted.extend(plain_block)
                    prev_block = block
                
                # 處理 PKCS7 填充
                padding_length = decrypted[-1]
                if 0 < padding_length <= 16:
                    if all(x == padding_length for x in decrypted[-padding_length:]):
                        decrypted = decrypted[:-padding_length]
                        return bytes(decrypted).decode('utf-8')
        except:
            pass
        
        # ECB 模式解密
        decrypted = []
        for i in range(0, len(encrypted_data), 16):
            block = encrypted_data[i:i+16]
            decrypted.extend(self.aes.decrypt_block(block))
        
        # 處理 PKCS7 填充
        padding_length = decrypted[-1]
        if 0 < padding_length <= 16:
            if all(x == padding_length for x in decrypted[-padding_length:]):
                decrypted = decrypted[:-padding_length]
        
        return bytes(decrypted).decode('utf-8')
    
    def send_disconnect_notice(self):
        """傳送中斷連線通知給伺服器"""
        try:
            if self.socket and self.connected:
                disconnect_msg = "<<DISCONNECT>>"
                encrypted = self.encrypt_message(disconnect_msg)
                self.socket.send(bytes.fromhex(''.join(f'{b:02X}' for b in encrypted)))
        except:
            pass  # 忽略發送錯誤，因為可能已經斷線
    
    def connect_to_server(self, host, port):
        try:
            if not (1 <= port <= 65535):
                raise ValueError("Port 必須在 1-65535 之間")
                
            socket_obj = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket_obj.settimeout(5)  # 只在連線時使用超時
            
            try:
                socket_obj.connect((host, port))
                socket_obj.settimeout(None)  # 連線後取消超時
                return socket_obj
            except ConnectionRefusedError:
                raise ConnectionError(f"在 {host}:{port} 找不到運行中的伺服器")
            except socket.gaierror:
                raise ConnectionError(f"無效的伺服器位址: {host}")
            except socket.timeout:
                raise ConnectionError(f"連線至 {host}:{port} 超時")
            
        except Exception as e:
            if isinstance(e, ConnectionError):
                raise
            raise ConnectionError(f"連線失敗: {str(e)}")

class AESConsoleClient(AESBaseClient):
    """命令列介面客戶端"""
    def connect(self):
        try:
            self.socket = self.connect_to_server(self.host, self.port)
            print(f"已連線到伺服器 {self.host}:{self.port}")
            
            # 接收金鑰
            key_hex = self.socket.recv(1024).decode()
            key = [int(b, 16) for b in key_hex.split()]
            self.aes = AES(key)
            print(f"已接收 AES 金鑰: {key_hex}")
            
            # 啟動接收執行緒
            receive_thread = threading.Thread(target=self.receive_messages)
            receive_thread.daemon = True
            receive_thread.start()
            
            # 開始發送訊息
            self.send_messages()
            
        except Exception as e:
            print(f"連線錯誤: {e}")
        finally:
            self.socket.close()
            
    def send_messages(self):
        try:
            while True:
                message = input("")
                if message.lower() == 'quit':
                    break
                    
                encrypted = self.encrypt_message(message)
                self.socket.send(bytes.fromhex(''.join(
                    f'{b:02X}' for b in encrypted)))
                    
        except Exception as e:
            print(f"發送錯誤: {e}")
            
    def receive_messages(self):
        try:
            while True:
                encrypted_data = self.socket.recv(1024)
                if not encrypted_data:
                    break
                    
                encrypted_bytes = bytes.fromhex(encrypted_data.decode())
                decrypted = self.decrypt_message(list(encrypted_bytes))
                print(f"\n收到: {decrypted}")
                
        except Exception as e:
            print(f"接收錯誤: {e}")

class AESChatClient(AESBaseClient):
    """GUI介面客戶端"""
    def __init__(self, host=None, port=None, message_callback=None, default_key=None):
        # 保存初始值但不立即設定
        self.initial_host = host
        self.initial_port = port
        self.initial_key = default_key  # 新增預設金鑰
        # 呼叫父類別初始化，但不傳入 host 和 port
        super().__init__(host=None, port=None)
        self.message_callback = message_callback
        self.window = tk.Tk()
        self.window.title("AES 加密聊天室")
        self.window.geometry("600x400")
        
        # 設置網格權重
        self.window.grid_rowconfigure(1, weight=1)
        self.window.grid_columnconfigure(0, weight=1)
        
        # 使用垂直佈局的框架
        self.control_frame = ttk.Frame(self.window, padding="5")
        self.control_frame.grid(row=0, column=0, sticky="ew")
        
        # 第一行：伺服器連接設定
        self.connect_frame1 = ttk.Frame(self.control_frame)
        self.connect_frame1.pack(fill=tk.X)

        # 伺服器位址輸入
        ttk.Label(self.connect_frame1, text="伺服器:").pack(side=tk.LEFT)
        self.host_var = tk.StringVar(value="")
        self.host_entry = ttk.Entry(self.connect_frame1, textvariable=self.host_var, width=15)
        self.host_entry.pack(side=tk.LEFT, padx=5)
        
        # port 輸入框設定
        ttk.Label(self.connect_frame1, text="Port:").pack(side=tk.LEFT, padx=5)
        self.port_var = tk.StringVar()
        self.port_entry = ttk.Entry(self.connect_frame1, textvariable=self.port_var, width=6)
        self.port_entry.pack(side=tk.LEFT)
        
        # 按鈕區域
        self.connect_button = ttk.Button(self.connect_frame1, text="連接", command=self.connect)
        self.connect_button.pack(side=tk.LEFT, padx=5)
        
        self.disconnect_button = ttk.Button(self.connect_frame1, text="中斷連線", 
                                          command=self.disconnect, state="disabled")
        self.disconnect_button.pack(side=tk.LEFT, padx=5)
        
        self.default_button = ttk.Button(self.connect_frame1, text="預設資訊", 
                                       command=self.set_default_info)
        self.default_button.pack(side=tk.LEFT, padx=5)

        # 第二行：暱稱和金鑰設定
        self.connect_frame2 = ttk.Frame(self.control_frame)
        self.connect_frame2.pack(fill=tk.X, pady=(5,0))
        
        # 暱稱輸入
        ttk.Label(self.connect_frame2, text="暱稱:").pack(side=tk.LEFT, padx=5)
        self.nickname_var = tk.StringVar(value="")
        self.nickname_entry = ttk.Entry(self.connect_frame2, textvariable=self.nickname_var, width=15)
        self.nickname_entry.pack(side=tk.LEFT)
        
        # 金鑰輸入
        ttk.Label(self.connect_frame2, text="金鑰:").pack(side=tk.LEFT, padx=5)
        self.key_var = tk.StringVar()
        self.key_entry = ttk.Entry(self.connect_frame2, textvariable=self.key_var, width=40)
        self.key_entry.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(0,5))
        
        # 聊天訊息顯示區
        self.chat_area = scrolledtext.ScrolledText(self.window, wrap=tk.WORD, height=20)
        self.chat_area.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
        self.chat_area.config(state='disabled')  # 設定為唯讀
        
        # 訊息輸入區
        self.input_frame = ttk.Frame(self.window, padding="5")
        self.input_frame.grid(row=2, column=0, sticky="ew")
        
        self.message_var = tk.StringVar()
        self.message_entry = ttk.Entry(self.input_frame, textvariable=self.message_var)
        self.message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0,5))
        
        # 添加 IV 模式切換
        self.use_iv_var = tk.BooleanVar(value=False)
        self.iv_check = ttk.Checkbutton(self.input_frame, text="使用IV", 
                                      variable=self.use_iv_var)
        self.iv_check.pack(side=tk.RIGHT, padx=5)
        
        self.send_button = ttk.Button(self.input_frame, text="發送", 
                                    command=self.send_message, 
                                    state="disabled")
        self.send_button.pack(side=tk.RIGHT)
        
        # 綁定Enter鍵和文字變更事件
        self.message_entry.bind('<Return>', lambda e: self.send_message())
        self.message_var.trace_add("write", self.on_message_change)
        
    def on_message_change(self, *args):
        """當訊息內容改變時更新發送按鈕狀態"""
        if self.connected and self.message_var.get().strip():
            self.send_button.config(state="normal")
        else:
            self.send_button.config(state="disabled")
            
    def validate_key(self, key_hex):
        """驗證金鑰格式"""
        try:
            # 移除空格和其他空白字元
            key_hex = ''.join(key_hex.split())
            # 檢查長度
            if len(key_hex) != 32:  # 128位元 = 32個十六進制字符
                return False
            # 檢查是否為有效的十六進制
            int(key_hex, 16)
            # 檢查每個字符是否為合法的十六進制
            valid_chars = set('0123456789ABCDEFabcdef')
            if not all(c in valid_chars for c in key_hex):
                return False
            return True
        except ValueError:
            return False
    
    def connect(self):
        if self.connected:
            return
            
        try:
            # 檢查暱稱是否已輸入
            nickname = self.nickname_var.get().strip()
            if not nickname:
                messagebox.showerror("錯誤", "請輸入暱稱")
                return
                
            # 檢查是否有輸入必要資訊，不使用預設值
            host = self.host_var.get().strip()
            port_str = self.port_var.get().strip()

            # 檢查必要資訊是否完整
            if not host:
                messagebox.showerror("錯誤", "請輸入伺服器位址")
                return
                
            if not port_str:
                messagebox.showerror("錯誤", "請輸入 Port")
                return
                
            # 檢查 port 是否有效
            try:
                port = int(port_str)
                if not (1 <= port <= 65535):
                    raise ValueError("Port 必須在 1-65535 之間")
            except ValueError as e:
                messagebox.showerror("錯誤", str(e))
                return

            # 設定連線資訊
            self.host = host
            self.port = port
            
            # 檢查是否有輸入金鑰
            input_key = self.key_var.get().strip()
            if input_key:
                if not self.validate_key(input_key):
                    messagebox.showerror("錯誤", "金鑰格式無效\n需要32個十六進制字符(128位)\n例如: 0123456789ABCDEF0123456789ABCDEF")
                    return
                # 將金鑰標準化（移除空格並轉為大寫）
                input_key = ''.join(input_key.split()).upper()
                self.key_var.set(input_key)  # 更新顯示
                key = [int(input_key[i:i+2], 16) for i in range(0, 32, 2)]
                self.aes = AES(key)
                
            # 使用新的連線方法
            try:
                self.socket = self.connect_to_server(self.host, self.port)
            except ConnectionError as e:
                messagebox.showerror("連線錯誤", str(e))
                return
            
            # 如果沒有輸入金鑰，則接收伺服器金鑰
            if not input_key:
                try:
                    key_hex = self.socket.recv(1024).decode()  # 使用默認 utf-8 編碼
                    key = [int(b, 16) for b in key_hex.split()]
                    self.aes = AES(key)
                    self.key_var.set(key_hex)  # 顯示接收到的金鑰
                except Exception as e:
                    messagebox.showerror("錯誤", f"接收金鑰失敗: {str(e)}")
                    self.socket.close()
                    return
            
            self.connected = True
            self.connect_button.config(text="已連接", state="disabled")
            self.disconnect_button.config(state="normal")
            self.host_entry.config(state="disabled")
            self.port_entry.config(state="disabled")
            self.key_entry.config(state="disabled")
            self.nickname_entry.config(state="disabled")  # 鎖定暱稱輸入
            self.message_entry.config(state="normal")
            
            # 啟動接收執行緒
            threading.Thread(target=self.receive_messages, daemon=True).start()
            
            # 清空聊天區域並顯示加入訊息
            self.clear_chat_area()
            self.append_chat_message("已加入伺服器")
            
        except Exception as e:
            messagebox.showerror("錯誤", f"連接失敗: {str(e)}")
            if hasattr(self, 'socket') and self.socket:
                self.socket.close()

    def disconnect(self):
        """中斷與伺服器的連線"""
        if not self.connected:
            return
        
        try:
            self.send_disconnect_notice()
            self.connected = False
            if self.socket:
                self.socket.close()
            
            self.connect_button.config(text="連接", state="normal")
            self.disconnect_button.config(state="disabled")
            self.host_entry.config(state="normal")
            self.port_entry.config(state="normal")
            self.key_entry.config(state="normal")
            self.nickname_entry.config(state="normal")  # 恢復暱稱輸入
            self.message_entry.config(state="disabled")
            self.send_button.config(state="disabled")
            
            # 清空聊天區域
            self.clear_chat_area()
            
        except Exception as e:
            messagebox.showerror("錯誤", f"中斷連線時發生錯誤: {str(e)}")

    def clear_chat_area(self):
        """清空聊天區域"""
        self.chat_area.config(state='normal')
        self.chat_area.delete(1.0, tk.END)
        self.chat_area.config(state='disabled')

    def log(self, message):
        """輸出日誌訊息"""
        if self.message_callback:
            self.message_callback(message)
            
    def append_chat_message(self, message):
        """添加訊息到聊天區域"""
        self.chat_area.config(state='normal')
        if message.startswith("系統:") or message.startswith("[系統]"):
            formatted_msg = f"[系統]: {message.split(':', 1)[1].strip()}"
        elif message.startswith("我:"):
            # 使用暱稱取代"我"
            formatted_msg = f"[{self.nickname_var.get()}]: {message.split(':', 1)[1].strip()}"
        else:
            formatted_msg = message  # 保持原始格式，因為其他用戶訊息已包含暱稱
        
        self.chat_area.insert(tk.END, formatted_msg + "\n")
        self.chat_area.see(tk.END)
        self.chat_area.config(state='disabled')
    
    def send_message(self):
        """發送訊息到伺服器"""
        if not self.connected or not self.message_var.get().strip():
            return
            
        try:
            message = f"{self.nickname_var.get()}: {self.message_var.get().strip()}"
            
            # 加密訊息
            encrypted = self.encrypt_message(message)
            hex_msg = ''.join(f'{b:02X}' for b in encrypted)
            
            # 發送加密訊息
            self.socket.send(hex_msg.encode('latin1'))
            
            # 顯示自己發送的訊息，使用"我:"讓 append_chat_message 處理格式
            self.append_chat_message(f"我: {self.message_var.get().strip()}")
            self.message_var.set("")
            
        except Exception as e:
            messagebox.showerror("錯誤", f"發送失敗: {str(e)}")
            self.disconnect()
        finally:
            self.on_message_change()

    def handle_encrypted_message(self, encrypted_hex):
        """處理接收到的加密訊息"""
        try:
            # 解析十六進制字串為位元組
            encrypted_bytes = bytes.fromhex(encrypted_hex)
            # 使用自己的金鑰解密
            decrypted = self.decrypt_message(list(encrypted_bytes))
            # 顯示解密後的訊息
            self.window.after(0, self.append_chat_message, decrypted)
        except UnicodeDecodeError:
            # 如果解密後無法轉換為字串，表示使用不同金鑰加密
            self.window.after(0, self.append_chat_message, "[系統]:其他金鑰加密訊息")
        except Exception as e:
            self.log(f"訊息解密錯誤: {str(e)}")

    def receive_messages(self):
        """接收訊息"""
        while self.connected:
            try:
                data = self.socket.recv(1024)
                if not data:
                    break

                try:
                    # 檢查是否為系統訊息
                    message = data.decode('utf-8')
                    if message.startswith("<<SYSTEM>>"):
                        # 直接顯示系統訊息（移除標記）
                        system_msg = message[10:]
                        self.window.after(0, self.append_chat_message, f"系統: {system_msg}")
                        continue

                    # 處理加密訊息
                    hex_str = data.decode('latin1').strip()
                    self.handle_encrypted_message(hex_str)

                except UnicodeDecodeError:
                    # 如果無法解碼為UTF-8，則視為加密訊息
                    hex_str = data.decode('latin1').strip()
                    self.handle_encrypted_message(hex_str)
                except Exception as e:
                    self.log(f"訊息處理錯誤: {str(e)}")
                    continue

            except socket.error:
                if self.connected:
                    break

        if self.connected:
            self.window.after(0, self.disconnect)

    def run(self):
        self.window.mainloop()

    def set_default_info(self):
        """設定預設的連線資訊"""
        if not self.connected:
            self.host_var.set(self.initial_host or "127.0.0.1")
            self.port_var.set(str(self.initial_port or "12345"))
            self.nickname_var.set("bob")
            if self.initial_key:  # 如果有預設金鑰就設定
                self.key_var.set(self.initial_key)

def main():
    parser = argparse.ArgumentParser(description='AES 加密聊天客戶端')
    parser.add_argument('--console', action='store_true', help='使用命令列介面')
    parser.add_argument('--host', default='127.0.0.1', help='伺服器位址')
    parser.add_argument('--port', type=int, help='伺服器埠號')
    parser.add_argument('--key', help='預設AES金鑰(十六進制)')  # 新增金鑰參數
    args = parser.parse_args()
    
    if args.console:
        client = AESConsoleClient(args.host, args.port)
        client.connect()
    else:
        client = AESChatClient(host=args.host, port=args.port, default_key=args.key)
        client.run()

if __name__ == "__main__":
    main()