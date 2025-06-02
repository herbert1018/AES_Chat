import os
import sys
import socket
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from Aes_work import AES
import json
import time

class AESServerGUI:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("AES 聊天伺服器")
        self.window.geometry("600x400")
        
        # 配置網格權重
        self.window.grid_rowconfigure(1, weight=1)
        self.window.grid_columnconfigure(0, weight=1)
        
        # 控制面板框架
        self.control_frame = ttk.Frame(self.window, padding="5")
        self.control_frame.grid(row=0, column=0, sticky="ew")
        
        # 伺服器狀態標籤
        self.status_label = ttk.Label(self.control_frame, text="伺服器狀態: 已停止")
        self.status_label.pack(side=tk.LEFT, padx=5)
        
        # 啟動/停止按鈕
        self.toggle_button = ttk.Button(self.control_frame, text="啟動伺服器", command=self.toggle_server)
        self.toggle_button.pack(side=tk.LEFT, padx=5)
        
        # Port 輸入
        ttk.Label(self.control_frame, text="Port:").pack(side=tk.LEFT, padx=5)
        self.port_var = tk.StringVar(value="12345")
        self.port_entry = ttk.Entry(self.control_frame, textvariable=self.port_var, width=6)
        self.port_entry.pack(side=tk.LEFT)
        
        # 日誌顯示區域 - 設定為唯讀但可選取
        self.log_area = scrolledtext.ScrolledText(self.window, wrap=tk.WORD, height=20)
        self.log_area.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
        self.log_area.config(state='disabled')  # 設定為唯讀
        
        self.server = None
        self.server_thread = None
        self.is_running = False
        
    def log(self, message):
        """將訊息加入日誌區域"""
        self.log_area.config(state='normal')  # 暫時啟用編輯
        self.log_area.insert(tk.END, message + "\n")
        self.log_area.see(tk.END)
        self.log_area.config(state='disabled')  # 恢復唯讀
        
    def toggle_server(self):
        """切換伺服器狀態"""
        if not self.is_running:
            self.start_server()
        else:
            self.stop_server()
            
    def start_server(self):
        """啟動伺服器"""
        try:
            port = int(self.port_var.get())
            if port < 1 or port > 65535:
                raise ValueError("Port 必須在 1-65535 之間")
                
            # 嘗試啟動伺服器前先檢查 port 是否可用
            test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                test_socket.bind(('127.0.0.1', port))
            except socket.error:
                raise Exception(f"Port {port} 已被使用")
            finally:
                test_socket.close()
            
            self.server = AESServer(port=port, gui_callback=self.log)
            self.server_thread = threading.Thread(target=self.server.start)
            self.server_thread.daemon = True
            self.server_thread.start()
            
            self.is_running = True
            self.toggle_button.config(text="停止伺服器")
            self.status_label.config(text="伺服器狀態: 運行中")
            self.log("伺服器已啟動")
            self.port_entry.config(state="disabled")  # 禁用 port 輸入
            
        except ValueError:
            messagebox.showerror("錯誤", "Port 必須是有效的數字")
            return
        except Exception as e:
            messagebox.showerror("錯誤", f"無法啟動伺服器: {str(e)}")
            
    def stop_server(self):
        """停止伺服器"""
        if self.server:
            self.server.stop()
            self.is_running = False
            self.toggle_button.config(text="啟動伺服器")
            self.status_label.config(text="伺服器狀態: 已停止")
            self.port_entry.config(state="normal")  # 恢復 port 輸入
            self.log("伺服器已停止")
            
    def run(self):
        self.window.mainloop()

class AESServer:
    def __init__(self, host='127.0.0.1', port=12345, gui_callback=None):
        self.host = host
        self.port = port
        self.gui_callback = gui_callback
        
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((host, port))
            self.server_socket.listen(5)
            self.server_socket.settimeout(1)
        except socket.error as e:
            raise Exception(f"無法在 Port {port} 啟動伺服器: {str(e)}")
            
        # 生成 AES 金鑰
        key_bytes = os.urandom(16)
        self.key = list(key_bytes)
        self.aes = AES(self.key)
        self.clients = []
        self.running = True
        
        if self.gui_callback:
            self.log(f"伺服器啟動於 {host}:{port}")
            self.log(f"AES金鑰: {' '.join(f'{b:02X}' for b in self.key)}")

    def log(self, message):
        """輸出日誌訊息，避免重複添加系統標記"""
        if self.gui_callback:
            # 移除已經存在的系統標記
            if message.startswith('[系統]: '):
                message = message[8:]
            self.gui_callback(message)
        print(message)
        
    def encrypt_message(self, message):
        """加密訊息 - 使用 PKCS7 填充"""
        data = list(message.encode('utf-8'))
        padding_length = 16 - (len(data) % 16)
        padded_data = data + [padding_length] * padding_length  # PKCS7 填充
        
        encrypted = []
        for i in range(0, len(padded_data), 16):
            block = padded_data[i:i+16]
            encrypted.extend(self.aes.encrypt_block(block))
        return encrypted
    
    def decrypt_message(self, encrypted_data):
        """解密訊息 - 處理 PKCS7 填充"""
        decrypted = []
        for i in range(0, len(encrypted_data), 16):
            block = encrypted_data[i:i+16]
            decrypted.extend(self.aes.decrypt_block(block))
        
        # 處理 PKCS7 填充
        padding_length = decrypted[-1]
        if 0 < padding_length <= 16:
            # 驗證填充
            if all(x == padding_length for x in decrypted[-padding_length:]):
                decrypted = decrypted[:-padding_length]
        
        return bytes(decrypted).decode('utf-8')
    
    def broadcast(self, message):
        """向所有客戶端廣播加密訊息"""
        try:
            # 發送給所有在線的客戶端
            dead_clients = []
            for client in self.clients:
                try:
                    client.send(message)
                except:
                    dead_clients.append(client)
            
            # 移除斷線的客戶端
            for client in dead_clients:
                if client in self.clients:
                    self.clients.remove(client)
                    
        except Exception as e:
            self.log(f"廣播訊息錯誤: {str(e)}")

    def send_encrypted_message(self, message, exclude_socket=None):
        """發送加密訊息給所有客戶端"""
        try:
            encrypted = self.encrypt_message(message)
            hex_msg = ''.join(f'{b:02X}' for b in encrypted)
            msg_bytes = hex_msg.encode('latin1')
            
            dead_clients = []
            for client in list(self.clients):  # 使用列表複本進行迭代
                if client != exclude_socket:
                    try:
                        client.send(msg_bytes)
                    except:
                        dead_clients.append(client)
            
            # 移除斷線的客戶端
            for client in dead_clients:
                if client in self.clients:
                    try:
                        addr = client.getpeername()
                    except:
                        addr = ('未知', 0)
                    self.remove_disconnected_client(client, addr)
                    
        except Exception as e:
            self.log(f"發送訊息錯誤: {str(e)}")

    def broadcast_encrypted_message(self, encrypted_hex, sender_socket, original_message):
        """轉發加密訊息給其他客戶端"""
        try:
            # 記錄加密訊息到日誌
            self.log(f"收到加密訊息: {encrypted_hex}")
            self.log(f"解密後訊息: {original_message}")
            
            # 轉發給其他客戶端
            dead_clients = []
            for client in self.clients:
                if client != sender_socket:
                    try:
                        client.send(encrypted_hex.encode('latin1'))
                    except:
                        dead_clients.append(client)
            
            # 移除斷線的客戶端
            for client in dead_clients:
                if client in self.clients:
                    self.clients.remove(client)
                    
            self.log(f"已轉發加密訊息給其他客戶端")
            
        except Exception as e:
            self.log(f"轉發訊息錯誤: {str(e)}")

    def remove_disconnected_client(self, client_socket, address):
        """安全地移除斷線的客戶端"""
        try:
            if client_socket in self.clients:
                self.clients.remove(client_socket)
                leave_message = f"使用者 {address[0]}:{address[1]} 離開聊天室"
                self.send_encrypted_message(leave_message)
                self.log(f"客戶端 {address} 已斷開連線")
                try:
                    client_socket.close()
                except:
                    pass
                return True
            return False
        except Exception as e:
            self.log(f"移除客戶端錯誤: {str(e)}")
            return False

    def forward_encrypted_message(self, encrypted_data, sender_socket, address):
        """直接轉發加密訊息給其他客戶端"""
        try:
            # 記錄加密訊息到日誌，不添加系統標記
            self.log(f"收到來自 {address[0]}:{address[1]} 的加密訊息: {encrypted_data.decode('latin1')}")
            
            # 轉發給其他客戶端
            dead_clients = []
            for client in self.clients:
                if client != sender_socket:
                    try:
                        client.send(encrypted_data)
                    except:
                        dead_clients.append(client)
            
            # 移除斷線的客戶端
            for client in dead_clients:
                if client in self.clients:
                    self.clients.remove(client)
                    
        except Exception as e:
            self.log(f"轉發訊息錯誤: {str(e)}")

    def send_system_message(self, message):
        """發送未加密的系統訊息給所有客戶端"""
        try:
            # 移除訊息中可能的系統前綴
            if message.startswith('[系統]: '):
                clean_message = message[8:]
            elif message.startswith('系統: '):
                clean_message = message[4:]
            else:
                clean_message = message

            system_msg = f"<<SYSTEM>>{clean_message}"
            msg_bytes = system_msg.encode('utf-8')
            
            self.log(clean_message)  # 使用清理後的訊息
            
            dead_clients = []
            for client in list(self.clients):
                try:
                    client.send(msg_bytes)
                except:
                    dead_clients.append(client)
            
            # 移除斷線的客戶端
            for client in dead_clients:
                if client in self.clients:
                    self.clients.remove(client)
                    
        except Exception as e:
            self.log(f"發送系統訊息錯誤: {str(e)}")

    def handle_client(self, client_socket, address):
        try:
            # 發送金鑰
            key_hex = ' '.join(f'{b:02X}' for b in self.key)
            client_socket.send(key_hex.encode('ascii'))
            
            # 將新客戶端加入列表並發送加入通知
            self.clients.append(client_socket)
            join_message = f"使用者 {address[0]}:{address[1]} 加入聊天室"
            self.send_system_message(join_message)
            
            self.log(f"客戶端 {address} 已連接")

            while self.running:
                try:
                    data = client_socket.recv(1024)
                    if not data:
                        break
                    
                    # 直接轉發加密訊息
                    self.forward_encrypted_message(data, client_socket, address)

                except (socket.error, ConnectionError) as e:
                    self.log(f"客戶端 {address} 連線中斷: {str(e)}")
                    break
                except Exception as e:
                    self.log(f"訊息處理錯誤: {str(e)}")
                    continue

        finally:
            if client_socket in self.clients:
                self.clients.remove(client_socket)
                # 發送離開通知
                leave_message = f"使用者 {address[0]}:{address[1]} 離開聊天室"
                self.send_system_message(leave_message)
                self.log(f"客戶端 {address} 已斷開連線")
            
            try:
                client_socket.close()
            except:
                pass

    def broadcast_message(self, data, exclude_socket=None):
        """直接轉發加密訊息"""
        try:
            dead_clients = []
            for client in self.clients:
                if client != exclude_socket:
                    try:
                        client.send(data)
                    except:
                        dead_clients.append(client)
            
            # 移除斷線的客戶端
            for client in dead_clients:
                if client in self.clients:
                    self.clients.remove(client)
        except Exception as e:
            self.log(f"廣播訊息錯誤: {str(e)}")

    def stop(self):
        """停止伺服器"""
        self.running = False
        # 關閉所有客戶端連接
        for client in self.clients[:]:
            try:
                client.close()
            except:
                pass
        self.clients.clear()
        # 關閉伺服器socket
        try:
            self.server_socket.close()
        except:
            pass

    def start(self):
        while self.running:
            try:
                client_socket, address = self.server_socket.accept()
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, address)
                )
                client_thread.daemon = True
                client_thread.start()
            except socket.timeout:
                continue
            except Exception as e:
                if self.gui_callback:
                    self.log(f"接受連線錯誤: {e}")
                if not self.running:
                    break

if __name__ == "__main__":
    server_gui = AESServerGUI()
    server_gui.run()