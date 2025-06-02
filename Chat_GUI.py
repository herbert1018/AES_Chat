import os
import sys
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
from aes_server import AESServer
from aes_client import AESChatClient
import subprocess

# 取得目前腳本所在的目錄
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

def get_resource_path(relative_path):
    if getattr(sys, 'frozen', False):
        base_path = os.path.dirname(sys.executable)
    else:
        base_path = SCRIPT_DIR
    return os.path.join(base_path, relative_path)

class ChatManagerGUI:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("AES 加密聊天管理器")
        self.window.geometry("800x600")
        
        # 配置網格權重
        self.window.grid_rowconfigure(1, weight=1)
        self.window.grid_columnconfigure(0, weight=1)
        
        # 控制區域
        self.control_frame = ttk.LabelFrame(self.window, text="控制面板", padding="10")
        self.control_frame.grid(row=0, column=0, sticky="ew", padx=5, pady=5)
        
        # 伺服器控制
        self.server_frame = ttk.Frame(self.control_frame)
        self.server_frame.pack(side=tk.LEFT, padx=10)
        
        ttk.Label(self.server_frame, text="Port:").pack(side=tk.LEFT)
        self.port_var = tk.StringVar(value="12345")
        self.port_entry = ttk.Entry(self.server_frame, textvariable=self.port_var, width=6)
        self.port_entry.pack(side=tk.LEFT, padx=5)
        
        self.server_button = ttk.Button(self.server_frame, text="啟動伺服器", 
                                      command=self.toggle_server)
        self.server_button.pack(side=tk.LEFT)
        
        self.server_status = ttk.Label(self.server_frame, text="伺服器狀態: 停止")
        self.server_status.pack(side=tk.LEFT, padx=5)
        
        # 客戶端控制
        self.client_frame = ttk.Frame(self.control_frame)
        self.client_frame.pack(side=tk.LEFT, padx=10)
        
        self.client_button = ttk.Button(self.client_frame, text="開啟客戶端", 
                                      command=self.open_client)
        self.client_button.pack(side=tk.LEFT)
        
        # 訊息監控區域
        self.log_frame = ttk.LabelFrame(self.window, text="訊息監控", padding="10")
        self.log_frame.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
        
        # 設定唯讀但可選取的訊息監控區域
        self.log_area = scrolledtext.ScrolledText(self.log_frame, wrap=tk.WORD)
        self.log_area.pack(fill=tk.BOTH, expand=True)
        self.log_area.config(state='disabled')  # 設定為唯讀
        
        # 新增金鑰顯示區域
        self.key_frame = ttk.LabelFrame(self.window, text="AES 金鑰", padding="10")
        self.key_frame.grid(row=2, column=0, sticky="ew", padx=5, pady=5)
        
        # 將標籤改為可選取的唯讀文字框
        self.key_var = tk.StringVar()
        self.key_entry = ttk.Entry(self.key_frame, textvariable=self.key_var, 
                                 font=('Courier', 10), state='readonly',
                                 width=50)
        self.key_entry.pack(fill=tk.X)
        
        # 初始化變數
        self.server = None
        self.server_running = False
        self.clients = []
        
        # 綁定關閉事件
        self.window.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        # 在控制面板添加清空按鈕
        self.clear_button = ttk.Button(self.control_frame, text="清空訊息",
                                     command=self.clear_log)
        self.clear_button.pack(side=tk.LEFT, padx=10)
        
        # 添加加解密工具按鈕
        self.tool_button = ttk.Button(self.control_frame, text="加解密工具",
                                    command=self.open_aes_tool)
        self.tool_button.pack(side=tk.LEFT, padx=10)
        
        # 在初始化時新增標籤樣式
        self.log_area.tag_configure("green", foreground="green")
        self.log_area.tag_configure("red", foreground="red")
        
    def log_message(self, message):
        """記錄訊息到監控區域，支援顏色標記"""
        self.log_area.config(state='normal')
        # 準備顯示訊息，統一格式
        display_msg = f"[系統]: {message}\n"
        
        # 根據訊息類型使用不同顏色
        if "伺服器已啟動" in message or "伺服器已在 Port" in message or "AES金鑰" in message:
            self.log_area.insert(tk.END, display_msg, "green")
        elif "伺服器已停止" in message or "錯誤" in message:
            self.log_area.insert(tk.END, display_msg, "red")
        elif "伺服器啟動於" in message:
            self.log_area.insert(tk.END, f"\n{display_msg}", "green")
        else:
            self.log_area.insert(tk.END, display_msg)
            
        self.log_area.see(tk.END)
        self.log_area.config(state='disabled')

    def clear_log(self):
        """清空訊息監控區域"""
        self.log_area.config(state='normal')
        self.log_area.delete(1.0, tk.END)
        self.log_area.config(state='disabled')
        
    def toggle_server(self):
        """切換伺服器狀態"""
        if not self.server_running:
            try:
                # 檢查是否有輸入 port
                if not self.port_var.get().strip():
                    messagebox.showerror("錯誤", "請輸入 Port")
                    return
                try:
                    # 驗證 port
                    port = int(self.port_var.get())
                    if port < 1 or port > 65535:
                        raise ValueError("Port 必須在 1-65535 之間")
                except ValueError as e:
                    messagebox.showerror("錯誤", str(e))
                    return
                
                self.server = AESServer(port=port, gui_callback=self.log_message)
                self.server_thread = threading.Thread(target=self.server.start)
                self.server_thread.daemon = True
                self.server_thread.start()
                
                self.server_running = True
                self.server_button.config(text="停止伺服器")
                self.server_status.config(text="伺服器狀態: 運行中")
                self.port_entry.config(state="disabled")
                
                # 修改金鑰顯示方式
                key_hex = ' '.join(f'{b:02X}' for b in self.server.key)
                self.key_var.set(f"{key_hex}")
                self.key_entry.config(state='readonly')  # 確保是唯讀狀態
                self.log_message(f"伺服器已在 Port {port} 啟動")
                
            except Exception as e:
                self.log_message(f"啟動伺服器失敗: {str(e)}")
                messagebox.showerror("錯誤", f"無法啟動伺服器: {str(e)}")
        else:
            try:
                if self.server:
                    self.server.stop()
                self.server_running = False
                self.server_button.config(text="啟動伺服器")
                self.server_status.config(text="伺服器狀態: 停止")
                self.port_entry.config(state="normal")
                self.key_var.set("")  # 清除金鑰顯示
                self.key_entry.config(state='readonly')  # 保持唯讀狀態
                self.log_message("伺服器已停止")  # 加入換行
            except Exception as e:
                self.log_message(f"停止伺服器失敗: {str(e)}")  # 加入換行

    def open_client(self):
        """開啟新的客戶端程序"""
        try:
            current_port = self.port_var.get().strip()
            port = current_port if current_port else "12345"
            
            key_arg = []
            if self.server_running and self.server:
                key = ''.join(f'{b:02X}' for b in self.server.key)
                key_arg = ["--key", key]
            
            if getattr(sys, 'frozen', False):
                # 如果是打包後的執行檔
                client_path = os.path.join(os.path.dirname(sys.executable), 'aes_client.exe')
                if os.path.exists(client_path):
                    os.startfile(client_path)
                else:
                    messagebox.showerror("錯誤", "找不到客戶端程式")
            else:
                # 開發環境：使用原本的 Python 執行方式
                client_path = get_resource_path("aes_client.py")
                subprocess.Popen([
                    sys.executable,
                    client_path,
                    "--host", "127.0.0.1",
                    "--port", port
                ] + key_arg)
            
        except Exception as e:
            messagebox.showerror("錯誤", f"無法開啟客戶端: {str(e)}")
            
    def open_aes_tool(self):
        """開啟 AES 加解密工具"""
        try:
            if getattr(sys, 'frozen', False):
                # 如果是打包後的執行檔
                crypto_path = os.path.join(os.path.dirname(sys.executable), 'Aes_gui.exe')
                if os.path.exists(crypto_path):
                    os.startfile(crypto_path)
                else:
                    messagebox.showerror("錯誤", "找不到加解密工具程式")
            else:
                # 開發環境：使用原本的 Python 執行方式
                tool_path = get_resource_path("Aes_gui.py")
                subprocess.Popen([
                    sys.executable,
                    tool_path,
                    "--path", SCRIPT_DIR
                ])
        except Exception as e:
            messagebox.showerror("錯誤", f"無法開啟加解密工具: {str(e)}")

    def on_closing(self):
        """關閉程式時的處理"""
        if self.server_running:
            self.toggle_server()
        self.window.destroy()
        
    def run(self):
        self.window.mainloop()

if __name__ == "__main__":
    manager = ChatManagerGUI()
    manager.run()