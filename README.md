# AES 加密工具與聊天系統

這是一個基於 Python 實現的 AES 加密工具和加密聊天系統，包含圖形化界面。

## 功能特色

### AES 加解密工具
- 支援 128/192/256 位元金鑰
- 支援 Hex 和 String 格式輸入/輸出
- 提供加解密過程可視化
- 支援 PKCS7 填充
- 可隨機生成金鑰

### 加密聊天系統
- 基於 AES 加密的安全通訊
- 支援多人聊天
- 圖形化使用者界面
- 即時訊息監控
- 伺服器狀態顯示

## 系統需求

- Python 3.8 或以上版本
- tkinter (Python 內建 GUI 套件)
- pypackage-resources (資源管理套件)

## 安裝步驟

1. 確保已安裝 Python 3.8+
2. 安裝所需套件：
```bash
pip install -r requirements.txt
```

### tkinter 安裝說明
- Windows: Python 安裝時已內建
- Linux (Ubuntu/Debian):
```bash
sudo apt-get install python3-tk
```
- macOS:
```bash
brew install python-tk
```

## 使用說明

### 執行檔啟動流程 (建議方式)

1. 啟動主程式
- 執行 `Chat_GUI.exe` 啟動聊天管理器
- 點擊「啟動伺服器」開始監聽（預設 Port: 12345）

2. 開啟聊天客戶端
- 方法一：點擊聊天管理器中的「開啟客戶端」按鈕（推薦）
- 方法二：直接執行 `aes_client.exe`
- 可開啟多個客戶端進行群聊
- 自動繼承伺服器設定（IP/Port/金鑰）

3. 加解密工具
- 方法一：點擊聊天管理器中的「加解密工具」按鈕
- 方法二：直接執行 `Aes_gui.exe`
- 支援獨立運作，可用於離線加解密

*備註：目前聊天功能只支援128bits金鑰
### 開發測試用啟動方式 (開發測試)
```bash
python Chat_GUI.py     # 啟動聊天管理器
python aes_client.py   # 啟動聊天客戶端
python Aes_gui.py      # 啟動加解密工具
```

## 檔案說明

- `Chat_GUI.py`: 聊天系統管理器
- `Aes_gui.py`: AES 加解密工具
- `aes_server.py`: 聊天伺服器實作
- `aes_client.py`: 聊天客戶端實作
- `Aes_work.py`: AES 加密演算法實作
- `aes_visualizer.py`: 加解密過程視覺化工具

## 注意事項

- 預設通訊埠為 12345
- 請確保防火牆不會阻擋程式運作
- 建議在本地網路環境使用

## 作者

herbert, 11103021A

