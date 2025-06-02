import tkinter as tk

class AesVisualizer:
    def __init__(self, canvas):
        self.process_canvas = canvas
        self.current_round_states = {}
        self.current_step = 0
        self.process_list = []
        self.is_auto_playing = False
        self.auto_play_id = None
        self.steps_data = {}  # 儲存每個回合的步驟數據
        self.current_round_data = {}  # 新增：儲存當前回合的所有步驟數據
        self.current_round = ""    # 當前回合標識符

        # 加解密步驟定義
        self.encrypt_steps = ["SubBytes", "ShiftRows", "MixColumns", "AddRoundKey"]
        self.encrypt_final = ["SubBytes", "ShiftRows", "AddRoundKey"]
        self.decrypt_steps = ["InvShiftRows", "InvSubBytes", "(inv)AddRoundKey", "InvMixColumns"]
        self.decrypt_final = ["InvShiftRows", "InvSubBytes", "(inv)AddRoundKey"]  # 新增：解密最後一輪步驟

        self.step_descriptions = {
            "SubBytes": "字節替換",
            "ShiftRows": "行位移",
            "MixColumns": "列混合",
            "AddRoundKey": "輪密鑰加",
            "InvSubBytes": "逆字節替換",
            "InvShiftRows": "逆行位移",
            "InvMixColumns": "逆列混合",
            "(inv)AddRoundKey": "輪密鑰加"  # 新增解密用的 AddRoundKey 描述
        }
        
    def update_process_visualization(self, step_info, data):
        """更新視覺化顯示"""
        self.process_canvas.delete("all")
        
        # 確保 step_info 是列表格式
        if isinstance(step_info, (list, tuple)):
            if len(step_info) > 2:  # round相關步驟
                step = step_info  # 保持完整的步驟信息
            else:
                step = step_info[0]
                data = step_info[1] if len(step_info) > 1 else data
        else:
            step = step_info  # 字符串格式
        
        # 根據步驟類型預估所需高度
        required_height = 150
        if isinstance(step, list) and len(step) > 2 and "Round" in step[1]:
            required_height = 160
        elif isinstance(data, str):
            lines = (len(data) + 47) // 48
            required_height = max(60 + lines * 20 + 20, 150)
        
        # 更新畫布大小
        current_height = int(self.process_canvas.cget("height"))
        if required_height > current_height:
            self.process_canvas.configure(height=required_height)
        
        # 處理回合相關步驟
        if isinstance(step, list) and len(step) > 2 and "Round" in step[1]:
            self.draw_round_step(step, data)
            return
        
        # 一般步驟的顯示邏輯
        if isinstance(step, str):
            parts = step.split(" - ")
        else:
            parts = [str(s) for s in step]
        
        # 確保畫布大小足夠，但不要過大
        required_height = 150  # 調整基本高度
        
        # 根據步驟類型預估所需高度
        if len(parts) > 2 and "Round" in parts[2]:
            required_height = 160  # 誤調整 Round 步驟所需空間
        elif isinstance(data, str):
            lines = (len(data) + 47) // 48
            required_height = max(60 + lines * 20 + 20, 150)  # 確保最小高度
        
        # 更新畫布大小
        current_height = int(self.process_canvas.cget("height"))
        if required_height > current_height:
            self.process_canvas.configure(height=required_height)
        
        # 解析步驟標題
        if isinstance(parts, str):
            parts = parts.split(" - ")
        
        # 如果是 round 相關的步驟，特殊處理
        if len(parts) > 2 and "Round" in parts[2]:
            self.draw_round_step(parts, data)
            return
        
        # 一般步驟的顯示邏輯
        y = 10
        for i, part in enumerate(parts):
            self.process_canvas.create_text(10, y + i*20, 
                                         text=part, 
                                         anchor="w",
                                         font=("Arial", 10, "bold"))
            
        x = 10
        y = 60 + len(parts)*20
        
        # 繪製資料
        if isinstance(data, str):
            # 將最終結果分行顯示
            chunks = [data[i:i+48] for i in range(0, len(data), 48)]
            for i, chunk in enumerate(chunks):
                self.process_canvas.create_text(x, y + i*20,
                                             text=chunk,
                                             anchor="w",
                                             font=("Courier", 10))
        else:
            self.draw_matrix(x, y, data)

    def draw_round_step(self, title, data):
        """繪製單個回合的加密/解密步驟"""
        try:
            # 新的標題解析邏輯
            if isinstance(title, list):
                # 檢查標題格式
                if len(title) >= 3 and "Round" in title[1]:
                    block_str = title[0]
                    round_str = title[1]
                    step_type = title[2] if len(title) > 2 else ""
                    
                    # 提取區塊號碼
                    block_num = block_str.replace("區塊 ", "").strip()
                    # 提取回合資訊
                    round_num = round_str.strip()
                    # 提取步驟類型
                    step_type = step_type.strip()
                else:
                    return
            else:
                return

            # 根據步驟類型判斷是加密還是解密過程，並修正 AddRoundKey 的判斷
            is_decryption = any(step.startswith("Inv") for step in step_type.split()) or step_type == "(inv)AddRoundKey"
            
            # 修改：保持當前步驟的加解密狀態，特別處理 AddRoundKey
            if is_decryption and step_type == "AddRoundKey":
                current_step_type = "(inv)AddRoundKey"
            else:
                current_step_type = step_type
            
            # 修改：根據加解密設定步驟順序
            if is_decryption:
                steps = self.decrypt_steps.copy()
                if "Final" in round_num:
                    steps = self.decrypt_final.copy()
            else:
                steps = self.encrypt_steps.copy()
                if "Final" in round_num:
                    steps = self.encrypt_final.copy()

            # 繪圖參數設定
            x_start = 40  # 左側邊距
            y_start = 85  # 增加頂部邊距，讓標題與內容有更多空間
            matrix_width = 120
            matrix_height = 64
            arrow_length = 60  # 增加箭頭長度
            block_padding = 15  # 區塊內部padding
            header_height = 45  # 標題區域高度
            
            # 計算總寬度確保置中
            total_blocks = len(steps)
            total_width = (total_blocks * matrix_width) + ((total_blocks - 1) * arrow_length)
            canvas_width = int(self.process_canvas.cget("width"))
            x_start = max(40, (canvas_width - total_width) // 2)

            # 調整標題位置
            title_y = 25
            if "Final" in round_num:
                round_title = f"Block {block_num} - Final Round"
            else:
                round_number = round_num.replace("Round ", "")
                round_title = f"Block {block_num} - Round {round_number}"
                if is_decryption:
                    round_title += " (解密)"
                else:
                    round_title += " (加密)"
            
            # 繪製標題
            self.process_canvas.create_text(10, title_y,
                                         text=round_title,
                                         anchor="w",
                                         font=("Arial", 12, "bold"))

            # 更新當前 round 的狀態
            current_round = f"{block_num}_{round_num}"

            # 檢查是否進入新的回合
            if step_type:
                if current_round not in self.steps_data:
                    # 進入新回合時，清空所有舊數據
                    self.steps_data = {}  # 清空所有回合的數據
                    self.current_round_data = {}  # 清空當前回合數據
                    self.steps_data[current_round] = {}  # 初始化新回合

            # 儲存步驟數據
            if step_type:
                # 儲存當前步驟的數據
                save_step_type = "(inv)AddRoundKey" if step_type == "AddRoundKey" and is_decryption else step_type
                self.current_round_data[save_step_type] = data.copy() if isinstance(data, list) else data
                self.steps_data[current_round] = self.current_round_data.copy()

                # 特別處理 Round 0，只保存當前步驟
                if "Round 0" in round_num:
                    self.steps_data[current_round] = {save_step_type: data.copy() if isinstance(data, list) else data}

            # 繪製所有步驟 - 移除 step_order 的條件邏輯
            for i, step in enumerate(steps):
                x = x_start + i * (matrix_width + arrow_length)

                # 繪製背景 - 修改判斷條件
                if step == current_step_type:
                    self.process_canvas.create_rectangle(
                        x - block_padding,
                        y_start - header_height,
                        x + matrix_width + block_padding,
                        y_start + matrix_height + block_padding,
                        outline="",
                        fill="#e6f3ff",
                        tags="background"
                    )

                # 繪製步驟標題和說明
                self.process_canvas.create_text(
                    x + matrix_width/2, 
                    y_start - 35,  # 調整標題位置
                    text=step,
                    anchor="center",
                    font=("Arial", 10, "bold")
                )
                
                self.process_canvas.create_text(
                    x + matrix_width/2, 
                    y_start - 20,  # 調整說明文字位置
                    text=self.step_descriptions.get(step, ""),
                    anchor="center",
                    font=("Arial", 9)
                )

                # 取得並繪製矩陣數據
                matrix_data = None
                if step == current_step_type:
                    matrix_data = data
                elif current_round in self.steps_data:
                    matrix_data = self.steps_data[current_round].get(step)

                # 繪製矩陣
                if matrix_data is not None:
                    self.draw_matrix(x + block_padding//2, y_start, matrix_data)

                # 調整箭頭位置，確保不會碰到下一個區塊
                if i < len(steps) - 1:
                    arrow_x = x + matrix_width + block_padding
                    arrow_y = y_start + matrix_height//2
                    arrow_actual_length = arrow_length - (2 * block_padding)  # 縮短箭頭長度
                    self.draw_arrow(arrow_x, arrow_y, arrow_actual_length)

            # 如果是回合的最後一個步驟，保存整個回合的狀態
            if step_type == steps[-1]:
                self.current_round_data = {}

        except Exception as e:
            print(f"視覺化處理錯誤: {str(e)}")  # 保留錯誤訊息
            raise
    
    def draw_matrix_placeholder(self, x, y):
        """繪製矩陣佔位框"""
        size = 30 * 4
        self.process_canvas.create_rectangle(x, y, x+size, y+size,
                                          outline="gray",
                                          dash=(2, 2))
        self.process_canvas.create_text(x + size//2, y + size//2,
                                      text="待處理",
                                      font=("Arial", 8),
                                      fill="gray")

    def draw_arrow(self, x, y, length):
        """繪製箭頭"""
        arrow_head_length = 10  # 箭頭頭部長度
        # 繪製箭頭主體，稍微縮短以避免碰到區塊
        self.process_canvas.create_line(
            x, y, 
            x + length - arrow_head_length, y,
            width=2
        )
        # 繪製箭頭頭部
        self.process_canvas.create_polygon(
            x + length - arrow_head_length, y - 5,
            x + length, y,
            x + length - arrow_head_length, y + 5,
            fill="black"
        )

    def draw_matrix(self, x, y, data):
        """繪製4x4矩陣"""
        cell_width = 30
        cell_height = 16
        cell_padding = 2  # 單元格間距
        
        if isinstance(data, list) and len(data) == 16:
            for i in range(4):
                for j in range(4):
                    value = data[i*4 + j]
                    self.process_canvas.create_text(
                        x + j*(cell_width + cell_padding), 
                        y + i*(cell_height + cell_padding),
                        text=value,
                        anchor="w",
                        font=("Courier", 10)
                    )
        else:
            for i, val in enumerate(data):
                self.process_canvas.create_text(x + (i % 4)*30, y + (i // 4)*16,  # 減少行高
                                             text=val,
                                             anchor="w",
                                             font=("Courier", 10))
        self.process_canvas.update()

    def animate_process(self, process_list, window, animation_speed):
        """動畫方式顯示整個過程"""
        self.process_list = process_list
        self.window = window
        self.animation_speed = animation_speed
        self.current_step = 0
        self.is_auto_playing = False  # 改為 False，一開始不自動播放
        self.show_current_step()
        
    def show_current_step(self):
        """顯示當前步驟"""
        if 0 <= self.current_step < len(self.process_list):
            step_info = self.process_list[self.current_step]
            if isinstance(step_info, (list, tuple)):
                if len(step_info) == 2:
                    step, data = step_info
                else:
                    step, data = step_info[:-1], step_info[-1]
            else:
                step, data = step_info, None
            
            self.update_process_visualization(step, data)
            if self.is_auto_playing:
                self.auto_play_id = self.window.after(self.animation_speed, self.next_step)
                
    def next_step(self):
        """顯示下一步"""
        if self.current_step < len(self.process_list) - 1:
            if self.auto_play_id:
                self.window.after_cancel(self.auto_play_id)
                self.auto_play_id = None
            self.current_step += 1
            self.show_current_step()
            
    def auto_play(self):
        """自動播放"""
        self.is_auto_playing = True
        self.show_current_step()
        
    def pause(self):
        """暫停自動播放"""
        self.is_auto_playing = False
        if self.auto_play_id:
            self.window.after_cancel(self.auto_play_id)
            self.auto_play_id = None
