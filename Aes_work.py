import numpy as np

class AES:
    # 輪常數
    rcon = [
        0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
    ]

    @staticmethod
    def generate_sbox():
        """生成 AES S-box"""
        # 初始化 S-box
        sbox = []
        # GF(2^8) 乘法逆元表，0 映射到自己
        inverse = [0] * 256
        
        # 生成 GF(2^8) 乘法逆元
        for i in range(1, 256):
            for j in range(256):
                # GF(2^8) 乘法
                product = 0
                a, b = i, j
                for _ in range(8):
                    if b & 1:
                        product ^= a
                    hi_bit = a & 0x80
                    a <<= 1
                    if hi_bit:
                        a ^= 0x1B  # AES 不可約多項式: x^8 + x^4 + x^3 + x + 1
                    b >>= 1
                if product == 1:
                    inverse[i] = j
                    break
        
        # 對每個字節進行仿射變換
        for i in range(256):
            # 取得乘法逆元
            b = inverse[i]
            
            # 仿射變換矩陣乘法和向量加法
            # y = M * x + c，其中：
            # M = [1 0 0 0 1 1 1 1]
            #     [1 1 0 0 0 1 1 1]
            #     [1 1 1 0 0 0 1 1]
            #     [1 1 1 1 0 0 0 1]
            #     [1 1 1 1 1 0 0 0]
            #     [0 1 1 1 1 1 0 0]
            #     [0 0 1 1 1 1 1 0]
            #     [0 0 0 1 1 1 1 1]
            # c = [0 1 1 0 0 0 1 1] = 0x63
            b_new = 0
            for j in range(8):
                b_bit = (b >> j) & 1
                b_bit_4 = (b >> ((j + 4) % 8)) & 1
                b_bit_5 = (b >> ((j + 5) % 8)) & 1
                b_bit_6 = (b >> ((j + 6) % 8)) & 1
                b_bit_7 = (b >> ((j + 7) % 8)) & 1
                new_bit = b_bit ^ b_bit_4 ^ b_bit_5 ^ b_bit_6 ^ b_bit_7 ^ ((0x63 >> j) & 1)
                b_new |= new_bit << j
            
            sbox.append(b_new)
        
        return sbox
    
    def __init__(self, key):
        # 生成標準 AES S-box
        self.sbox = [
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
            0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
            0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
            0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
            0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
            0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
            0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
            0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
            0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
            0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
            0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
            0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
            0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
        ]
        
        self.key_size = len(key)
        if self.key_size not in [16, 24, 32]:
            raise ValueError("金鑰長度必須是 128、192 或 256 位元")
        self.rounds = {16: 10, 24: 12, 32: 14}[self.key_size]
        self.round_keys = self.key_expansion(key)

    def sub_bytes(self, state):
        """使用 S-box 替換每個位元組"""
        # 對每個位元組使用 S-box 進行替換
        result = [[0 for _ in range(4)] for _ in range(4)]
        for i in range(4):
            for j in range(4):
                # 確保索引值在正確範圍內
                index = state[i][j] & 0xFF  # 確保是 0-255 之間
                result[i][j] = self.sbox[index]
        return result

    def shift_rows(self, state):
        return [
            state[0],
            state[1][1:] + state[1][:1],
            state[2][2:] + state[2][:2],
            state[3][3:] + state[3][:3]
        ]

    def mix_columns(self, state):
        def mul_by_2(x):
            if x & 0x80:
                return ((x << 1) ^ 0x1B) & 0xFF
            return x << 1

        def mul_by_3(x):
            return mul_by_2(x) ^ x

        result = [[0 for _ in range(4)] for _ in range(4)]
        for j in range(4):  # 對每一列
            result[0][j] = mul_by_2(state[0][j]) ^ mul_by_3(state[1][j]) ^ state[2][j] ^ state[3][j]
            result[1][j] = state[0][j] ^ mul_by_2(state[1][j]) ^ mul_by_3(state[2][j]) ^ state[3][j]
            result[2][j] = state[0][j] ^ state[1][j] ^ mul_by_2(state[2][j]) ^ mul_by_3(state[3][j])
            result[3][j] = mul_by_3(state[0][j]) ^ state[1][j] ^ state[2][j] ^ mul_by_2(state[3][j])
        return result

    def add_round_key(self, state, round_key):
        return [[state[i][j] ^ round_key[i][j] for j in range(4)] for i in range(4)]

    def key_expansion(self, key):
        # 將金鑰擴展為所需的輪密鑰
        Nk = self.key_size // 4  # 金鑰字數
        key_bytes = list(key)
        key_schedule = [key_bytes[i:i+4] for i in range(0, len(key_bytes), 4)]
        
        # 生成額外的輪密鑰
        for i in range(Nk, 4 * (self.rounds + 1)):
            temp = key_schedule[i-1].copy()
            if i % Nk == 0:
                temp = self.rot_word(temp)
                temp = [self.sbox[b] for b in temp]
                temp[0] ^= self.rcon[i // Nk - 1]
            elif Nk > 6 and i % Nk == 4:
                temp = [self.sbox[b] for b in temp]
            
            new_word = [key_schedule[i-Nk][j] ^ temp[j] for j in range(4)]
            key_schedule.append(new_word)
        
        # 將金鑰排程轉換為正確的矩陣格式 [Nr+1][4][4]
        round_keys = []
        for r in range(self.rounds + 1):
            round_key = [[0 for _ in range(4)] for _ in range(4)]
            for i in range(4):
                for j in range(4):
                    round_key[i][j] = key_schedule[r*4 + j][i]
            round_keys.append(round_key)
        
        return round_keys

    def rot_word(self, word):
        return word[1:] + word[:1]

    def encrypt_block(self, plaintext):
        """加密一個區塊"""
        # 初始化狀態矩陣
        state = [[0 for _ in range(4)] for _ in range(4)]
        
        # 將輸入轉換為狀態矩陣
        for i in range(4):
            for j in range(4):
                state[i][j] = plaintext[i + 4*j]
        
        # 初始輪金鑰加法
        state = self.add_round_key(state, self.round_keys[0])
        
        # 主要回合 (Nr-1 輪)
        for round in range(1, self.rounds):
            # SubBytes - 使用 S-box 進行位元組替換
            state = self.sub_bytes(state)
            # ShiftRows - 循環位移矩陣列
            state = self.shift_rows(state)
            # MixColumns - 列混合變換
            state = self.mix_columns(state)
            # AddRoundKey - 與輪金鑰進行 XOR
            state = self.add_round_key(state, self.round_keys[round])
        
        # 最後一輪 (不含 MixColumns)
        state = self.sub_bytes(state)
        state = self.shift_rows(state)
        state = self.add_round_key(state, self.round_keys[self.rounds])
        
        # 將狀態矩陣轉回位元組序列
        result = []
        for j in range(4):
            for i in range(4):
                result.append(state[i][j])
                
        return result

    def inv_sub_bytes(self, state):
        """反向 SubBytes 變換"""
        inv_sbox = [0] * 256
        for i in range(256):
            inv_sbox[self.sbox[i]] = i
        return [[inv_sbox[state[i][j]] for j in range(4)] for i in range(4)]

    def inv_shift_rows(self, state):
        """反向 ShiftRows 變換"""
        return [
            state[0],
            state[1][-1:] + state[1][:-1],
            state[2][-2:] + state[2][:-2],
            state[3][-3:] + state[3][:-3]
        ]

    def inv_mix_columns(self, state):
        """反向 MixColumns 變換"""
        def mul_by_2(x):
            return ((x << 1) ^ 0x1B) & 0xFF if x & 0x80 else (x << 1) & 0xFF

        def mul_by_9(x):
            return mul_by_2(mul_by_2(mul_by_2(x))) ^ x
        
        def mul_by_11(x):
            return mul_by_2(mul_by_2(mul_by_2(x))) ^ mul_by_2(x) ^ x
        
        def mul_by_13(x):
            return mul_by_2(mul_by_2(mul_by_2(x))) ^ mul_by_2(mul_by_2(x)) ^ x
        
        def mul_by_14(x):
            return mul_by_2(mul_by_2(mul_by_2(x))) ^ mul_by_2(mul_by_2(x)) ^ mul_by_2(x)

        result = [[0 for _ in range(4)] for _ in range(4)]
        for j in range(4):  # 對每一列
            result[0][j] = mul_by_14(state[0][j]) ^ mul_by_11(state[1][j]) ^ mul_by_13(state[2][j]) ^ mul_by_9(state[3][j])
            result[1][j] = mul_by_9(state[0][j]) ^ mul_by_14(state[1][j]) ^ mul_by_11(state[2][j]) ^ mul_by_13(state[3][j])
            result[2][j] = mul_by_13(state[0][j]) ^ mul_by_9(state[1][j]) ^ mul_by_14(state[2][j]) ^ mul_by_11(state[3][j])
            result[3][j] = mul_by_11(state[0][j]) ^ mul_by_13(state[1][j]) ^ mul_by_9(state[2][j]) ^ mul_by_14(state[3][j])
        return result

    def decrypt_block(self, ciphertext):
        """解密一個區塊"""
        # 使用相同的模式修改解密過程...
        # 強制轉換為整數列表
        block = []
        for x in ciphertext:
            if isinstance(x, (bytes, bytearray)):
                block.extend(list(x))
            else:
                block.append(int(x))
        
        if len(block) != 16:
            raise ValueError("區塊長度必須是16位元組")
        
        # 轉換為狀態矩陣，確保正確的轉換順序
        state = []
        for i in range(4):
            row = []
            for j in range(4):
                row.append(block[i + 4*j])
            state.append(row)
        
        # 初始輪金鑰加法
        state = self.add_round_key(state, self.round_keys[self.rounds])
        
        # 主要回合
        for round in range(self.rounds-1, 0, -1):
            state = self.inv_shift_rows(state)
            state = self.inv_sub_bytes(state)
            state = self.add_round_key(state, self.round_keys[round])
            state = self.inv_mix_columns(state)
        
        # 最終回合
        state = self.inv_shift_rows(state)
        state = self.inv_sub_bytes(state)
        state = self.add_round_key(state, self.round_keys[0])
        
        # 將狀態矩陣轉換回位元組序列
        result = []
        for j in range(4):
            for i in range(4):
                result.append(state[i][j])
        return result

    def get_state_matrix(self, block):
        """將位元組區塊轉換為狀態矩陣"""
        state = [[0 for _ in range(4)] for _ in range(4)]
        for i in range(4):
            for j in range(4):
                state[i][j] = block[i + 4*j]
        return state

    def state_to_bytes(self, state):
        """將狀態矩陣轉換回位元組序列"""
        result = []
        for j in range(4):
            for i in range(4):
                result.append(state[i][j])
        return result
