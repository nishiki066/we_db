"""
微信图片解密模块
支持旧版XOR和V4版本(AES+XOR)的图片解密
"""
import struct
from typing import Tuple
from Crypto.Cipher import AES
from pathlib import Path


class ImageDecryptor:
    """微信图片解密器"""

    # 图片格式头定义
    JPG_HEADER = bytes([0xFF, 0xD8, 0xFF])
    PNG_HEADER = bytes([0x89, 0x50, 0x4E, 0x47])
    GIF_HEADER = bytes([0x47, 0x49, 0x46, 0x38])
    WXGF_HEADER = bytes([0x77, 0x78, 0x67, 0x66])

    # V4 格式定义
    V4_FORMAT1_HEADER = bytes([0x07, 0x08, 0x56, 0x31])
    V4_FORMAT2_HEADER = bytes([0x07, 0x08, 0x56, 0x32])
    V4_FORMAT1_AES_KEY = bytes.fromhex("cfcd208495d565ef")

    def __init__(self, aes_key_hex: str = None, xor_key: int = 0x37):
        """
        初始化解密器

        Args:
            aes_key_hex: V4 Format2的AES密钥(hex字符串)
            xor_key: V4的XOR密钥(默认0x37)
        """
        self.v4_format2_aes_key = bytes.fromhex(aes_key_hex) if aes_key_hex else None
        self.xor_key_v4 = xor_key

    def decrypt_file(self, input_path: str, output_dir: str = None) -> str:
        """
        解密单个.dat文件

        Args:
            input_path: 输入.dat文件路径
            output_dir: 输出目录(默认与输入文件同目录)

        Returns:
            解密后的文件路径
        """
        input_path = Path(input_path)

        if not input_path.exists():
            raise FileNotFoundError(f"文件不存在: {input_path}")

        # 读取加密数据
        with open(input_path, 'rb') as f:
            encrypted_data = f.read()

        # 解密
        decrypted_data, ext = self.decrypt_dat(encrypted_data)

        # 确定输出路径
        if output_dir is None:
            output_dir = input_path.parent
        else:
            output_dir = Path(output_dir)
            output_dir.mkdir(parents=True, exist_ok=True)

        output_path = output_dir / f"{input_path.stem}.{ext}"

        # 保存
        with open(output_path, 'wb') as f:
            f.write(decrypted_data)

        return str(output_path)

    def decrypt_dat(self, data: bytes) -> Tuple[bytes, str]:
        """
        解密.dat文件数据

        Args:
            data: 加密的.dat文件数据

        Returns:
            (解密后的数据, 文件扩展名)
        """
        if len(data) < 6:
            raise ValueError(f"数据太短: {len(data)} bytes")

        # 检查V4格式
        if data[:4] == self.V4_FORMAT1_HEADER:
            return self._decrypt_v4(data, self.V4_FORMAT1_AES_KEY)

        if data[:4] == self.V4_FORMAT2_HEADER:
            if self.v4_format2_aes_key is None:
                raise ValueError("需要设置V4 Format2的AES密钥")
            return self._decrypt_v4(data, self.v4_format2_aes_key)

        # 旧版XOR解密
        return self._decrypt_xor(data)

    def _decrypt_v4(self, data: bytes, aes_key: bytes) -> Tuple[bytes, str]:
        """
        V4格式解密 (AES-ECB + XOR)

        文件结构:
        - 0-3:   格式头 (0x07085631 或 0x07085632)
        - 4-5:   未知
        - 6-9:   AES加密长度 (小端序)
        - 10-13: XOR加密长度 (小端序)
        - 14:    0x01
        - 15+:   加密数据
        """
        if len(data) < 15:
            raise ValueError("V4格式数据太短")

        # 解析头部
        aes_len = struct.unpack('<I', data[6:10])[0]
        xor_len = struct.unpack('<I', data[10:14])[0]

        file_data = data[15:]

        # AES部分 (对齐到16字节)
        aes_len_aligned = ((aes_len // 16) + 1) * 16
        if aes_len_aligned > len(file_data):
            aes_len_aligned = len(file_data)

        # 解密AES部分
        aes_encrypted = file_data[:aes_len_aligned]
        aes_decrypted = self._decrypt_aes_ecb(aes_encrypted, aes_key)

        # 组装结果
        result = bytearray()

        # 1. AES解密部分 (去除padding)
        result.extend(aes_decrypted[:aes_len])

        # 2. 中间未加密部分
        middle_start = aes_len_aligned
        middle_end = len(file_data) - xor_len
        if middle_start < middle_end:
            result.extend(file_data[middle_start:middle_end])

        # 3. XOR解密尾部
        if xor_len > 0 and middle_end < len(file_data):
            xor_data = file_data[middle_end:]
            result.extend(bytes([b ^ self.xor_key_v4 for b in xor_data]))

        # 识别图片类型
        ext = self._detect_image_type(bytes(result))

        # WXGF格式需要特殊处理 (暂不支持)
        if ext == 'wxgf':
            raise NotImplementedError("WXGF格式(动画表情)暂不支持,需要HEVC解码")

        return bytes(result), ext

    def _decrypt_xor(self, data: bytes) -> Tuple[bytes, str]:
        """
        旧版XOR解密
        通过已知的图片格式头推导XOR密钥
        """
        formats = [
            (self.JPG_HEADER, 'jpg'),
            (self.PNG_HEADER, 'png'),
            (self.GIF_HEADER, 'gif'),
        ]

        for header, ext in formats:
            # 计算XOR密钥
            xor_key = data[0] ^ header[0]

            # 验证是否匹配
            if all(data[i] ^ xor_key == header[i] for i in range(min(len(header), len(data)))):
                # 解密整个文件
                decrypted = bytes([b ^ xor_key for b in data])
                return decrypted, ext

        raise ValueError("无法识别的图片格式")

    @staticmethod
    def _decrypt_aes_ecb(data: bytes, key: bytes) -> bytes:
        """AES-ECB模式解密"""
        cipher = AES.new(key, AES.MODE_ECB)
        decrypted = cipher.decrypt(data)

        # 移除PKCS7 padding
        padding = decrypted[-1]
        if 0 < padding <= 16:
            # 验证padding是否有效
            if all(decrypted[-i] == padding for i in range(1, padding + 1)):
                return decrypted[:-padding]

        return decrypted

    @staticmethod
    def _detect_image_type(data: bytes) -> str:
        """根据文件头检测图片类型"""
        if data.startswith(bytes([0xFF, 0xD8, 0xFF])):
            return 'jpg'
        elif data.startswith(bytes([0x89, 0x50, 0x4E, 0x47])):
            return 'png'
        elif data.startswith(bytes([0x47, 0x49, 0x46])):
            return 'gif'
        elif data.startswith(bytes([0x42, 0x4D])):
            return 'bmp'
        elif data.startswith(bytes([0x77, 0x78, 0x67, 0x66])):
            return 'wxgf'
        else:
            return 'bin'


# 便捷函数
def decrypt_image(input_path: str, output_dir: str = None,
                  aes_key: str = None, xor_key: int = 0x37) -> str:
    """
    便捷函数: 解密单张图片

    Args:
        input_path: 输入.dat文件路径
        output_dir: 输出目录
        aes_key: AES密钥(hex字符串)
        xor_key: XOR密钥

    Returns:
        解密后的文件路径
    """
    decryptor = ImageDecryptor(aes_key, xor_key)
    return decryptor.decrypt_file(input_path, output_dir)