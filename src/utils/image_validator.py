"""
图片密钥验证器
用于验证从内存中提取的AES密钥是否正确
"""
import os
from pathlib import Path
from typing import Optional
from Crypto.Cipher import AES


class ImageKeyValidator:
    """图片密钥验证器"""

    V4_FORMAT2_HEADER = bytes([0x07, 0x08, 0x56, 0x32])
    JPG_HEADER = bytes([0xFF, 0xD8, 0xFF])
    WXGF_HEADER = bytes([0x77, 0x78, 0x67, 0x66])

    def __init__(self, wechat_dir: str):
        """
        初始化验证器

        Args:
            wechat_dir: 微信数据目录 (会递归扫描)
        """
        self.encrypted_sample: Optional[bytes] = None
        self.sample_file: Optional[str] = None
        self._scan_sample(wechat_dir)

    def _scan_sample(self, wechat_dir: str):
        """扫描目录找一个V4 Format2的.dat文件作为验证样本"""
        wechat_path = Path(wechat_dir)

        if not wechat_path.exists():
            raise ValueError(f"目录不存在: {wechat_dir}")

        # 递归扫描所有.dat文件(排除缩略图)
        for dat_file in wechat_path.rglob('*.dat'):
            # 跳过缩略图
            if dat_file.name.endswith('_t.dat'):
                continue

            try:
                with open(dat_file, 'rb') as f:
                    data = f.read(31)  # 读取头部 + 16字节数据

                # 检查是否为V4 Format2
                if len(data) >= 31 and data[:4] == self.V4_FORMAT2_HEADER:
                    self.encrypted_sample = data[15:31]  # 提取AES加密的前16字节
                    self.sample_file = str(dat_file)
                    print(f"[验证器] 找到样本文件: {dat_file}")
                    return
            except Exception as e:
                continue

        print("[验证器] 未找到V4 Format2格式的图片样本")

    def validate(self, key_hex: str) -> bool:
        """
        验证密钥是否正确

        Args:
            key_hex: AES密钥(hex字符串)

        Returns:
            密钥是否有效
        """
        if self.encrypted_sample is None:
            print("[验证器] 没有样本数据,无法验证")
            return False

        try:
            key_bytes = bytes.fromhex(key_hex)

            if len(key_bytes) < 16:
                return False

            # 取前16字节作为AES密钥
            aes_key = key_bytes[:16]

            # 解密样本
            cipher = AES.new(aes_key, AES.MODE_ECB)
            decrypted = cipher.decrypt(self.encrypted_sample)

            # 检查解密后是否为已知图片格式
            is_valid = (decrypted.startswith(self.JPG_HEADER) or
                        decrypted.startswith(self.WXGF_HEADER))

            if is_valid:
                print(f"[验证器] 密钥验证成功!")
            else:
                print(f"[验证器] 密钥验证失败 (解密后不是有效图片格式)")

            return is_valid

        except Exception as e:
            print(f"[验证器] 验证出错: {e}")
            return False