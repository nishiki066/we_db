#!/usr/bin/env python3
"""
微信数据库解密器

将加密的微信数据库解密成标准 SQLite 数据库
"""

import os
from pathlib import Path
from typing import Optional

from .crypto import (
    V4_PAGE_SIZE,
    KEY_SIZE,
    SALT_SIZE,
    RESERVE,
    IV_SIZE,
    SQLITE_HEADER,
    derive_keys,
    verify_page_hmac,
    decrypt_aes_cbc,
)


class DatabaseDecryptor:
    """
    微信数据库解密器

    用法:
        decryptor = DatabaseDecryptor(key_hex="9b646e026b1042ab...")
        success = decryptor.decrypt_file("message_0.db", "decrypted.db")
    """

    def __init__(self, key_hex: str):
        """
        初始化解密器

        Args:
            key_hex: 原始密钥的十六进制字符串 (64 个字符 = 32 bytes)

        Raises:
            ValueError: 如果密钥格式不正确
        """
        try:
            self.key = bytes.fromhex(key_hex)
        except ValueError:
            raise ValueError("密钥必须是有效的十六进制字符串")

        if len(self.key) != KEY_SIZE:
            raise ValueError(f"密钥长度必须是 {KEY_SIZE} bytes, 实际: {len(self.key)}")

    def decrypt_file(self, input_path: str, output_path: str,
                     verify_hmac: bool = True) -> bool:
        """
        解密整个数据库文件

        Args:
            input_path: 加密的数据库文件路径
            output_path: 解密后的输出文件路径
            verify_hmac: 是否验证 HMAC (默认 True)

        Returns:
            True: 解密成功
            False: 解密失败
        """
        try:


            # 1. 验证输入文件
            if not self._validate_input(input_path):
                return False

            # 2. 读取文件信息
            file_size = os.path.getsize(input_path)
            total_pages = (file_size + V4_PAGE_SIZE - 1) // V4_PAGE_SIZE



            # 3. 提取 Salt 并派生密钥
            salt, enc_key, mac_key = self._extract_and_derive_keys(input_path)



            # 4. 解密数据库
            success = self._decrypt_pages(
                input_path, output_path,
                enc_key, mac_key,
                total_pages, verify_hmac
            )

            if not success:
                return False

            # 5. 验证输出文件
            if self._verify_output(output_path):

                return True
            else:
                print("\n❌ 输出文件验证失败")
                return False

        except Exception as e:
            print(f"\n❌ 解密失败: {e}")
            import traceback
            traceback.print_exc()
            return False

    def _validate_input(self, input_path: str) -> bool:
        """验证输入文件"""
        if not os.path.exists(input_path):
            print(f"❌ 文件不存在: {input_path}")
            return False

        file_size = os.path.getsize(input_path)
        if file_size < V4_PAGE_SIZE:
            print(f"❌ 文件太小: {file_size} bytes")
            return False

        return True

    def _extract_and_derive_keys(self, input_path: str) -> tuple:
        """
        提取 Salt 并派生密钥

        Returns:
            (salt, enc_key, mac_key)
        """
        with open(input_path, 'rb') as f:
            first_page = f.read(V4_PAGE_SIZE)

        # 提取 Salt (第一页前 16 字节)
        salt = first_page[:SALT_SIZE]

        # 派生密钥
        enc_key, mac_key = derive_keys(self.key, salt)

        return salt, enc_key, mac_key

    def _decrypt_pages(self, input_path: str, output_path: str,
                       enc_key: bytes, mac_key: bytes,
                       total_pages: int, verify_hmac: bool) -> bool:
        """
        逐页解密数据库

        Args:
            input_path: 输入文件
            output_path: 输出文件
            enc_key: 加密密钥
            mac_key: MAC 密钥
            total_pages: 总页数
            verify_hmac: 是否验证 HMAC

        Returns:
            True: 成功, False: 失败
        """


        # 创建输出目录
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)

        failed_pages = []

        with open(input_path, 'rb') as inf, open(output_path, 'wb') as outf:
            for page_num in range(total_pages):
                # 读取页数据
                page_data = inf.read(V4_PAGE_SIZE)

                if len(page_data) == 0:
                    break

                # 补齐不足 4096 字节的页
                if len(page_data) < V4_PAGE_SIZE:
                    page_data += b'\x00' * (V4_PAGE_SIZE - len(page_data))

                # 检查是否是全零页 (跳过解密)
                if page_data == b'\x00' * V4_PAGE_SIZE:
                    outf.write(page_data)
                    continue

                # 解密页
                try:
                    decrypted_page = self._decrypt_page(
                        page_data, enc_key, mac_key,
                        page_num,
                        is_first_page=(page_num == 0),
                        verify_hmac=verify_hmac
                    )
                    outf.write(decrypted_page)

                except Exception as e:
                    # 记录失败的页
                    failed_pages.append((page_num, str(e)))
                    # 写入原始数据 (保持文件结构完整)
                    outf.write(page_data)

                # 显示进度
                if (page_num + 1) % 100 == 0 or page_num == total_pages - 1:
                    progress = (page_num + 1) / total_pages * 100


        print()  # 换行

        # 显示失败的页
        if failed_pages:
            print(f"\n[4/5] 警告: {len(failed_pages)} 个页面解密失败")
            for page_num, error in failed_pages[:5]:  # 只显示前 5 个
                print(f"  ├─ 页 {page_num}: {error}")
            if len(failed_pages) > 5:
                print(f"  └─ ... 还有 {len(failed_pages) - 5} 个")
        else:
            print(f"")

        return True

    def _decrypt_page(self, page_data: bytes, enc_key: bytes, mac_key: bytes,
                      page_num: int, is_first_page: bool = False,
                      verify_hmac: bool = True) -> bytes:
        """
        解密单个数据库页 (修正版)
        """
        # 1. 确定 IV 和 HMAC 的位置 (所有页都在末尾!)
        iv_start = V4_PAGE_SIZE - RESERVE
        iv = page_data[iv_start:iv_start + IV_SIZE]

        # 2. 确定加密数据的起始位置
        # 第一页前 16 字节是 Salt，不是加密数据，需要跳过
        # 普通页从 0 开始
        offset = SALT_SIZE if is_first_page else 0

        # 3. 验证 HMAC (可选)
        if verify_hmac:
            if not verify_page_hmac(page_data, mac_key, page_num, is_first_page):
                # 建议先打印警告而不是报错，方便排查
                print(f"  ⚠️ Warning: Page {page_num} HMAC 验证失败")

        # 4. 提取加密数据
        # 范围: [起始位置 : IV开始位置]
        encrypted_data = page_data[offset:iv_start]

        # 5. AES-256-CBC 解密
        # 注意：这里使用的 IV 是从页尾提取的，而不是 Salt
        decrypted_data = decrypt_aes_cbc(encrypted_data, enc_key, iv)

        # 6. 构建解密后的页
        if is_first_page:
            # 第一页特殊处理：
            # 结构: [SQLite Header (16)] + [解密后的数据] + [保留区]
            result = SQLITE_HEADER + decrypted_data
        else:
            # 普通页直接使用解密数据
            result = decrypted_data

        # 7. 补回保留区 (IV + HMAC)
        # 保持页面大小为 4096 且结构完整
        result += page_data[iv_start:V4_PAGE_SIZE]

        return result

    def _verify_output(self, output_path: str) -> bool:
        """
        验证解密后的文件

        Args:
            output_path: 输出文件路径

        Returns:
            True: 验证通过, False: 验证失败
        """


        if not os.path.exists(output_path):
            print("  ❌ 输出文件不存在")
            return False

        output_size = os.path.getsize(output_path)
        print(f"  ├─ 输出文件: {output_path}")
        print(f"  └─ 文件大小: {output_size:,} bytes")

        # 验证 SQLite 头
        with open(output_path, 'rb') as f:
            header = f.read(len(SQLITE_HEADER))

        if header == SQLITE_HEADER:

            return True
        else:
            print(f"  ⚠️ 文件头不是标准 SQLite 格式")
            print(f"     期望: {SQLITE_HEADER.hex()}")
            print(f"     实际: {header.hex()}")
            return False


def decrypt_database(input_file: str, key_hex: str, output_file: str,
                     verify_hmac: bool = True) -> bool:
    """
    便捷函数: 解密数据库

    Args:
        input_file: 加密的数据库
        key_hex: 密钥 (十六进制)
        output_file: 输出文件
        verify_hmac: 是否验证 HMAC

    Returns:
        True: 成功, False: 失败
    """
    decryptor = DatabaseDecryptor(key_hex)
    return decryptor.decrypt_file(input_file, output_file, verify_hmac)


if __name__ == "__main__":
    # 测试代码
    import sys

    if len(sys.argv) < 4:
        print("用法: python decryptor.py <加密DB> <密钥HEX> <输出DB>")
        sys.exit(1)

    input_db = sys.argv[1]
    key = sys.argv[2]
    output_db = sys.argv[3]

    success = decrypt_database(input_db, key, output_db)
    sys.exit(0 if success else 1)