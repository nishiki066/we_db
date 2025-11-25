#!/usr/bin/env python3
"""
微信数据库加密工具函数

提供 v4 版本的加密/解密相关工具
"""

import hashlib
import hmac
import struct
from Crypto.Cipher import AES

# ==============================================================================
# 常量定义
# ==============================================================================

# 微信 v4 版本常量
V4_PAGE_SIZE = 4096  # SQLite 页大小
V4_ITER_COUNT = 256000  # PBKDF2 迭代次数

# 密钥和哈希大小
KEY_SIZE = 32  # AES-256 密钥长度
SALT_SIZE = 16  # Salt 长度
IV_SIZE = 16  # AES IV 长度
HMAC_SHA512_SIZE = 64  # HMAC-SHA512 输出长度
AES_BLOCK_SIZE = 16  # AES 块大小

# 计算 Reserve 区域大小
# Reserve = IV (16) + HMAC (64) = 80
# 需要对齐到 AES 块大小 (16)
RESERVE = IV_SIZE + HMAC_SHA512_SIZE
if RESERVE % AES_BLOCK_SIZE != 0:
    RESERVE = ((RESERVE // AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE

# SQLite 文件头
SQLITE_HEADER = b"SQLite format 3\x00"


# ==============================================================================
# 基础工具函数
# ==============================================================================

def xor_bytes(data: bytes, value: int) -> bytes:
    """
    对字节数组进行异或操作

    Args:
        data: 输入字节数组
        value: 异或值 (0-255)

    Returns:
        异或后的字节数组
    """
    return bytes(b ^ value for b in data)


# ==============================================================================
# 密钥派生
# ==============================================================================

def derive_keys(key: bytes, salt: bytes) -> tuple:
    """
    派生加密密钥和 MAC 密钥

    微信 v4 使用两级密钥派生:
    1. 原始密钥 + salt → 加密密钥 (PBKDF2, 256000 次迭代)
    2. 加密密钥 + mac_salt → MAC 密钥 (PBKDF2, 2 次迭代)

    Args:
        key: 原始密钥 (32 bytes)
        salt: 数据库 salt (16 bytes, 从第一页提取)

    Returns:
        (enc_key, mac_key) 元组
        - enc_key: 用于 AES-256-CBC 加密
        - mac_key: 用于 HMAC-SHA512 验证

    Raises:
        ValueError: 如果密钥或 salt 长度不正确
    """
    if len(key) != KEY_SIZE:
        raise ValueError(f"密钥长度必须是 {KEY_SIZE} bytes, 实际: {len(key)}")

    if len(salt) != SALT_SIZE:
        raise ValueError(f"Salt 长度必须是 {SALT_SIZE} bytes, 实际: {len(salt)}")

    # 1. 派生加密密钥
    enc_key = hashlib.pbkdf2_hmac(
        'sha512',
        key,
        salt,
        V4_ITER_COUNT,
        dklen=KEY_SIZE
    )

    # 2. 派生 MAC 密钥
    # MAC salt = salt XOR 0x3a
    mac_salt = xor_bytes(salt, 0x3a)

    mac_key = hashlib.pbkdf2_hmac(
        'sha512',
        enc_key,  # 使用派生的加密密钥作为输入
        mac_salt,
        2,  # MAC 密钥仅迭代 2 次
        dklen=KEY_SIZE
    )

    return enc_key, mac_key


# ==============================================================================
# HMAC 计算
# ==============================================================================

def calculate_page_hmac(page_data: bytes, mac_key: bytes, page_num: int,
                        is_first_page: bool = False) -> bytes:
    """
    计算数据库页的 HMAC-SHA512

    微信 v4 的 HMAC 计算方式:
    HMAC-SHA512(mac_key, encrypted_data || page_number)

    Args:
        page_data: 页数据 (4096 bytes)
        mac_key: MAC 密钥 (32 bytes)
        page_num: 页码 (从 0 开始)
        is_first_page: 是否是第一页 (第一页需要跳过 salt)

    Returns:
        HMAC-SHA512 值 (64 bytes)
    """
    # 确定数据起始位置
    # 第一页: 跳过 salt (16 bytes)
    # 其他页: 从 0 开始
    offset = SALT_SIZE if is_first_page else 0

    # 数据结束位置: page_size - reserve + IV_SIZE
    # 4096 - 80 + 16 = 4032
    data_end = V4_PAGE_SIZE - RESERVE + IV_SIZE

    # 创建 HMAC
    h = hmac.new(mac_key, digestmod=hashlib.sha512)

    # 添加加密数据部分
    h.update(page_data[offset:data_end])

    # 添加页码 (小端序, 从 1 开始)
    page_no = struct.pack('<I', page_num + 1)
    h.update(page_no)

    return h.digest()


def verify_page_hmac(page_data: bytes, mac_key: bytes, page_num: int,
                     is_first_page: bool = False) -> bool:
    """
    验证数据库页的 HMAC

    Args:
        page_data: 页数据 (4096 bytes)
        mac_key: MAC 密钥
        page_num: 页码
        is_first_page: 是否是第一页

    Returns:
        True: HMAC 验证通过
        False: HMAC 验证失败
    """
    # 计算 HMAC
    calculated_mac = calculate_page_hmac(page_data, mac_key, page_num, is_first_page)

    # 提取存储的 HMAC
    # 位置: page[4032:4096]
    data_end = V4_PAGE_SIZE - RESERVE + IV_SIZE
    stored_mac = page_data[data_end:data_end + HMAC_SHA512_SIZE]

    # 使用恒定时间比较 (防止时序攻击)
    return hmac.compare_digest(calculated_mac, stored_mac)


# ==============================================================================
# AES 加密/解密
# ==============================================================================

def decrypt_aes_cbc(encrypted_data: bytes, key: bytes, iv: bytes) -> bytes:
    """
    AES-256-CBC 解密

    Args:
        encrypted_data: 加密数据
        key: AES 密钥 (32 bytes)
        iv: 初始化向量 (16 bytes)

    Returns:
        解密后的数据
    """
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.decrypt(encrypted_data)


def encrypt_aes_cbc(plain_data: bytes, key: bytes, iv: bytes) -> bytes:
    """
    AES-256-CBC 加密

    Args:
        plain_data: 明文数据
        key: AES 密钥 (32 bytes)
        iv: 初始化向量 (16 bytes)

    Returns:
        加密后的数据
    """
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(plain_data)


# ==============================================================================
# 工具函数
# ==============================================================================

def is_encrypted_db(file_path: str) -> bool:
    """
    检查数据库是否已加密

    Args:
        file_path: 数据库文件路径

    Returns:
        True: 已加密
        False: 未加密 (标准 SQLite 格式)
    """
    try:
        with open(file_path, 'rb') as f:
            header = f.read(len(SQLITE_HEADER))

        # 如果是标准 SQLite 头，说明未加密
        return header != SQLITE_HEADER
    except Exception:
        return False


def get_db_salt(file_path: str) -> bytes:
    """
    从数据库第一页提取 Salt

    Args:
        file_path: 数据库文件路径

    Returns:
        Salt (16 bytes)

    Raises:
        ValueError: 如果文件太小或读取失败
    """
    try:
        with open(file_path, 'rb') as f:
            first_page = f.read(V4_PAGE_SIZE)

        if len(first_page) < SALT_SIZE:
            raise ValueError(f"文件太小，无法提取 salt")

        return first_page[:SALT_SIZE]
    except Exception as e:
        raise ValueError(f"读取 salt 失败: {e}")


if __name__ == "__main__":
    # 简单测试
    print("微信 v4 加密参数:")
    print(f"  页大小: {V4_PAGE_SIZE} bytes")
    print(f"  迭代次数: {V4_ITER_COUNT}")
    print(f"  Reserve 大小: {RESERVE} bytes")
    print(f"  密钥长度: {KEY_SIZE} bytes")
    print(f"  Salt 长度: {SALT_SIZE} bytes")