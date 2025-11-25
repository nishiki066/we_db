"""
微信数据库工具 - 核心模块
"""

from .crypto import (
    V4_PAGE_SIZE,
    V4_ITER_COUNT,
    KEY_SIZE,
    SALT_SIZE,
    derive_keys,
    verify_page_hmac,
    decrypt_aes_cbc,
    is_encrypted_db,
    get_db_salt,
)

from .decryptor import DatabaseDecryptor, decrypt_database

# key_extractor 只在 lldb 环境中导入
# 不在 __all__ 中导出

__all__ = [
    'V4_PAGE_SIZE',
    'V4_ITER_COUNT',
    'KEY_SIZE',
    'SALT_SIZE',
    'derive_keys',
    'verify_page_hmac',
    'decrypt_aes_cbc',
    'is_encrypted_db',
    'get_db_salt',
    'DatabaseDecryptor',
    'decrypt_database',
]