#!/usr/bin/env python3
"""
微信数据库密钥提取器 (macOS v4)

使用 lldb hook CCKeyDerivationPBKDF 函数来捕获原始密钥
"""

import lldb
import os
import json
from pathlib import Path
from datetime import datetime

from .crypto import (
    V4_ITER_COUNT,
    KEY_SIZE,
    SALT_SIZE,
    V4_PAGE_SIZE,
    derive_keys,
    verify_page_hmac,
)

# ==============================================================================
# 全局变量
# ==============================================================================

# 记录线程最后打开的数据库文件
thread_last_db = {}

# 记录已发现的密钥
discovered_keys = {}  # {db_name: {'key': key_hex, 'path': db_path, 'validated': bool}}

# 数据库文件路径映射
db_paths = {}  # {db_name: full_path}

# 输出目录 (可以在导入后修改)
OUTPUT_DIR = Path("./data/keys")


# ==============================================================================
# 密钥验证函数
# ==============================================================================

def validate_key(db_path: str, key: bytes) -> bool:
    """
    验证密钥是否正确

    通过验证第一页的 HMAC 来判断密钥是否正确

    Args:
        db_path: 数据库文件路径
        key: 原始密钥 (32 bytes)

    Returns:
        True: 密钥正确, False: 密钥错误
    """
    try:
        if not os.path.exists(db_path):
            print(f"    ⚠️  数据库文件不存在: {db_path}")
            return False

        # 读取第一页
        with open(db_path, 'rb') as f:
            first_page = f.read(V4_PAGE_SIZE)

        if len(first_page) < V4_PAGE_SIZE:
            print(f"    ❌ 数据库文件太小: {len(first_page)} bytes")
            return False

        # 提取 Salt
        salt = first_page[:SALT_SIZE]

        # 派生密钥
        enc_key, mac_key = derive_keys(key, salt)

        # 验证 HMAC
        if verify_page_hmac(first_page, mac_key, page_num=0, is_first_page=True):
            print(f"    ✅ 密钥验证成功!")
            print(f"    📌 Salt: {salt.hex()}")
            return True
        else:
            print(f"    ❌ HMAC 验证失败 - 密钥不正确")
            return False

    except Exception as e:
        print(f"    ❌ 验证过程出错: {e}")
        import traceback
        traceback.print_exc()
        return False


# ==============================================================================
# lldb Hook 回调函数
# ==============================================================================

def open_callback(frame, bp_loc, dict):
    """
    拦截 open() 函数,记录正在打开的 .db 文件

    ARM64 函数调用约定:
        - open(const char *path, int flags, ...)
        - x0 = path (字符串指针)
    """
    # 读取 x0 寄存器 (path 参数)
    path_ptr = frame.FindRegister("x0").GetValueAsUnsigned()

    # 从内存读取路径字符串
    error = lldb.SBError()
    path_data = frame.GetThread().GetProcess().ReadMemory(path_ptr, 512, error)

    if error.Success():
        try:
            path_str = path_data.split(b'\0')[0].decode('utf-8')

            # 只关注微信数据库文件
            if path_str.endswith(".db") and "com.tencent.xinWeChat" in path_str:
                tid = frame.GetThread().GetThreadID()
                db_name = os.path.basename(path_str)

                # 记录线程和数据库的对应关系
                thread_last_db[tid] = db_name
                db_paths[db_name] = path_str

                print(f"\n{'=' * 70}")
                print(f"[📂 打开文件] Thread-{tid}: {db_name}")
                print(f"    路径: {path_str}")
                print(f"{'=' * 70}")

        except Exception:
            pass

    return False  # 不暂停,继续运行


def pbkdf_callback(frame, bp_loc, dict):
    """
    拦截 CCKeyDerivationPBKDF 函数,提取原始密钥

    函数签名:
        int CCKeyDerivationPBKDF(
            CCPBKDFAlgorithm algorithm,    // x0
            const char *password,          // x1 ← 原始密钥
            size_t passwordLen,            // x2 ← 密钥长度
            const uint8_t *salt,           // x3 ← Salt
            size_t saltLen,                // x4
            CCPseudoRandomAlgorithm prf,   // x5
            uint rounds,                   // x6 ← 迭代次数
            uint8_t *derivedKey,           // x7
            size_t derivedKeyLen           // stack
        );
    """
    # 1. 读取迭代次数 (x6)
    rounds_reg = frame.FindRegister("x6")
    if not rounds_reg.IsValid():
        return False

    rounds = rounds_reg.GetValueAsUnsigned()

    # 2. 只捕获原始密钥派生 (rounds = 256000)
    # MAC 密钥派生时 rounds = 2, 我们不需要
    if rounds != V4_ITER_COUNT:
        return False

    # 3. 读取密钥长度 (x2)
    len_reg = frame.FindRegister("x2")
    if not len_reg.IsValid():
        return False

    length = len_reg.GetValueAsUnsigned()
    if length != KEY_SIZE:
        return False

    # 4. 读取密钥地址 (x1)
    addr_reg = frame.FindRegister("x1")
    if not addr_reg.IsValid():
        return False

    addr = addr_reg.GetValueAsUnsigned()

    # 5. 从内存读取密钥数据
    process = frame.GetThread().GetProcess()
    error = lldb.SBError()
    key_bytes = process.ReadMemory(addr, KEY_SIZE, error)

    if not error.Success():
        print(f"    ❌ 读取密钥失败: {error}")
        return False

    # 6. 获取线程 ID 和对应的数据库
    tid = frame.GetThread().GetThreadID()
    db_name = thread_last_db.get(tid, "Unknown_DB")

    # 7. 转换为十六进制
    key_hex = key_bytes.hex()

    # 8. 去重检查
    if db_name in discovered_keys:
        if discovered_keys[db_name]['key'] == key_hex:
            return False  # 相同的密钥,跳过
        else:
            print(f"\n⚠️  警告: {db_name} 发现不同的密钥!")
            print(f"    旧密钥: {discovered_keys[db_name]['key']}")
            print(f"    新密钥: {key_hex}")

    # 9. 显示捕获的密钥
    print(f"\n[🔑 捕获原始密钥]")
    print(f"    数据库: {db_name}")
    print(f"    线程ID: {tid}")
    print(f"    迭代次数: {rounds}")
    print(f"    密钥: {key_hex}")

    # 10. 可选: 读取 Salt
    salt_addr_reg = frame.FindRegister("x3")
    salt_len_reg = frame.FindRegister("x4")

    if salt_addr_reg.IsValid() and salt_len_reg.IsValid():
        salt_addr = salt_addr_reg.GetValueAsUnsigned()
        salt_len = salt_len_reg.GetValueAsUnsigned()

        if salt_len == SALT_SIZE:
            salt_bytes = process.ReadMemory(salt_addr, SALT_SIZE, error)
            if error.Success():
                print(f"    Salt: {salt_bytes.hex()}")

    # 11. 立即验证密钥
    db_path = db_paths.get(db_name)
    validated = False

    if db_path:
        print(f"\n[🔍 验证密钥]")
        validated = validate_key(db_path, key_bytes)
    else:
        print(f"\n    ⚠️  未找到数据库路径,无法验证")

    # 12. 记录新发现的密钥
    discovered_keys[db_name] = {
        'key': key_hex,
        'path': db_path,
        'validated': validated,
        'timestamp': datetime.now().isoformat()
    }

    print(f"{'=' * 70}\n")
    auto_save_keys()
    return False  # 不暂停,继续运行


def auto_save_keys():
    """
    自动保存密钥到文件
    """
    if not discovered_keys:
        return

    try:
        # 确保输出目录存在
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

        # 主文件（始终最新）
        output_file = OUTPUT_DIR / "wechat_keys_latest.json"

        # 备份文件（带时间戳）
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = OUTPUT_DIR / f"wechat_keys_{timestamp}.json"

        # 构建数据
        data = {
            "extracted_at": datetime.now().isoformat(),
            "version": "v4",
            "total_databases": len(discovered_keys),
            "databases": discovered_keys
        }

        # 保存主文件
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        # 保存备份
        with open(backup_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        print(f"💾 已自动保存密钥:")
        print(f"   📄 主文件: {output_file.name}")
        print(f"   📄 备份: {backup_file.name}")
        print(f"   📊 共 {len(discovered_keys)} 个数据库\n")

    except Exception as e:
        print(f"⚠️  自动保存失败: {e}\n")


# ==============================================================================
# lldb 模块初始化
# ==============================================================================

def __lldb_init_module(debugger, internal_dict):
    """
    lldb 加载此脚本时自动调用
    """
    target = debugger.GetSelectedTarget()

    if not target.IsValid():
        print("❌ 没有有效的目标进程")
        return

    # 确保输出目录存在
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    print("\n" + "=" * 70)
    print("🔧 微信数据库密钥提取器 v3.0")
    print("=" * 70)
    print(f"📁 输出目录: {OUTPUT_DIR.absolute()}")
    print("=" * 70)

    # 1. Hook open() 函数
    bp_open = target.BreakpointCreateByName("open", "libsystem_kernel.dylib")
    if bp_open.IsValid():
        bp_open.SetScriptCallbackFunction("extract_keys.open_callback")
        print(f"✅ 已设置 open() hook (Breakpoint #{bp_open.GetID()})")
    else:
        print("⚠️  设置 open() hook 失败")

    # 2. Hook CCKeyDerivationPBKDF() 函数
    bp_key = target.BreakpointCreateByName("CCKeyDerivationPBKDF", "libcommonCrypto.dylib")
    if bp_key.IsValid():
        bp_key.SetScriptCallbackFunction("extract_keys.pbkdf_callback")
        print(f"✅ 已设置 CCKeyDerivationPBKDF() hook (Breakpoint #{bp_key.GetID()})")
    else:
        print("⚠️  设置 CCKeyDerivationPBKDF() hook 失败")

    print("=" * 70)
    print("📡 开始监听...\n")
    print("💡 提示:")
    print("  1. 在微信中打开不同的聊天，触发数据库访问")
    print("  2. 密钥将自动捕获并验证")
    print("  3. 使用以下命令管理密钥:")
    print("     (lldb) script extract_keys.show_keys()         # 显示已捕获的密钥")
    print("     (lldb) script extract_keys.save_keys()         # 保存密钥")
    print("  4. 按 Ctrl+C 停止监听")
    print("=" * 70 + "\n")


# ==============================================================================
# 辅助函数 (在 lldb 中调用)
# ==============================================================================

def show_keys(debugger=None, command=None, result=None, internal_dict=None):
    """
    显示已捕获的所有密钥

    在 lldb 中使用:
        (lldb) script extract_keys.show_keys()
    """
    if not discovered_keys:
        print("\n还没有捕获到任何密钥")
        print("💡 请在微信中打开聊天，触发数据库访问\n")
        return

    print(f"\n{'=' * 70}")
    print(f"📋 已捕获的密钥 (共 {len(discovered_keys)} 个)")
    print(f"{'=' * 70}\n")

    for db_name, info in discovered_keys.items():
        status = "✅" if info['validated'] else "❓"
        print(f"{status} {db_name}")
        print(f"   🔑 密钥: {info['key']}")

        if info['path']:
            print(f"   📁 路径: {info['path']}")

        print(f"   🔍 验证: {'通过' if info['validated'] else '未验证'}")
        print(f"   ⏰ 时间: {info['timestamp']}")
        print()

    print(f"{'=' * 70}\n")


def save_keys(output_file: str = None, debugger=None, command=None,
              result=None, internal_dict=None):
    """
    保存密钥到 JSON 文件

    在 lldb 中使用:
        (lldb) script extract_keys.save_keys()                    # 自动生成文件名
        (lldb) script extract_keys.save_keys("my_keys.json")     # 自定义文件名
    """
    if not discovered_keys:
        print("\n还没有捕获到任何密钥")
        print("💡 请在微信中打开聊天，触发数据库访问\n")
        return

    # 生成默认文件名
    if output_file is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = str(OUTPUT_DIR / f"wechat_keys_{timestamp}.json")
    elif not output_file.startswith('/'):
        # 相对路径，放到 OUTPUT_DIR
        output_file = str(OUTPUT_DIR / output_file)

    try:
        # 构建 JSON 数据
        data = {
            "extracted_at": datetime.now().isoformat(),
            "version": "v4",
            "total_databases": len(discovered_keys),
            "databases": discovered_keys
        }

        # 写入文件
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        print(f"\n{'=' * 70}")
        print("✅ 密钥保存成功!")
        print(f"{'=' * 70}")
        print(f"📄 文件: {output_file}")
        print(f"📊 数量: {len(discovered_keys)} 个数据库")
        print(f"{'=' * 70}\n")

    except Exception as e:
        print(f"\n❌ 保存失败: {e}\n")


if __name__ == "__main__":
    print("这个脚本需要在 lldb 中运行")
    print("\n使用方法:")
    print('  sudo lldb -n WeChat -w \\')
    print('    -o "command script import /path/to/key_extractor.py" \\')
    print('    -o "c"')