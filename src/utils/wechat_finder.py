"""
自动查找微信进程和数据目录
"""
import subprocess
import re
from pathlib import Path
from typing import Optional, Tuple, List
import plistlib


class WeChatFinder:
    """微信进程和目录查找器"""

    # macOS微信的Bundle ID
    BUNDLE_ID = "com.tencent.xinWeChat"

    # 可能的微信数据目录位置 (按优先级排序)
    BASE_PATHS = [
        # V4.1+ 新位置
        Path.home() / "Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files",
        # V4.0 旧位置
        Path.home() / "Library/Containers/com.tencent.xinWeChat/Data/Library/Application Support/com.tencent.xinWeChat",
        # 更老的版本
        Path.home() / "Library/Application Support/WeChat",
    ]

    @classmethod
    def find_wechat_process(cls) -> Optional[int]:
        """
        查找微信进程PID

        Returns:
            微信进程PID，如果未找到返回None
        """
        try:
            # 方式1: 使用 pgrep (最简单)
            result = subprocess.run(
                ['pgrep', '-x', 'WeChat'],
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.returncode == 0 and result.stdout.strip():
                pid = int(result.stdout.strip().split()[0])  # 取第一个PID
                print(f"[查找器] 找到微信进程: PID={pid}")
                return pid

            # 方式2: 使用 ps aux | grep (备用)
            result = subprocess.run(
                "ps aux | grep -i 'WeChat.app' | grep -v grep | awk '{print $2}'",
                shell=True,
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.stdout.strip():
                pid = int(result.stdout.strip().split()[0])
                print(f"[查找器] 找到微信进程: PID={pid}")
                return pid

            print("[查找器] 未找到微信进程 (微信可能未运行)")
            return None

        except Exception as e:
            print(f"[查找器] 查找微信进程出错: {e}")
            return None

    @classmethod
    def verify_process_running(cls, pid: int) -> bool:
        """验证进程是否仍在运行"""
        try:
            subprocess.run(['kill', '-0', str(pid)], check=True, capture_output=True)
            return True
        except:
            return False

    @classmethod
    def find_wechat_data_dir(cls) -> Optional[Path]:
        """
        查找微信数据目录

        Returns:
            微信数据目录路径，如果未找到返回None
        """
        # 检查预定义路径
        for base_path in cls.BASE_PATHS:
            if not base_path.exists():
                continue

            # 查找账号目录
            # V4.1+: 目录名格式如 zjf553216192_b79a
            # V4.0:  目录名格式如 2:c123456789abcdef
            account_dirs = []

            try:
                for item in base_path.iterdir():
                    if not item.is_dir():
                        continue

                    # V4.1+ 格式: 包含字母数字和下划线
                    # V4.0  格式: 以 "2:" 开头
                    if ('_' in item.name and not item.name.startswith('.')) or item.name.startswith('2:'):
                        # 验证是否包含微信数据特征目录
                        if (item / 'msg').exists() or (item / 'db_storage').exists() or (item / 'Message').exists():
                            account_dirs.append(item)
            except Exception as e:
                print(f"[查找器] 扫描目录出错 {base_path}: {e}")
                continue

            if account_dirs:
                # 取最新修改的账号目录
                latest_dir = max(account_dirs, key=lambda x: x.stat().st_mtime)
                print(f"[查找器] 找到微信数据目录: {latest_dir}")
                return latest_dir

        print("[查找器] 未找到微信数据目录")
        return None

    @classmethod
    def find_wechat_message_dir(cls) -> Optional[Path]:
        """
        查找微信消息存储目录 (包含图片的目录)

        Returns:
            消息目录路径
        """
        data_dir = cls.find_wechat_data_dir()
        if not data_dir:
            return None

        # 尝试多个可能的消息目录位置
        possible_dirs = [
            data_dir / "msg",  # V4.1+ 新位置
            data_dir / "Message",  # V4.0 位置
            data_dir / "Msg",  # V3 位置
        ]

        for msg_dir in possible_dirs:
            if msg_dir.exists():
                print(f"[查找器] 找到消息目录: {msg_dir}")
                return msg_dir

        print("[查找器] 未找到消息目录")
        return None

    @classmethod
    def get_wechat_version(cls) -> Optional[str]:
        """
        获取微信版本号

        Returns:
            版本号字符串，如 "4.1.5"
        """
        try:
            # 读取微信的 Info.plist
            app_path = Path("/Applications/WeChat.app/Contents/Info.plist")
            if not app_path.exists():
                return None

            with open(app_path, 'rb') as f:
                plist = plistlib.load(f)

            version = plist.get('CFBundleShortVersionString', 'Unknown')
            print(f"[查找器] 微信版本: {version}")
            return version

        except Exception as e:
            print(f"[查找器] 获取微信版本失败: {e}")
            return None

    @classmethod
    def find_all(cls) -> Tuple[Optional[int], Optional[Path], Optional[Path]]:
        """
        一次性查找所有信息

        Returns:
            (PID, 数据目录, 消息目录)
        """
        print("=" * 60)
        print("正在自动查找微信信息...")
        print("=" * 60)

        # 获取版本
        version = cls.get_wechat_version()

        # 查找进程
        pid = cls.find_wechat_process()

        # 查找目录
        data_dir = cls.find_wechat_data_dir()
        message_dir = cls.find_wechat_message_dir()

        print("=" * 60)

        if pid and data_dir and message_dir:
            print("✓ 所有信息查找完成!")
        else:
            print("⚠ 部分信息未找到")
            if not pid:
                print("  - 微信进程: 未运行")
            if not data_dir:
                print("  - 数据目录: 未找到")
            if not message_dir:
                print("  - 消息目录: 未找到")

        print("=" * 60)

        return pid, data_dir, message_dir


# 便捷函数
def find_wechat_pid() -> Optional[int]:
    """便捷函数: 查找微信进程PID"""
    return WeChatFinder.find_wechat_process()


def find_wechat_dir() -> Optional[Path]:
    """便捷函数: 查找微信数据目录"""
    return WeChatFinder.find_wechat_data_dir()


def find_wechat_message_dir() -> Optional[Path]:
    """便捷函数: 查找微信消息目录"""
    return WeChatFinder.find_wechat_message_dir()