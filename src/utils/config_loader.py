# !/usr/bin/env python3
"""
配置加载模块

从 YAML 文件读取配置
"""

import yaml
from pathlib import Path
from typing import Any, Optional


class Config:
    """
    配置管理类

    用法:
        config = Config('config.yaml')
        log_level = config.get('logging.level', 'INFO')
        workspace_root = config.get('workspace.root')
    """

    def __init__(self, config_file: str = 'config.yaml'):
        """
        初始化配置

        Args:
            config_file: 配置文件路径

        Raises:
            FileNotFoundError: 配置文件不存在
            yaml.YAMLError: YAML 格式错误
        """
        self.config_file = Path(config_file)

        if not self.config_file.exists():
            raise FileNotFoundError(f"配置文件不存在: {config_file}")

        with open(self.config_file, 'r', encoding='utf-8') as f:
            self.data = yaml.safe_load(f)

        if self.data is None:
            self.data = {}

    def get(self, key_path: str, default: Any = None) -> Any:
        """
        获取配置项 (支持点号路径)

        Args:
            key_path: 配置路径，用点号分隔 (例如: 'workspace.root')
            default: 默认值 (如果配置项不存在)

        Returns:
            配置值

        Example:
            >>> config.get('workspace.root')
            './data'
            >>> config.get('workspace.keys')
            './data/keys'
            >>> config.get('non.existent.key', 'default_value')
            'default_value'
        """
        keys = key_path.split('.')
        value = self.data

        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default

        return value

    def get_path(self, key_path: str, default: Any = None) -> Optional[Path]:
        """
        获取配置项并转换为 Path 对象

        Args:
            key_path: 配置路径
            default: 默认值

        Returns:
            Path 对象或 None
        """
        value = self.get(key_path, default)
        if value is None:
            return None
        return Path(value)

    def ensure_directories(self):
        """
        确保所有配置的目录存在

        自动创建 workspace 下的所有目录
        """
        workspace = self.get('workspace', {})

        for key, path in workspace.items():
            if path:
                Path(path).mkdir(parents=True, exist_ok=True)

        # 创建日志目录
        log_dir = self.get('workspace.logs', 'logs')
        Path(log_dir).mkdir(parents=True, exist_ok=True)

    def __repr__(self) -> str:
        return f"Config(file='{self.config_file}')"

    def __str__(self) -> str:
        return yaml.dump(self.data, allow_unicode=True, default_flow_style=False)


if __name__ == "__main__":
    # 测试代码
    try:
        config = Config('config.yaml')
        print("配置加载成功:")
        print(config)

        # 测试获取配置
        print("\n测试获取配置:")
        print(f"workspace.root = {config.get('workspace.root')}")
        print(f"workspace.keys = {config.get('workspace.keys')}")
        print(f"logging.level = {config.get('logging.level')}")
        print(f"不存在的配置 = {config.get('non.existent', 'default')}")

        # 测试创建目录
        print("\n创建工作目录...")
        config.ensure_directories()
        print("✅ 目录创建完成")

    except FileNotFoundError as e:
        print(f"❌ {e}")
        print("请先创建 config.yaml 文件")