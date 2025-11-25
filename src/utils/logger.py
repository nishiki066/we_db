#!/usr/bin/env python3
"""
日志配置模块

提供统一的日志配置
"""

import logging
import sys
from pathlib import Path
from typing import Optional


def setup_logger(
        name: str,
        log_file: Optional[str] = None,
        level: int = logging.INFO,
        console: bool = True
) -> logging.Logger:
    """
    创建并配置 logger

    Args:
        name: logger 名称
        log_file: 日志文件路径 (可选)
        level: 日志级别 (默认 INFO)
        console: 是否输出到控制台 (默认 True)

    Returns:
        配置好的 logger

    Example:
        logger = setup_logger('MyApp', 'logs/app.log')
        logger.info('Hello World')
    """
    # 创建 logger
    logger = logging.getLogger(name)
    logger.setLevel(level)

    # 避免重复添加 handler
    if logger.handlers:
        return logger

    # 日志格式
    formatter = logging.Formatter(
        '[%(asctime)s] %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # 控制台输出
    if console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(level)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

    # 文件输出
    if log_file:
        # 确保日志目录存在
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)

        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger


def get_logger(name: str) -> logging.Logger:
    """
    获取已存在的 logger

    Args:
        name: logger 名称

    Returns:
        logger 实例
    """
    return logging.getLogger(name)


# 预定义的 logger 配置
LOG_LEVELS = {
    'DEBUG': logging.DEBUG,
    'INFO': logging.INFO,
    'WARNING': logging.WARNING,
    'ERROR': logging.ERROR,
    'CRITICAL': logging.CRITICAL,
}

if __name__ == "__main__":
    # 测试代码
    logger = setup_logger('test', 'logs/test.log')

    logger.debug('This is a debug message')
    logger.info('This is an info message')
    logger.warning('This is a warning message')
    logger.error('This is an error message')
    logger.critical('This is a critical message')