
import concurrent.futures
import inspect
import os
import sys
import time
from enum import Enum
from typing import List

import pkg_resources


class LogLevel(Enum):
    NONE = -1
    ERROR = 0
    WARN = 1
    INFO = 2
    DEBUG = 3
    DEBUG_MORE = 4
    # if this isn't being piped to a file it will be ridiculous
    # it will also likely slow down the processor a shit-ton if it's being output to term.
    DEBUG_TOO_MUCH = 5

def print_err(msg):
    print(msg, file=sys.stderr)


class log:
    """
    """

    LOG_LEVEL = LogLevel.ERROR
    LOG_FUNC = print
    LOG_ERR = print_err

    @staticmethod
    def get_class_from_frame(fr):
        fr: inspect.FrameInfo = fr
        if 'self' in fr.frame.f_locals:
            return type(fr.frame.f_locals["self"]).__name__
        elif 'cls' in fr.frame.f_locals:
            return fr.frame.f_locals['cls'].__name__

        return None

    @staticmethod
    def line():
        stack_frame = inspect.stack()[2]
        filename = os.path.basename(stack_frame[1]).split('.')[0]
        line_name = f'L#{stack_frame[2]}'
        cn = log.get_class_from_frame(stack_frame)
        call_from = cn + ':' if cn is not None else ""
        call_from += stack_frame[3]
        return 'gidsrv.' + filename + ":" + line_name + ":" + call_from + '()'

    @staticmethod
    def debug(msg: str = ""):
        if log.LOG_LEVEL.value >= LogLevel.DEBUG.value:
            log.LOG_FUNC(f'DEBUG - {log.line()} - {msg}')

    @staticmethod
    def debug_more(msg: str = ""):
        if log.LOG_LEVEL.value >= LogLevel.DEBUG_MORE.value:
            log.LOG_FUNC(f'DEBUG-2 - {log.line()} - {msg}')

    @staticmethod
    def debug_tm(msg: str = ""):
        if log.LOG_LEVEL.value >= LogLevel.DEBUG_TOO_MUCH.value:
            log.LOG_FUNC(f'DEBUG-3 - {log.line()} - {msg}')

    @staticmethod
    def info(msg: str = ""):
        if log.LOG_LEVEL.value >= LogLevel.INFO.value:
            log.LOG_FUNC(f'INFO - {log.line()} - {msg}')

    @staticmethod
    def warn(msg: str = ""):
        if log.LOG_LEVEL.value >= LogLevel.WARN.value:
            log.LOG_ERR(f'WARN - {log.line()} - {msg}')

    @staticmethod
    def warning(msg: str = ""):
        if log.LOG_LEVEL.value >= LogLevel.WARN.value:
            log.LOG_ERR(f'WARN - {log.line()} - {msg}')

    @staticmethod
    def error(msg: str = ""):
        if log.LOG_LEVEL.value >= LogLevel.ERROR.value:
            log.LOG_ERR(f'ERROR - {log.line()} - {msg}')
