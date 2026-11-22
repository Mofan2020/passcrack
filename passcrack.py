"""PyInstaller 打包入口。

单独放一个文件，是为了让 PyInstaller 有个干净的入口，不要把打包相关的
判断散进业务代码里。

freeze_support 必须在最前面调，否则 macOS 上打包后的多进程会重新执行
整个脚本。
"""

import multiprocessing
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

from passcrack.cli import main  # noqa: E402

if __name__ == "__main__":
    multiprocessing.freeze_support()
    sys.exit(main())
