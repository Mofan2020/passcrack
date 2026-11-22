"""模块入口：python -m passcrack 等价于直接跑 passcrack。"""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
