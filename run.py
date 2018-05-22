#!/usr/bin/env python3
import io
import sys

import generator
from generator.cmdline import *

if __name__ == '__main__':
    if len(sys.argv) == 1:
        run_cli()
    else:
        cmds = []
        line_buf = []

        for arg in sys.argv[1:]:
            if arg == '--':
                cmds.append(' '.join(line_buf))
                line_buf = []
            else:
                line_buf.append(arg)

        cmds.append(' '.join(line_buf))
        run_cmds(io.StringIO('\n'.join(cmds)))
