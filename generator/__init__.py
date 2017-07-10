import sys
import os
import os.path

try:
    bess_path = os.getenv('BESS_PATH', None)
    if bess_path is None:
        print >> sys.stderr, 'BESS_PATH not set'
        sys.exit(1)
    sys.path.insert(1, '%s/bessctl' % bess_path)
    sys.path.insert(1, '%s' % bess_path)
    import pybess.bess
    import cli
except ImportError:
    print >> sys.stderr, 'Cannot import the API module (pybess)'
    raise
