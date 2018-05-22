import sys
import os
import os.path

THIS_DIR = os.path.dirname(os.path.realpath(__file__))
LOCAL_BESS = os.path.realpath('{}/../bess'.format(THIS_DIR))

try:
    bess_path = os.getenv('BESS_PATH', LOCAL_BESS)
    os.environ['BESS_PATH'] = bess_path
    sys.path.insert(1, '%s/bessctl' % bess_path)
    sys.path.insert(1, '%s' % bess_path)
    import pybess.bess
    import cli
except ImportError:
    print >> sys.stderr, 'Cannot import the API module (pybess)'
    raise
