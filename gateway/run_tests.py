"""Run application fixtures with an explicit, test-only in-process fence."""
from contextlib import nullcontext
from pathlib import Path
import sys
import unittest


def main():
    root = Path(__file__).resolve().parent
    sys.path.insert(0, str(root))
    import registry

    original = registry.Registry.__init__

    def synthetic_registry(self, *args, **kwargs):
        kwargs.setdefault('fence_factory', nullcontext)
        return original(self, *args, **kwargs)

    registry.Registry.__init__ = synthetic_registry
    try:
        suite = unittest.defaultTestLoader.discover(str(root), pattern='test_*.py')
        result = unittest.TextTestRunner(verbosity=1).run(suite)
        return 0 if result.wasSuccessful() else 1
    finally:
        registry.Registry.__init__ = original


if __name__ == '__main__':
    raise SystemExit(main())
