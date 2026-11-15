#!/usr/bin/env python3
"""Emit one JSON event per cycle with identity-client state (nsswitch, SSSD, Kerberos)."""
import sys

from authid_common import discover, emit


def main():
    emit(discover())
    return 0


if __name__ == "__main__":
    sys.exit(main())
