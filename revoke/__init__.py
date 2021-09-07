"""
Implementation of the Revocation List 2020 specification.
See here for details: https://w3c-ccg.github.io/vc-status-rl-2020/
"""

import zlib
import base64
from typing import List, Optional

# Default size of the revocation list (for herd privacy)
DefaultListSize = 16 * 1024 * 8


class RevocationList:
    bitlist: bytearray

    def __init__(self, bitlist: Optional[bytearray] = None):
        self.bitlist = bitlist if bitlist else bytearray(DefaultListSize)

    def revoke(self, rid: int):
        """
        Revoke a credential for the given revocation list index
        """
        i = rid >> 3
        self.bitlist[i] = self.bitlist[i] | 128 >> (rid & 7)

    def is_revoked(self, rid: int) -> bool:
        """
        Check if a credential is revoked
        """
        if self.bitlist[rid >> 3] & 1 << (7 - rid % 8) > 0:
            return True
        else:
            return False

    def batch_revoke(self, revocation_list: List[int]):
        for i in revocation_list:
            self.revoke(i)

    @classmethod
    def decode(cls, encoded: str):
        b = base64.urlsafe_b64decode(encoded)
        bl = zlib.decompress(b)
        return cls(bl)

    def encode(self) -> str:
        compressed = zlib.compress(bytes(self.bitlist))
        return base64.urlsafe_b64encode(compressed).decode()

    def size(self):
        return len(self.bitlist)
