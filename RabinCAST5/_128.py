from rabin import RabinCAST5, RabinFile
from cryptography.hazmat.primitives.ciphers import modes
import numpy as np


class RabinCAST5_128(RabinCAST5):
    def __init__(self, skrot_size):
        super(RabinCAST5_128, self).__init__(key_size=16, skrot_size=skrot_size)


class RabinCAST5_128_CBC64(RabinCAST5_128):
    def __init__(self, skrot_size=32):
        super(RabinCAST5_128_CBC64, self).__init__(skrot_size=skrot_size)
        self.mode = self.mode = modes.CBC(np.random.bytes(8))


class RabinFileCAST5_128_CBC64(RabinFile, RabinCAST5_128_CBC64):
    def __init__(self, file, file_chunk=1024, skrot_size=32):
        super(RabinFileCAST5_128_CBC64, self).__init__(skrot_size=skrot_size)
        np.random.seed(13)
        self.file_chunk = file_chunk
        self.file = file