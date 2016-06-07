from rabin import RabinSEED, RabinFile
from cryptography.hazmat.primitives.ciphers import modes
import numpy as np


class RabinSEED128(RabinSEED):
    def __init__(self, skrot_size):
        super(RabinSEED128, self).__init__(key_size=16, skrot_size=skrot_size)


class RabinSEED128_CBC128(RabinSEED128):
    def __init__(self, skrot_size=32):
        super(RabinSEED128_CBC128, self).__init__(skrot_size=skrot_size)
        self.mode = self.mode = modes.CBC(np.random.bytes(16))


class RabinFileSEED128_CBC128(RabinFile, RabinSEED128_CBC128):
    def __init__(self, file, file_chunk=1024, skrot_size=32):
        super(RabinFileSEED128_CBC128, self).__init__(skrot_size=skrot_size)
        np.random.seed(13)
        self.file_chunk = file_chunk
        self.file = file