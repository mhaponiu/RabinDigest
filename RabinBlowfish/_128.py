from rabin import RabinBlowfish, RabinFile
from cryptography.hazmat.primitives.ciphers import modes
import numpy as np


class RabinBlowfish128(RabinBlowfish):
    def __init__(self, skrot_size):
        super(RabinBlowfish128, self).__init__(key_size=16, skrot_size=skrot_size)


class RabinBlowfish128_CBC64(RabinBlowfish128):
    def __init__(self, skrot_size=32):
        super(RabinBlowfish128_CBC64, self).__init__(skrot_size=skrot_size)
        self.mode = self.mode = modes.CBC(np.random.bytes(8))


class RabinFileBlowfish128_CBC64(RabinFile, RabinBlowfish128_CBC64):
    def __init__(self, file, file_chunk=1024, skrot_size=32):
        super(RabinFileBlowfish128_CBC64, self).__init__(skrot_size=skrot_size)
        np.random.seed(13)
        self.file_chunk = file_chunk
        self.file = file