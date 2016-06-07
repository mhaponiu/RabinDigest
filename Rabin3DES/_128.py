from rabin import Rabin3DES, RabinFile
from cryptography.hazmat.primitives.ciphers import modes
import numpy as np


class Rabin3DES128(Rabin3DES):
    def __init__(self, skrot_size):
        super(Rabin3DES128, self).__init__(key_size=16, skrot_size=skrot_size)

class Rabin3DES128_CBC64(Rabin3DES128):
    def __init__(self, skrot_size=32):
        super(Rabin3DES128_CBC64, self).__init__(skrot_size=skrot_size)
        self.mode = self.mode = modes.CBC(np.random.bytes(8))

class RabinFile3DES128_CBC64(RabinFile, Rabin3DES128_CBC64):
    def __init__(self, file, file_chunk=1024, skrot_size=32):
        super(RabinFile3DES128_CBC64, self).__init__(skrot_size=skrot_size)
        np.random.seed(13)
        self.file_chunk = file_chunk
        self.file = file