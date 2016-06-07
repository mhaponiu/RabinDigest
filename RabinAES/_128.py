from rabin import RabinAES, RabinFile
from cryptography.hazmat.primitives.ciphers import modes
import numpy as np

class RabinAES128(RabinAES):
    def __init__(self, skrot_size):
        super(RabinAES128, self).__init__(key_size=16, skrot_size=skrot_size)

class RabinAES128_CBC128(RabinAES128):
    def __init__(self, skrot_size=32):
        super(RabinAES128_CBC128, self).__init__(skrot_size=skrot_size)
        self.mode = self.mode = modes.CBC(np.random.bytes(16))

class RabinAES128_CTR128(RabinAES128):
    def __init__(self, skrot_size=32):
        super(RabinAES128_CTR128, self).__init__(skrot_size=skrot_size)
        self.mode = self.mode = modes.CTR(np.random.bytes(16))

class RabinFileAES128_CBC128(RabinFile, RabinAES128_CBC128):
    def __init__(self, file, file_chunk=1024, skrot_size=32):
        super(RabinFileAES128_CBC128, self).__init__(skrot_size=skrot_size)
        np.random.seed(13)
        self.file_chunk = file_chunk
        self.file = file

class RabinFileAES128_CTR128(RabinFile, RabinAES128_CTR128):
    def __init__(self, file, file_chunk=1024, skrot_size=32):
        super(RabinFileAES128_CTR128, self).__init__(skrot_size=skrot_size)
        np.random.seed(13)
        self.file_chunk = file_chunk
        self.file = file