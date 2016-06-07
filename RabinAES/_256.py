from rabin import RabinAES, RabinFile
from cryptography.hazmat.primitives.ciphers import modes
import numpy as np

class RabinAES256(RabinAES):
    def __init__(self, skrot_size):
        super(RabinAES256, self).__init__(key_size=32, skrot_size=skrot_size)

class RabinAES256_CBC128(RabinAES256):
    def __init__(self, skrot_size=32):
        super(RabinAES256_CBC128, self).__init__(skrot_size=skrot_size)
        self.mode = self.mode = modes.CBC(np.random.bytes(16))

class RabinFileAES256_CBC128(RabinFile, RabinAES256_CBC128):
    def __init__(self, file, file_chunk=1024, skrot_size=32):
        super(RabinFileAES256_CBC128, self).__init__(skrot_size=skrot_size)
        np.random.seed(13)
        self.file_chunk = file_chunk
        self.file = file
