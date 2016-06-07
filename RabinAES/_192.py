from rabin import RabinAES, RabinFile
from cryptography.hazmat.primitives.ciphers import modes
import numpy as np

class RabinAES192(RabinAES):
    def __init__(self, skrot_size):
        super(RabinAES192, self).__init__(key_size=32, skrot_size=skrot_size)

class RabinAES192_CBC128(RabinAES192):
    def __init__(self, skrot_size=32):
        super(RabinAES192_CBC128, self).__init__(skrot_size=skrot_size)
        self.mode = self.mode = modes.CBC(np.random.bytes(16))

class RabinFileAES192_CBC128(RabinFile, RabinAES192_CBC128):
    def __init__(self, file, file_chunk=1024, skrot_size=32):
        super(RabinFileAES192_CBC128, self).__init__(skrot_size=skrot_size)
        np.random.seed(13)
        self.file_chunk = file_chunk
        self.file = file