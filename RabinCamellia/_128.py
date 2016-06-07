from rabin import RabinCamellia, RabinFile
from cryptography.hazmat.primitives.ciphers import modes
import numpy as np


class RabinCamellia128(RabinCamellia):
    def __init__(self, skrot_size):
        super(RabinCamellia128, self).__init__(key_size=16, skrot_size=skrot_size)

class RabinCamellia128_CBC128(RabinCamellia128):
    def __init__(self, skrot_size=32):
        super(RabinCamellia128_CBC128, self).__init__(skrot_size=skrot_size)
        self.mode = self.mode = modes.CBC(np.random.bytes(16))

class RabinFileCamellia128_CBC128(RabinFile, RabinCamellia128_CBC128):
    def __init__(self, file, file_chunk=1024, skrot_size=32):
        super(RabinFileCamellia128_CBC128, self).__init__(skrot_size=skrot_size)
        np.random.seed(13)
        self.file_chunk = file_chunk
        self.file = file