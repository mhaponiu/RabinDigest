from rabin import RabinARC4, RabinFile
import numpy as np

#strumieniowy
class RabinARC4_128(RabinARC4):
    def __init__(self, skrot_size):
        super(RabinARC4_128, self).__init__(key_size=16, skrot_size=skrot_size)


class RabinFileARC4_128(RabinFile, RabinARC4_128):
    def __init__(self, file, file_chunk=1024, skrot_size=32):
        super(RabinFileARC4_128, self).__init__(skrot_size=skrot_size)
        np.random.seed(13)
        self.file_chunk = file_chunk
        self.file = file