from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from rabin import SkrotBase

class InnySkrot(SkrotBase):
    def __init__(self, algorytm):
        self.digest = hashes.Hash(algorytm, backend=default_backend())

    def skrot(self):
        self.digest.update(self.bin_data)
        return self.hex_from_bin(self.digest.finalize())

    def pobierz_dane_binarne(self, bin_data):
        self.bin_data = bin_data

    def pobierz_dane_tekstowe(self, text_data):
        bin_data = self.bin_from_str(text_data)
        self.pobierz_dane_binarne(bin_data)


class SHA256(InnySkrot):
    def __init__(self):
        super(SHA256, self).__init__(hashes.SHA256())


class MD5(InnySkrot):
    def __init__(self):
        super(MD5, self).__init__(hashes.MD5())


