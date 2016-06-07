import subprocess
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


class InnySkrotFile(SkrotBase):
    def __init__(self, sciezka, skrot):
        self.sciezka = sciezka
        self.nazwa_skrotu = skrot

    def skrot(self):
        wywolanie = ['openssl', 'dgst', '-'+self.nazwa_skrotu, self.sciezka]
        ret = subprocess.check_output(wywolanie).split('=')[-1].strip()
        # print ret
        return ret

class MD4_file(InnySkrotFile):
    def __init__(self, sciezka):
        super(MD4_file, self).__init__(sciezka=sciezka, skrot='md4')

class MD5_file(InnySkrotFile):
    def __init__(self, sciezka):
        super(MD5_file, self).__init__(sciezka=sciezka, skrot='md5')

class SHA1_file(InnySkrotFile):
    def __init__(self, sciezka):
        super(SHA1_file, self).__init__(sciezka=sciezka, skrot='sha1')

class SHA256_file(InnySkrotFile):
    def __init__(self, sciezka):
        super(SHA256_file, self).__init__(sciezka=sciezka, skrot='sha256')

class SHA512_file(InnySkrotFile):
    def __init__(self, sciezka):
        super(SHA512_file, self).__init__(sciezka=sciezka, skrot='sha512')

class Ripemd160_file(InnySkrotFile):
    def __init__(self, sciezka):
        super(Ripemd160_file, self).__init__(sciezka=sciezka, skrot='ripemd160')

class Whirlpool_file(InnySkrotFile):
    def __init__(self, sciezka):
        super(Whirlpool_file, self).__init__(sciezka=sciezka, skrot='whirlpool')
