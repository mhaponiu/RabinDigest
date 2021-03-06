import binascii
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.backends import default_backend
import numpy as np
from functools import partial
from io import BytesIO

class BinHexStr(object):
    @staticmethod
    def bin_from_str(string):
        return binascii.b2a_qp(string)

    @staticmethod
    def str_from_bin(bin):
        return binascii.b2a_qp(bin)

    @staticmethod
    def hex_from_bin(bin):
        return binascii.hexlify(bin)

    @staticmethod
    def string_from_hex(hex_string):
        return binascii.unhexlify(hex_string)

    @staticmethod
    def hex_from_string(string):
        return BinHexStr.hex_from_bin(BinHexStr.bin_from_str(string))

class SkrotBase(BinHexStr):
    def pobierz_dane_binarne(self, bin_data):
        pass

    def pobierz_dane_tekstowe(self, text_data):
        pass

    def skrot(self):
        pass



class Rabin(SkrotBase):
    def __init__(self, key_size=16, skrot_size=32, algorytm = algorithms.AES):
        self.backend = default_backend()
        self.algorytm = algorytm
        self.key_size = key_size
        self.skrot_size = skrot_size
        np.random.seed(13)
        self.mode = None
        # self.mode = modes.CBC(np.random.bytes(16)) #tylko 16, padding wymagany
        # self.mode = modes.GCM(np.random.bytes(16)) #moga byc rozne rozmiary 1 - 2^64
        # self.mode = modes.CTR(np.random.bytes(16)) # tylko 16

    def skrot(self):
        wejscie = self.init_value(byte_length=self.skrot_size)
        for blok in self.gen_blok_do_szyfru_klucz(key_len_bytes=self.key_size):
            wyjscie = self.szyfruj(klucz=blok, wiadomosc=wejscie)
            wejscie = wyjscie
        return self.hex_from_bin(wyjscie)

    def _generator_klucza(self, bytes_io, byte_len):
        '''z bloku danych w ramie generuje paczki o byte_len dlugosci
        ale ostatni moze miec mniejsza dlugosc'''
        CHUNK = byte_len  # 16 bajtow to 128bitow
        return iter(partial(bytes_io.read, CHUNK), b'')

    def init_value(self, byte_length=32):
        # byte_length determinuje dlugosc wyjsciowa skrotu
        # 16 bajtow to 128 bitow
        np.random.seed(42)
        return np.random.bytes(byte_length)

    def pobierz_dane_binarne(self, bin_data):
        self.bytes_io = BytesIO(bin_data)

    def pobierz_dane_tekstowe(self, text_data):
        bin_data = self.str_from_bin(text_data)
        self.pobierz_dane_binarne(bin_data)

    def gen_blok_do_szyfru_klucz(self, key_len_bytes):
        '''generuje blok do podania do szyfru jako klucz
        zawsze ma stala wartosc, uzupelnia pseudolosowa liczba do block_len_bytes
        tutaj odczytuje z np pliku'''

        # 16 bajtow to 128 bitow
        # 1600 bajtow to 100 x 128bitow

        np.random.seed(69)
        for block in self._generator_klucza(self.bytes_io, byte_len=key_len_bytes):
            len_block = len(block)
            if len_block < key_len_bytes:
                block = block + np.random.bytes(key_len_bytes - len_block)
            elif len_block > key_len_bytes:
                raise Exception("blok wiekszy niz niz zakladano, szyfr go nie lyknie jako klucz")
            yield block

    def szyfruj(self, klucz, wiadomosc):
        cipher = Cipher(algorithm=self.algorytm(klucz), mode=self.mode, backend=self.backend)
        encryptor = cipher.encryptor()
        szyfrogram = encryptor.update(wiadomosc) + encryptor.finalize()
        return szyfrogram

class RabinAES(Rabin):
    def __init__(self, key_size, skrot_size):
        super(RabinAES, self).__init__(key_size=key_size, skrot_size=skrot_size, algorytm=algorithms.AES)

class Rabin3DES(Rabin):
    def __init__(self, key_size, skrot_size):
        super(Rabin3DES, self).__init__(key_size=key_size, skrot_size=skrot_size, algorytm=algorithms.TripleDES)

class RabinCamellia(Rabin):
    def __init__(self, key_size, skrot_size):
        super(RabinCamellia, self).__init__(key_size=key_size, skrot_size=skrot_size, algorytm=algorithms.Camellia)

class RabinBlowfish(Rabin):
    def __init__(self, key_size, skrot_size):
        super(RabinBlowfish, self).__init__(key_size=key_size, skrot_size=skrot_size, algorytm=algorithms.Blowfish)

class RabinARC4(Rabin):
    def __init__(self, key_size, skrot_size):
        super(RabinARC4, self).__init__(key_size=key_size, skrot_size=skrot_size, algorytm=algorithms.ARC4)

class RabinCAST5(Rabin):
    def __init__(self, key_size, skrot_size):
        super(RabinCAST5, self).__init__(key_size=key_size, skrot_size=skrot_size, algorytm=algorithms.CAST5)

class RabinSEED(Rabin):
    def __init__(self, key_size, skrot_size):
        super(RabinSEED, self).__init__(key_size=key_size, skrot_size=skrot_size, algorytm=algorithms.SEED)

class RabinIDEA(Rabin):
    def __init__(self, key_size, skrot_size):
        super(RabinIDEA, self).__init__(key_size=key_size, skrot_size=skrot_size, algorytm=algorithms.IDEA)

class RabinFile(object):
    def gen_blok_do_szyfru_klucz(self, key_len_bytes):
        with open(self.file, 'rb') as f:
            CHUNK = self.file_chunk  # 16 bajtow to 128bitow
            file_gen = iter(partial(f.read, CHUNK), b'')
            np.random.seed(69)
            for file_block in file_gen:
                file_block = BytesIO(file_block)
                for key_block in self._generator_klucza(file_block, byte_len=key_len_bytes):
                    len_block = len(key_block)
                    if len_block < key_len_bytes:
                        key_block = key_block + np.random.bytes(key_len_bytes - len_block)
                    elif len_block > key_len_bytes:
                        raise Exception("blok wiekszy niz niz zakladano, szyfr go nie lyknie jako klucz")
                    yield key_block






