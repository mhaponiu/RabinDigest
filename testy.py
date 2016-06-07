# coding=utf-8
import os
import unittest
import binascii

from Rabin3DES._128 import RabinFile3DES128_CBC64
from RabinAES._192 import RabinFileAES192_CBC128
from RabinAES._256 import RabinFileAES256_CBC128
from RabinARC4._128 import RabinFileARC4_128
from RabinBlowfish._128 import RabinFileBlowfish128_CBC64
from RabinCAST5._128 import RabinFileCAST5_128_CBC64
from RabinCamellia._128 import RabinFileCamellia128_CBC128
from RabinSEED._128 import RabinFileSEED128_CBC128
from inneSkroty import MD5, SHA256
from rabin import BinHexStr
from RabinAES._128 import RabinAES128_CBC128, RabinFileAES128_CBC128, RabinFileAES128_CTR128, RabinFileAES128_GCM128, \
    RabinFileAES128_GCM512


class OgolnyRabinTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rabin = RabinAES128_CBC128()
        dir_test_data = 'test_data'
        cls.alfabet2kb = os.path.join(dir_test_data, 'alfabet2kB.bin')
        cls.alfabet2kb_plus_2 = os.path.join(dir_test_data, 'alfabet2kB_plus2.bin')
        cls.alfabet2kb_1_inny = os.path.join(dir_test_data, 'alfabet2kB_1inny.bin')
        # cls.alfabet4MB = os.path.join(dir_test_data, 'alfabet4MB.bin')
        # cls.alfabet4MB_plus_2 = os.path.join(dir_test_data, 'alfabet4MB_plus2.bin')
        # cls.alfabet4MB_1_inny = os.path.join(dir_test_data, 'alfabet4MB_1inny.bin')

    def test_bytearray_to_hexstring(self):
        string = 'ALA'
        b = bytearray(string)
        hex_string =  binascii.hexlify(b) #414c41
        odtworzony_string = binascii.unhexlify(hex_string)
        self.assertEqual(string, odtworzony_string)

    def test_bin_str_hex(self):
        string = 'ALA'
        bin_string = binascii.a2b_qp(string)
        string_from_bin = binascii.b2a_qp(bin_string)
        hex_string = binascii.hexlify(bin_string)
        string_from_hex = binascii.unhexlify(hex_string)
        self.assertEqual(string, string_from_bin)
        self.assertEqual('414c41', hex_string)
        self.assertEqual(string, string_from_hex)

    def test_init_value(self):
        bin_data = self.rabin.init_value()
        self.assertEqual('66dce15fb33deacb5c0362f30e95f52e6af463bb47d499c7bcae4199142ccb98',
                         BinHexStr.hex_from_bin(bin_data))

    def test_generator_klucza(self):
        r = RabinAES128_CBC128()
        text = 'a'*16 + 'b' * 17 + 'ł'
        r.pobierz_dane_tekstowe(text)
        generator = r._generator_klucza(r.bytes_io, byte_len=16)
        lista = []
        for r in generator:
            lista.append(r)
        self.assertEqual(lista, ['a' * 16, 'b' * 16, 'b=C5=82'])

    def test_podaj_blok_do_AESa(self):
        r = RabinAES128_CBC128()
        text = 'a' * 16 + 'b' * 17 + 'ł'
        r.pobierz_dane_tekstowe(text)
        for block in r.gen_blok_do_szyfru_klucz(key_len_bytes=16):
            self.assertEqual(16, len(block))

    def test_szyfruj(self):
        r = RabinAES128_CBC128()
        self.assertEqual('b37165e2fcb77375fb1b16a4696d896d',
                         r.hex_from_bin(r.szyfruj(b'1234567890123456', b"a secret message")))

    def test_skrot(self):
        r = RabinAES128_CBC128()
        text = b'a'*16 + b'ba'
        r.pobierz_dane_tekstowe(text)
        self.assertEqual('23468570f72bacc1b269d40dde92b8406826838c1eceff2dc25fadbf02b7465e',
                         r.skrot())

    def test_podaj_blok_do_AESa_z_pliku1(self):
        r = RabinFileAES128_CBC128(self.alfabet2kb)
        i = 0
        length = 0
        for b in  r.gen_blok_do_szyfru_klucz(key_len_bytes=16):
            i = i + 1
            length = length + len(b)
        self.assertEqual(2048/16, i)
        self.assertEqual(2048, length)

    def test_podaj_blok_do_AESa_z_pliku2(self):
        r = RabinFileAES128_CBC128(self.alfabet2kb_plus_2)
        i = 0
        length = 0
        for blok in r.gen_blok_do_szyfru_klucz(key_len_bytes=16):
            i = i + 1
            length = length + len(blok)
        self.assertEqual(2048 / 16 + 1, i)
        self.assertEqual(2048 + 16, length)


    def test_file_skrot1(self):
        r = RabinFileAES128_CBC128(self.alfabet2kb)
        self.assertEqual('b2dc7bca4d3950b38c3bd042f93bcf28247bd7fa112e0edf6e60c56790c80604',
                         r.skrot())

    def test_file_equal_normal(self):
        with open(self.alfabet2kb_plus_2, 'rb') as f:
            bin_data = f.read()
        r = RabinAES128_CBC128()
        r.pobierz_dane_binarne(bin_data)
        r2 = RabinFileAES128_CBC128(file=self.alfabet2kb_plus_2)
        self.assertEqual(r.skrot(), r2.skrot())

# @unittest.skip('.')
class TestRozneRabinyFile(object):

    @classmethod
    def setUpClass(cls):
        dir_test_data = 'test_data'
        cls.alfabet2kB = os.path.join(dir_test_data, 'alfabet2kB.bin')
        cls.alfabet2kB_plus_2 = os.path.join(dir_test_data, 'alfabet2kB_plus2.bin')
        cls.alfabet2kB_1_inny = os.path.join(dir_test_data, 'alfabet2kB _1inny.bin')

        cls.alfabet2MB = os.path.join(dir_test_data, 'alfabet2MB.bin')
        cls.alfabet2MB_plus_2 = os.path.join(dir_test_data, 'alfabet2MB_plus2.bin')
        cls.alfabet2MB_1_inny = os.path.join(dir_test_data, 'alfabet2MB_1inny.bin')

    def test_normal_2k(self):
        self.r = self.klasa(file=self.alfabet2kB, file_chunk=1024, skrot_size=32)
        self.r.skrot()

    @unittest.skip('')
    def test_normal_2M_2k_equal(self):
        r1 = self.klasa(file=self.alfabet2MB, file_chunk=1024, skrot_size=32)
        skrot_blok_1k = r1.skrot()
        r2 = self.klasa(file=self.alfabet2MB, file_chunk=1048576, skrot_size=32)
        skrot_blok_1M =  r2.skrot()
        self.assertEqual(skrot_blok_1k, skrot_blok_1M)

    def test_1inny_2k(self):
        r1 = self.klasa(file=self.alfabet2kB, file_chunk=1024, skrot_size=32)
        skrot1 = r1.skrot()
        r2 = self.klasa(file=self.alfabet2kB_1_inny, file_chunk=1024, skrot_size=32)
        skrot2 = r2.skrot()
        p = self._podobienstwo_ciagow(skrot1, skrot2)
        self.assertLess(p, 0.15) # 0.04% tych samych znakow

    def test_2wiecej_2k(self):
        r1 = self.klasa(file=self.alfabet2kB, file_chunk=1024, skrot_size=32)
        skrot1 = r1.skrot()
        r2 = self.klasa(file=self.alfabet2kB_plus_2, file_chunk=1024, skrot_size=32)
        skrot2 = r2.skrot()
        p = self._podobienstwo_ciagow(skrot1, skrot2)
        self.assertLess(p, 0.15)  # 0.04% tych samych znakow

    def _podobienstwo_ciagow(self, skrot1, skrot2):
        dlugosc = len(skrot1)
        rozniace_sie = 0
        for a in zip(skrot1, skrot2):
            if a[0] != a[1]:
                rozniace_sie = rozniace_sie + 1
        podobienstwo = 1 - float(rozniace_sie)/dlugosc
        return podobienstwo

#AES 128 (blokowy)
class Test_RabinFileAES128_CBC128(TestRozneRabinyFile, unittest.TestCase):
    def setUp(self):
        self.klasa = RabinFileAES128_CBC128

class Test_RabinFileAES128_CTR128(TestRozneRabinyFile, unittest.TestCase):
    def setUp(self):
        self.klasa = RabinFileAES128_CTR128

class Test_RabinFileAES128_GCM128(TestRozneRabinyFile, unittest.TestCase):
    def setUp(self):
        self.klasa = RabinFileAES128_GCM128

class Test_RabinFileAES128_GCM512(TestRozneRabinyFile, unittest.TestCase):
    def setUp(self):
        self.klasa = RabinFileAES128_GCM512

# AES 192 (blokowy)
class Test_RabinFileAES192_CBC128(TestRozneRabinyFile, unittest.TestCase):
    def setUp(self):
        self.klasa = RabinFileAES192_CBC128

#AES 256 (blokowy)
class Test_RabinFileAES256_CBC128(TestRozneRabinyFile, unittest.TestCase):
    def setUp(self):
        self.klasa = RabinFileAES256_CBC128

#3DES 128 (blokowy)
class Test_RabinFile3DES128_CBC64(TestRozneRabinyFile, unittest.TestCase):
    def setUp(self):
        self.klasa = RabinFile3DES128_CBC64

#Camellia 128 (blokowy)
class Test_RabinFileCamellia128_CBC128(TestRozneRabinyFile, unittest.TestCase):
    def setUp(self):
        self.klasa = RabinFileCamellia128_CBC128

#Blowfish 128 (blokowy)
class Test_RabinFileBlowfish128_CBC128(TestRozneRabinyFile, unittest.TestCase):
    def setUp(self):
        self.klasa = RabinFileBlowfish128_CBC64

#ARC4 (strumieniowy)
class Test_RabinFileARC4_128(TestRozneRabinyFile, unittest.TestCase):
    def setUp(self):
        self.klasa = RabinFileARC4_128

#CAST5
class Test_RabinFileCAST5_128_CBC64(TestRozneRabinyFile, unittest.TestCase):
    def setUp(self):
        self.klasa = RabinFileCAST5_128_CBC64

#SEED
class Test_RabinFileSEED128_CBC128(TestRozneRabinyFile, unittest.TestCase):
    def setUp(self):
        self.klasa = RabinFileSEED128_CBC128

class InneSkrotyFile(unittest.TestCase):
    # TODO
    pass

class InneSkroty(unittest.TestCase):

    def test_SHA256_text(self):
        sha256 = SHA256()
        string = "ala ma kota"
        sha256.pobierz_dane_tekstowe(string)
        self.assertEqual('c623e3ee2d7fa2c770f19cace523191cf92f1d59b0678bbbb1825817c9a61575',
                         sha256.skrot())

    def test_SHA256_bin(self):
        sha256 = SHA256()
        string = "ala ma kota"
        bin_string = sha256.bin_from_str(string)
        sha256.pobierz_dane_binarne(bin_string)
        self.assertEqual('c623e3ee2d7fa2c770f19cace523191cf92f1d59b0678bbbb1825817c9a61575',
                         sha256.skrot())

    def test_MD5_bin(self):
        md5 = MD5()
        string = "ala ma kota"
        bin_string = md5.bin_from_str(string)
        md5.pobierz_dane_binarne(bin_string)
        self.assertEqual('e2c3275d0e1a4bc0da360dd225d74a43',
                         md5.skrot())

    def test_MD5_text(self):
        md5 = MD5()
        string = "ala ma kota"
        md5.pobierz_dane_tekstowe(string)
        self.assertEqual('e2c3275d0e1a4bc0da360dd225d74a43',
                         md5.skrot())