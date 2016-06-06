# coding=utf-8
import unittest
import binascii
from rabin import BinHexStr, RabinAES, SHA256, MD5, RabinFileAES

import numpy as np

class RabinTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rabin = RabinAES()

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
        r = RabinAES()
        text = 'a'*16 + 'b' * 17 + 'ł'
        r.pobierz_dane_tekstowe(text)
        generator = r._generator_klucza(r.bytes_io, byte_len=16)
        lista = []
        for r in generator:
            lista.append(r)
        self.assertEqual(lista, ['a' * 16, 'b' * 16, 'b=C5=82'])

    def test_podaj_blok_do_AESa(self):
        r = RabinAES()
        text = 'a' * 16 + 'b' * 17 + 'ł'
        r.pobierz_dane_tekstowe(text)
        for block in r.gen_blok_do_szyfru_klucz(key_len_bytes=16):
            self.assertEqual(16, len(block))

    def test_szyfruj(self):
        r = RabinAES()
        self.assertEqual('b37165e2fcb77375fb1b16a4696d896d',
                         r.hex_from_bin(r.szyfruj(b'1234567890123456', b"a secret message")))

    def test_skrot(self):
        r = RabinAES()
        text = b'a'*16 + b'ba'
        r.pobierz_dane_tekstowe(text)
        self.assertEqual('23468570f72bacc1b269d40dde92b8406826838c1eceff2dc25fadbf02b7465e',
                         r.skrot())

    def test_podaj_blok_do_AESa_z_pliku1(self):
        r = RabinFileAES('alfabet2048.bin')
        i = 0
        length = 0
        for b in  r.gen_blok_do_szyfru_klucz(key_len_bytes=16):
            i = i + 1
            length = length + len(b)
        self.assertEqual(2048/16, i)
        self.assertEqual(2048, length)

    def test_podaj_blok_do_AESa_z_pliku2(self):
        r = RabinFileAES('alfabet2050.bin')
        i = 0
        length = 0
        for blok in r.gen_blok_do_szyfru_klucz(key_len_bytes=16):
            i = i + 1
            length = length + len(blok)
        self.assertEqual(2048 / 16 + 1, i)
        self.assertEqual(2048 + 16, length)


    def test_file_skrot1(self):
        r = RabinFileAES('alfabet2048.bin')
        self.assertEqual('b2dc7bca4d3950b38c3bd042f93bcf28247bd7fa112e0edf6e60c56790c80604',
                         r.skrot())

    def test_file_equal_normal(self):
        with open('alfabet2050.bin', 'rb') as f:
            bin_data = f.read()
        r = RabinAES()
        r.pobierz_dane_binarne(bin_data)
        r2 = RabinFileAES(file='alfabet2050.bin')
        self.assertEqual(r.skrot(), r2.skrot())



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