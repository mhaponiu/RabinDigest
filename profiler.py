import os
import matplotlib.pyplot as plt
import json

import time
from multiprocessing import Pool, Process

from Rabin3DES._128 import RabinFile3DES128_CBC64
from RabinAES._128 import RabinFileAES128_CBC128, RabinFileAES128_CTR128, RabinFileAES128_GCM128, RabinFileAES128_GCM512
from RabinAES._192 import RabinFileAES192_CBC128
from RabinAES._256 import RabinFileAES256_CBC128
from RabinARC4._128 import RabinFileARC4_128
from RabinBlowfish._128 import RabinFileBlowfish128_CBC64
from RabinCAST5._128 import RabinFileCAST5_128_CBC64
from RabinCamellia._128 import RabinFileCamellia128_CBC128
from RabinSEED._128 import RabinFileSEED128_CBC128
from inneSkroty import MD4_file, MD5_file, SHA1_file, SHA256_file, SHA512_file, Ripemd160_file, Whirlpool_file


class Profiler(object):
    def __init__(self):
        self.profiler_dir = 'profile_data'
        self.rozszerzenie_pliku = 'bin'
        self.pliki = os.listdir(self.profiler_dir)
        self.pliki = [p for p in self.pliki if '.bin' in p]
        self.pliki.sort(key=lambda a: int(a.split('.')[0]))
        self.wszystkie_rabiny = [RabinFile3DES128_CBC64,
                            RabinFileAES128_CBC128,
                            RabinFileAES128_CTR128,
                            RabinFileAES128_GCM128,
                            RabinFileAES128_GCM512,
                            RabinFileAES192_CBC128,
                            RabinFileAES256_CBC128,
                            RabinFileARC4_128,
                            RabinFileBlowfish128_CBC64,
                            RabinFileCAST5_128_CBC64,
                            RabinFileCamellia128_CBC128,
                            RabinFileSEED128_CBC128]
        self.wszystkie_inne = [MD4_file,
                          MD5_file,
                          SHA1_file,
                          SHA256_file,
                          SHA512_file,
                          Ripemd160_file,
                          Whirlpool_file]


    def generuj_pliki(self, potega_od=0, potega_do=33):
        for waga in [2**n for n in range(potega_od, potega_do)]:
            nazwa = '.'.join([str(waga), self.rozszerzenie_pliku])
            sciezka = os.path.join(self.profiler_dir, nazwa)
            self._generuj_plik(waga_bajty=waga, sciezka=sciezka)

    def _generuj_plik(self, waga_bajty, sciezka):
        with open(sciezka, 'wb') as f:
            f.write(os.urandom(waga_bajty))

    def filtruj_nazwe(self, int):
        kB = 2**10
        MB = 2**20
        GB = 2**30
        if int > GB:
            return str(int / GB) + ' GB'
        if int > MB:
            return str(int/MB) + ' MB'
        if int > kB:
            return str(int/kB)+' kB'
        return str(int) + ' B'

    def statystyki_1_watek(self):
        self.statystyki_wydzielone_pliki(self.pliki)

    def statystyki_kilka_procesow(self):
        p1 = Process(target=self.statystyki_wydzielone_pliki, args=(self.pliki[:-7],))
        p2 = Process(target=self.statystyki_wydzielone_pliki, args=([self.pliki[-1]],))
        p3 = Process(target=self.statystyki_wydzielone_pliki, args=([self.pliki[-2]],))
        p4 = Process(target=self.statystyki_wydzielone_pliki, args=([self.pliki[-3]],))
        p5 = Process(target=self.statystyki_wydzielone_pliki, args=([self.pliki[-4]],))
        p6 = Process(target=self.statystyki_wydzielone_pliki, args=([self.pliki[-5]],))
        p7 = Process(target=self.statystyki_wydzielone_pliki, args=([self.pliki[-6]],))
        p8 = Process(target=self.statystyki_wydzielone_pliki, args=([self.pliki[-7]],))
        procesy = [p1, p2, p3, p4, p5, p6, p7, p8]
        for p in procesy:
            p.start()
        for p in procesy:
            p.join()
        print "KONIEC_LICZENIA_HASZY"

    def statystyki_wydzielone_pliki(self, pliki, rabiny=None, inne=None):
        if rabiny == None:
            rabiny = self.wszystkie_rabiny
        if inne == None:
            inne = self.wszystkie_inne
        for plik in pliki:
            slownik = {}
            sciezka_bin = self.profiler_dir + '/' + plik
            sciezka_stat = sciezka_bin.split('.')[0] + '.stat'
            print "poczatek ", sciezka_stat
            try:
                for rabin in rabiny:
                    r = rabin('niewazne_co_tu_jest')
                    slownik[self._nazwa_klasy(r)] = {}
                    for chunk in [1024, 1048576]:
                        r = rabin(file=sciezka_bin, file_chunk=1024, skrot_size=32)
                        slownik[self._nazwa_klasy(r)]['file_chunk_' + str(chunk)] = self.mierz_czas(r)
                for inny in inne:
                    r = inny(sciezka=sciezka_bin)
                    slownik[self._nazwa_klasy(r)] = self.mierz_czas(r)
            except Exception as e:
                print "Obsluga wyjatku"
                with open(sciezka_stat, 'wt') as f:
                    json.dump(slownik, f, indent=4)
                raise e
            with open(sciezka_stat, 'wt') as f:
                slownik['waga_pliku'] = self.filtruj_nazwe(int(plik.split('.')[0]))
                json.dump(slownik, f, indent=4)
            print "koniec ",sciezka_stat

    def mierz_czas(self, skroter):
        start = time.time()
        skrot = skroter.skrot()
        end = time.time()
        return {'skrot': skrot, 'czas': end - start}


    def _nazwa_klasy(self, obiekt):
        return str(obiekt.__class__).split('.')[-1].split("'")[0].replace("File", "").replace("_file", '')

    def rysuj_rabiny_128(self):
        pliki_wszystkie = os.listdir(self.profiler_dir)
        pliki = [p for p in pliki_wszystkie if '.stat' in p]
        pliki.sort(key=lambda a: int(a.split('.')[0]))
        plt.grid(True)
        plt.ylabel('czas [s]')
        plt.xlabel('waga pliku')
        plt.title('Rabiny z roznymi algorytmami szyfrujacymi')

        skroty = [(RabinFile3DES128_CBC64, 'r'),
                  (RabinFileAES128_CBC128, 'g'),
                  (RabinFileARC4_128, 'b'),
                  (RabinFileBlowfish128_CBC64, 'y'),
                  (RabinFileCAST5_128_CBC64, 'k'),
                  (RabinFileCamellia128_CBC128, 'm'),
                  (RabinFileSEED128_CBC128,'c')]
        for skrot in skroty:
            czas = []
            waga = []
            s = self._nazwa_klasy(skrot[0]('cokolwiek'))
            for file in pliki:
                json_stat = self.profiler_dir + '/' + file
                with open(json_stat, 'rt') as f:
                    slownik = json.load(f)
                    czas.append(slownik[s]['file_chunk_1048576']['czas'])
                    waga.append(int(file.split('.')[0]))
            plt.plot(waga, czas, skrot[1]+'.-', label=s)
            plt.legend(loc = 2)
            # plt.plot(waga, czas, color=skrot[0])
        plt.savefig('rabiny128')

    def rysuj_aesy(self):
        pliki_wszystkie = os.listdir(self.profiler_dir)
        pliki = [p for p in pliki_wszystkie if '.stat' in p]
        pliki.sort(key=lambda a: int(a.split('.')[0]))
        plt.grid(True)
        plt.ylabel('czas [s]')
        plt.xlabel('waga pliku')
        plt.title('RabinyAES z roznymi dlugosciami klucza')

        skroty = [(RabinFileAES192_CBC128, 'r'),
                  (RabinFileAES128_CBC128, 'g'),
                  (RabinFileAES256_CBC128, 'b')]
        for skrot in skroty:
            czas = []
            waga = []
            s = self._nazwa_klasy(skrot[0]('cokolwiek'))
            for file in pliki:
                json_stat = self.profiler_dir + '/' + file
                with open(json_stat, 'rt') as f:
                    slownik = json.load(f)
                    czas.append(slownik[s]['file_chunk_1048576']['czas'])
                    waga.append(int(file.split('.')[0]))
            plt.plot(waga, czas, skrot[1] + '.-', label=s)
            plt.legend(loc=2)
        plt.savefig('aesy_rozne_klucze')

    def rysuj_aesy_128_rozne_tryby(self):
        pliki_wszystkie = os.listdir(self.profiler_dir)
        pliki = [p for p in pliki_wszystkie if '.stat' in p]
        pliki.sort(key=lambda a: int(a.split('.')[0]))
        # plt.xscale('log', basex=2)
        # plt.yscale('log', basey=2)
        plt.grid(True)
        plt.ylabel('czas [s]')
        plt.xlabel('waga pliku')
        plt.title('RabinyAES128 z roznymi trybami')

        skroty = [(RabinFileAES128_GCM512, 'r'),
                  (RabinFileAES128_CBC128, 'g'),
                  (RabinFileAES128_GCM128, 'b'),
                  (RabinFileAES128_CTR128, 'y')]
        for skrot in skroty:
            czas = []
            waga = []
            s = self._nazwa_klasy(skrot[0]('cokolwiek'))
            for file in pliki:
                json_stat = self.profiler_dir + '/' + file
                with open(json_stat, 'rt') as f:
                    slownik = json.load(f)
                    czas.append(slownik[s]['file_chunk_1048576']['czas'])
                    waga.append(int(file.split('.')[0]))
            plt.plot(waga, czas, skrot[1] + '.-', label=s)
            plt.legend(loc=2)
            # plt.plot(waga, czas, color=skrot[0])
        plt.savefig('rabinyAES128_rozne_tryby')

    def rysuj_inne(self):
        pliki_wszystkie = os.listdir(self.profiler_dir)
        pliki = [p for p in pliki_wszystkie if '.stat' in p]
        pliki.sort(key=lambda a: int(a.split('.')[0]))
        # plt.xscale('log', basex=2)
        plt.grid(True)
        plt.ylabel('czas [s]')
        plt.xlabel('waga pliku')
        plt.title('Inne skroty')

        skroty = [(MD4_file, 'r'),
                  (MD5_file, 'g'),
                  (SHA1_file, 'b'),
                  (SHA256_file, 'y'),
                  (SHA512_file, 'c'),
                  (Ripemd160_file, 'm'),
                  (Whirlpool_file, 'k')]
        for skrot in skroty:
            czas = []
            waga = []
            s = self._nazwa_klasy(skrot[0]('cokolwiek'))
            for file in pliki:
                json_stat = self.profiler_dir + '/' + file
                with open(json_stat, 'rt') as f:
                    slownik = json.load(f)
                    czas.append(slownik[s]['czas'])
                    waga.append(int(file.split('.')[0]))
            plt.plot(waga, czas, skrot[1] + '.-', label=s)
            plt.legend(loc=2)
            # plt.plot(waga, czas, color=skrot[0])
        plt.savefig('inne')

    def rysuj_whirlpool_aes256(self):
        pliki_wszystkie = os.listdir(self.profiler_dir)
        pliki = [p for p in pliki_wszystkie if '.stat' in p]
        pliki.sort(key=lambda a: int(a.split('.')[0]))
        # plt.xscale('log', basex=2)
        # plt.yscale('log', basey=2)
        plt.grid(True)
        plt.ylabel('czas [s]')
        plt.xlabel('waga pliku')
        plt.title('Najszybszy rabin i najwolniejszy inny')

        skroty = [(RabinFileAES256_CBC128, 'c'),
                  (Whirlpool_file, 'r')]
        for skrot in [skroty[0]]:
            czas = []
            waga = []
            s = self._nazwa_klasy(skrot[0]('cokolwiek'))
            for file in pliki:
                json_stat = self.profiler_dir + '/' + file
                with open(json_stat, 'rt') as f:
                    slownik = json.load(f)
                    czas.append(slownik[s]['file_chunk_1048576']['czas'])
                    waga.append(int(file.split('.')[0]))
            plt.plot(waga, czas, skrot[1] + '.-', label=s)
            plt.legend(loc=2)
        for skrot in [skroty[1]]:
            czas = []
            waga = []
            s = self._nazwa_klasy(skrot[0]('cokolwiek'))
            for file in pliki:
                json_stat = self.profiler_dir + '/' + file
                with open(json_stat, 'rt') as f:
                    slownik = json.load(f)
                    czas.append(slownik[s]['czas'])
                    waga.append(int(file.split('.')[0]))
            plt.plot(waga, czas, skrot[1] + '.-', label=s)
            plt.legend(loc=2)
        plt.savefig('whirlpool_aes_256')

if __name__ == '__main__':
    pro = Profiler()
    # pro.generuj_pliki(potega_od=0, potega_do=30)
    # print [pro.filtruj_nazwe(2**n) for n in range(0,32)]
    # pro.statystyki_1_watek()

    # pro.statystyki_kilka_procesow()

    # plt.xscale('log', basex=2)
    # plt.yscale('log', basey=2)

    # ODPALAC KAZDY POJEDYNCZO BO INACZEJ RYSUJA SIE JAKOS NAWZAJEM PO SOBIE
    # pro.rysuj_rabiny_128()
    # pro.rysuj_aesy()
    # pro.rysuj_aesy_128_rozne_tryby()
    # pro.rysuj_inne()
    # pro.rysuj_whirlpool_aes256()
