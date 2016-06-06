import os


class Profiler(object):
    def __init__(self):
        self.profiler_dir = 'profile_data'
        self.rozszerzenie_pliku = 'bin'

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


if __name__ == '__main__':
    pro = Profiler()
    # pro.generuj_pliki(potega_od=0, potega_do=30)
    print [pro.filtruj_nazwe(2**n) for n in range(0,32)]
