from rabin import RabinAES, RabinFile

class RabinAES192(RabinAES):
    def __init__(self):
        super(RabinAES192, self).__init__(key_size=24)