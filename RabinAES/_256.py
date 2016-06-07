from rabin import RabinAES, RabinFile

class RabinAES256(RabinAES):
    def __init__(self):
        super(RabinAES256, self).__init__(key_size=32)