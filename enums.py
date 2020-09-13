import enum


class TypeEnum(enum.IntEnum):
    @classmethod
    def _missing_(cls, value):
        obj = int.__new__(cls, value)
        obj._name_ = f'{cls.__name__}_{value}'
        obj._value_ = value
        return obj


class DhId(TypeEnum):
    DH_NONE = 0
    DH_1 = 1
    DH_2 = 2
    DH_5 = 5
    DH_14 = 14
    DH_15 = 15
    DH_16 = 16
    DH_17 = 17
    DH_18 = 18
    DH_19 = 19
    DH_20 = 20
    DH_21 = 21
    DH_22 = 22
    DH_23 = 23
    DH_24 = 24
    DH_25 = 25
    DH_26 = 26
    DH_27 = 27
    DH_28 = 28
    DH_29 = 29
    DH_30 = 30
    DH_31 = 31
    DH_32 = 32

