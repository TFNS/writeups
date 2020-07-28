import dis
import types


def define_func(argcount, nlocals, code, consts, names):
    # PYTHON3.8!!!
    def inner():
        return 0

    fn_code = inner.__code__
    cd_new = types.CodeType(argcount,
                            0,
                            fn_code.co_kwonlyargcount,
                            nlocals,
                            1024,
                            fn_code.co_flags,
                            code,
                            consts,
                            names,
                            tuple(["v%d" %i for i in range(nlocals)]),
                            fn_code.co_filename,
                            fn_code.co_name,
                            fn_code.co_firstlineno,
                            fn_code.co_lnotab,
                            fn_code.co_freevars,
                            fn_code.co_cellvars)
    inner.__code__ = cd_new
    return inner


f1 = define_func(2, 2, b'|\x00|\x01k\x02S\x00', (None,), ())
f2 = define_func(1, 1, b't\x00|\x00\x83\x01S\x00', (None,), ('ord',))
f3 = define_func(0, 0, b't\x00d\x01\x83\x01S\x00', (None, 'Give me flag: '), ('input',))
f4 = define_func(1, 3,
                 b'd\x01d\x02d\x03d\x04d\x05d\x01d\x06d\x07d\x08d\td\x03d\nd\x0bd\x0cd\rd\x08d\x0cd\x0ed\x0cd\x0fd\x0ed\x10d\x11d\td\x12d\x03d\x10d\x03d\x0ed\x13d\x0bd\nd\x14d\x08d\x13d\x01d\x01d\nd\td\x01d\x12d\x0bd\x10d\x0fd\x14d\x03d\x0bd\x15d\x16g1}\x01t\x00|\x00\x83\x01t\x00|\x01\x83\x01k\x03r\x82t\x01d\x17\x83\x01\x01\x00d\x18S\x00t\x02|\x00|\x01\x83\x02D\x00]$}\x02t\x03|\x02d\x19\x19\x00t\x04|\x02d\x1a\x19\x00\x83\x01\x83\x02d\x18k\x02r\x8c\x01\x00d\x18S\x00q\x8cd\x1bS\x00',
                 (None, 99, 121, 98, 114, 105, 115, 123, 52, 97, 100, 51, 101, 55, 57, 53, 54, 48, 49, 50, 56, 102, 125, 'Length mismatch!', False, 1, 0, True),
                 ('len', 'print', 'zip', 'f1', 'f2'))
f5 = define_func(0, 1, b't\x00\x83\x00}\x00t\x01|\x00\x83\x01d\x01k\x08r\x1ct\x02d\x02\x83\x01\x01\x00n\x08t\x02d\x03\x83\x01\x01\x00d\x00S\x00',
                 (None, False, 'Nope!', 'Yep!'), ('f3', 'f4', 'print'))
f5()
