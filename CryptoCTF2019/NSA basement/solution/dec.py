import Crypto
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher.PKCS1_OAEP import strxor, bchr, ceil_div, bord
from Crypto.Util.number import long_to_bytes, bytes_to_long
import gmpy2
import random
import datetime


_hashObj = Crypto.Hash.SHA
_mgf = lambda x,y: Crypto.Signature.PKCS1_PSS.MGF1(x,y, _hashObj)
def decrypt_fromPKCS(ct, d, n):
    # See 7.1.2 in RFC3447
    modBits = Crypto.Util.number.size(n)
    k = ceil_div(modBits, 8)  # Convert from bits to bytes
    hLen = _hashObj.digest_size

    # Step 1b and 1c
    if len(ct) != k or k < hLen + 2:
        raise ValueError("Ciphertext with incorrect length.")
    # Step 2a (O2SIP), 2b (RSADP), and part of 2c (I2OSP)
    # m = self._key.decrypt(ct)
    m = long_to_bytes(pow(bytes_to_long(ct), d, n))
    # Complete step 2c (I2OSP)
    em = bchr(0x00) * (k - len(m)) + m
    # Step 3a
    lHash = _hashObj.new('').digest()
    # Step 3b
    y = em[0]
    # y must be 0, but we MUST NOT check it here in order not to
    # allow attacks like Manger's (http://dl.acm.org/citation.cfm?id=704143)
    maskedSeed = em[1:hLen + 1]
    maskedDB = em[hLen + 1:]
    # Step 3c
    seedMask = _mgf(maskedDB, hLen)
    # Step 3d
    seed = strxor(maskedSeed, seedMask)
    # Step 3e
    dbMask = _mgf(seed, k - hLen - 1)
    # Step 3f
    db = strxor(maskedDB, dbMask)
    # Step 3g
    valid = 1
    one = db[hLen:].find(bchr(0x01))
    lHash1 = db[:hLen]
    if lHash1 != lHash:
        valid = 0
    if one < 0:
        valid = 0
    if bord(y) != 0:
        valid = 0
    if not valid:
        raise ValueError("Incorrect decryption.")
    # Step 4
    return db[hLen + one + 1:]


def bit_len(n):
    return (len(hex(n))-2) * 4


factors_97 = [
    0x9924a29bc79f3cda657327b37b96c679542ffa9aa5193ac447d9d320e0c94faf,
    0xce1a2b1f6f9baa2ab43c796c7ca14113aace4a02e6e31ecd97cbb9471b700ef7,
    0xe1e1d6e65c575bb597040a83d85f193ee4a35fff6edc3ef300cf566201e76413,
    0x2f16205d466405b4d631b3c5e177dce85d62d09482a65234707b76f8e29220d1181fed9a9343f9359d4bc1692c1b5f13cb4000873db2a8c8b7381ce3a8656d77734f67314ed70c987fc41376560e674133f465afda1f9ea42b5a44117866d051d,
    0x94c21c264f65fd298bad48e528bd882d8d4cd7fb436739ad7585178c6c204d95,
    0xbb5794796906fa730aed54e02880f9092e6d488bfc8f020acf0cb3d60446d88f,
]
factors_87 = [
    0xe5b4b1b65784b253f37e2677033aaebebdcf5eef0c52f4845c240e8a19aa91f3,
    0xe8ced45445808b948698238797a76b92c36a6490b22c260def7403963b6f0fe3,
    0x3bebbf0541192edc741ccb522d6888ee0701ecb5f2723b3cd59ffd09fc385a51f4ebb0af83c934362778b5c7ac3df8a0157bdb0b0d3b72d7ef4cadae5f4bcb99f8d6af4da4172d2df55a4a328a2f9ec133fad44c6af0f8845a75227b40ff63809,
    0xccbccc3ac19ec7b472311f3c9fe1acad2196093ba196104c2ad894818e1eca49,
    0xf7deac53ee40907cd4b186d88d04e96d4740a0e37678d4abffb405574ad9de21,
    0xfb6b690d83c20cc08fd16bcaa9277e412b7b855f6b7e59b40386d08a5589d7ab,
]


def decrypt(num_str, factors):
    with open('stuff\\keys\\pubkey_' + num_str + '.pem', 'r') as f:
        pubkey = RSA.importKey(f.read())
    
    n = getattr(pubkey, 'n')
    e = getattr(pubkey, 'e')
    print('e =', e)
    i = 1
    for p in factors:
        i *= p
    assert i == n
    
    with open('stuff\\enc\\flag_' + num_str + '.enc', 'rb') as f:
        c_bytes = f.read()
        c = bytes_to_long(c_bytes)
    print("n:", bit_len(n), " bits")
    print("c:", bit_len(c), " bits")
    print("c =", hex(c))
    
    phi = 1
    for p in factors:
        phi *= (p - 1)
    
    d = int(gmpy2.invert(e, phi))
    for _ in range(10):
        test_m = random.randint(2, n - 1)
        assert test_m == (pow(test_m, e * d, n))

    # key = RSA.construct((n, e, d))
    # cipher = PKCS1_OAEP.new(key)
    # m = cipher.decrypt(c_bytes)
    m = decrypt_fromPKCS(c_bytes, d, n)
    print(m)


decrypt('00097', factors_97)
decrypt('00087', factors_87)

