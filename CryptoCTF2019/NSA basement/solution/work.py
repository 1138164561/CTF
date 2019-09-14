from Crypto.PublicKey import RSA
from Crypto.Util.number import long_to_bytes, bytes_to_long
import gmpy2
import random
import datetime

FILE_NUM = 100


def get_now():
    return datetime.datetime.now().strftime('%Y%m%d-%H%M%S')


def bit_len(n):
    return (len(hex(n))-2) * 4


def bit_len_list(a):
    num = len(a)
    if 1 > num:
        return 0
    N = 100
    tot = 0
    for i in range(N):
        tot += bit_len(list(a)[random.randint(0, num - 1)])
    return tot/N


sessions_c = []
sessions_n = []
ancestor = dict()
divisor = dict()
for i in range(0, FILE_NUM):
    num = '%05d'%i
    with open('stuff\\keys\\pubkey_' + num + '.pem', 'r') as f:
        pubkey = RSA.importKey(f.read())
        n = getattr(pubkey, 'n')
        e = getattr(pubkey, 'e')
        if e != 65537:
            print(i)
    with open('stuff\\enc\\flag_' + num + '.enc', 'rb') as f:
        c = bytes_to_long(f.read())
    sessions_c.append(c)
    sessions_n.append(n)
    divisor[n] = set()
    ancestor[n] = set()
print("Reading files over.")
print(bit_len_list(sessions_c))
print(bit_len_list(sessions_n))


def full_divide(n, p):
    while 0 == n % p:
        n //= p
    return n


def link(n, p):
    if 1 == p:
        return
    if p not in ancestor.keys():
        ancestor[p] = set()
    if 0 == len(ancestor[n]):
        divisor[n].add(p)
        ancestor[p].add(n)
    else:
        for root in ancestor[n]:
            try: divisor[root].remove(n)
            except: pass
            divisor[root].add(p)
            ancestor[p].add(root)
            

level = 0
def recursive_gcd(pool, level):
    if 0 == len(pool):
        return
    print("level =", level, " size =", len(pool), "now: ", get_now())
    new_pool1 = set()
    new_pool2 = set()
    d = 1
    for i in pool:
        for j in pool:
            if i == j:
                continue
            if bit_len(i) < 260 or bit_len(i) < 260:
                continue
            d = int(gmpy2.gcd(i, j))
            if d == 1:
                continue
            new_pool1.add(d)
            qi = full_divide(i, d)
            qj = full_divide(j, d)
            new_pool2.add(qi)
            new_pool2.add(qj)
            link(i, d)
            link(j, d)
            link(i, qi)
            link(j, qj)
            d = 1
    recursive_gcd(new_pool1, level + 1)
    recursive_gcd(new_pool2, level + 1)
    

set256 = set()
setbig = set(sessions_n)
def new_gcd(set256, setbig):
    while True:
        width = bit_len_list(list(setbig))
        print("len(set256) =", len(set256), "\tlen(setbig) =", len(setbig), "now: ", get_now(),
              "\t", width, "bits")
        newset256 = set().union(set256)
        newsetbig = set().union(setbig)
        for p in set256:
            for big in setbig:
                if big not in newsetbig:
                    continue
                if 0 != big % p:
                    continue
                new_big = full_divide(big, p)
                link(big, p)
                link(big, new_big)
                for root in ancestor[p]:
                    divs = divisor[root]
                    if 7 <= len(divs):
                        f = open(get_now() + '_divisors.txt', 'w')
                        print('root =', root, '\n\t', )
                        for d in divs:
                            print(hex(d), end=',\n\t', file=f)
                        print()
                        f.close()
                newsetbig.remove(big)
                if 300 < bit_len(new_big):
                    newsetbig.add(new_big)
                else:
                    newset256.add(new_big)
            newset256.remove(p)
        set256 = set().union(newset256)
        setbig = set().union(newsetbig)
        
        print("Start gcd ", "now: ", get_now())
        finish_num = (width * 25 // 2048) + 2
        for i in sorted(list(setbig), reverse=True):
            for j in sorted(list(setbig), reverse=True):
                if i == j:
                    continue
                if bit_len(i) < 300 or bit_len(i) < 300:
                    continue
                d = int(gmpy2.gcd(i, j))
                if d != 1:
                    if bit_len(d) < 300:
                        set256.add(d)
                    else:
                        setbig.add(d)
            if len(set256) >= finish_num:
                break
        if 0 == len(set256):
            break

# new_gcd(set256, setbig)
recursive_gcd(sessions_n, 0)
f = open(get_now()+'_divisors.txt', 'w')
for i in range(FILE_NUM):
    divs = divisor[sessions_n[i]]
    print("i:", i, "\t\t", end='', file=f)
    for d in divs:
        print(bit_len(d), end=',\t', file=f)
    if 6 <= len(divs):
        print(end='\n\t', file=f)
        for d in divs:
            print(hex(d), end=',\n\t', file=f)
    print(file=f)
f.close()


