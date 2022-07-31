import socket
import sys
import random
import sm2
from pysmx.SM3 import digest as sm3

ID = '1990314710@qq.com'
M = 'Are you watching closely?'

n = sm2.SM2_n
ecc = sm2.ECC(p=sm2.SM2_p, a=sm2.SM2_a, b=sm2.SM2_b, n=sm2.SM2_n, G=(sm2.SM2_Gx, sm2.SM2_Gy))

#P1=d1^(-1)G
d1 = random.randint(1, n - 1)
d1_inv = sm2.get_inverse(d1, n)
P1 =  ecc.Jacb_multiply(d1_inv, ecc.G)
print(P1)
#Alice=sm2.SM2(ID=ID,sk=d1,pk=P1)

##M_ = sm2.join_bytes([Alice.get_Z(), M])
##e = sm2.to_int(sm3(M_))
##k = random.randint(1, n - 1)
##x1,y1=ecc.Jacb_multiply(k, ecc.G)
##r = (e+x1)%n
##s = (sm2.get_inverse(1 + d1, n))*(k-r*d1)%n
##Bob=sm2.SM2()
##print(Bob.verify(M,(r,s),ID,P1))


HOST = '127.0.0.1'
PORT = 50007
so = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    so.connect((HOST, PORT))
except Exception as e:
    print('Server not found or not open')
    sys.exit()
while True:
    so.sendall((str(P1[0])+'_'+str(P1[1])).encode())
    data = so.recv(1024).decode()
    data = data.split('_')
    P = (int(data[0]), int(data[1]))
    print('Received:', P)
    Alice=sm2.SM2(ID=ID, pk=P)
    M_ = sm2.join_bytes([Alice.get_Z(ID=ID,P=P), M])
    e = sm2.to_int(sm3(M_))
    k1 = random.randint(1, n - 1)
    Q1 = ecc.Jacb_multiply(k1, ecc.G)
    so.sendall((str(Q1[0])+'_'+str(Q1[1])+'_'+str(e)).encode())

    data = so.recv(1024).decode()
    data = data.split('_')
    r,s2,s3 = int(data[0]), int(data[1]), int(data[2])
    s = ((d1 * k1) * s2 + d1 * s3 - r) % n
    if s != 0 and s != n-r:
        print(r, s)
    so.sendall('bye'.encode())
    break
so.close()

##验证签名
Carol=sm2.SM2()
if(Carol.verify(M,(r,s),ID,P)):
    print('验证成功')
else:
    print('验证失败')
