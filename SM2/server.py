import socket
import random
import sm2
from pysmx.SM3 import digest as sm3
from os.path import commonprefix

n = sm2.SM2_n
ecc = sm2.ECC(p=sm2.SM2_p, a=sm2.SM2_a, b=sm2.SM2_b, n=sm2.SM2_n, G=(sm2.SM2_Gx, sm2.SM2_Gy))

HOST = ''
PORT = 50007
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((HOST, PORT))
s.listen(1)
print('Listening on port:',PORT)
conn, addr = s.accept()
print('Connected by', addr)
while True:
    data = conn.recv(1024).decode()
    if not data: break
    data = data.split('_')
    P1 = (int(data[0]), int(data[1]))
    print('Received message:', P1, '\n')
    d2 = random.randint(1, n - 1)
    d2_inv = sm2.get_inverse(d2, n)
    P = ecc.Jacb_multiply(d2_inv, P1)
    P = ecc.add(P, ecc.minus(ecc.G))
    conn.sendall((str(P[0])+'_'+str(P[1])).encode())

    data = conn.recv(1024).decode()
    if not data: break
    data = data.split('_')
    Q1 = (int(data[0]), int(data[1]))
    e = int(data[2])
    k2 = random.randint(1, n - 1)
    k3 = random.randint(1, n - 1)
    Q2 = ecc.Jacb_multiply(k2, ecc.G)
    Q = ecc.Jacb_multiply(k3, Q1)
    x1, y1 = ecc.add(Q, Q2)
    r = (x1 + e) % n
    s2 = d2 * k3 % n
    s3 = d2 * (r + k2) % n
    conn.sendall((str(r)+'_'+str(s2)+'_'+str(s3)).encode())
    data = conn.recv(1024).decode()
    if data == 'bye':
        break
conn.close()
s.close()
