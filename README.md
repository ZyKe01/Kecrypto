# 创新创业实践

小组成员：赵贇珂  

git账户：ZyKe01  

#### 完成的项目

##### SM3

implement the Rho method of reduced SM3.  

implement length extension attack for SM3, SHA256, etc.  

##### SM2

impl sm2 with RFC6979.  

verify the above pitfalls with proof-of-concept code.  

implement the above ECMH scheme.  

implement a PGP scheme with SM2.

##### Bitcoin

send a tx on  Bitcoin testnet, and  parse the tx data down  to every bit, better  write script yourself.  

forge a signature to pretend that you are Satoshi.  

#### 未完成的项目

implement the naïve birthday attack of reduced SM3.(实现了Rho)  

do your best to optimize SM3 implementation (software).  

Impl Merkle Tree following RFC6962.  

report on the application of this deduce technique in Ethereum with ECDSA.  

 implement sm2 2P sign with real network communication.  

implement sm2 2P decrypt with real network communication.  

PoC impl of the scheme, or do implement analysis by Google.  

## 代码说明

本项目代码基于OpenSSL库，其中国密算法的源代码引用互联网

## SM3

#### implement the Rho method of reduced SM3.  

代码位置[Kecrypto](https://github.com/ZyKe01/Kecrypto)/**SM3**/sm3.cpp  

函数birthday()为生日攻击代码，设置要寻找的碰撞长度length（以字节为单位），选择初始输入$x_1=x_2=x_0$，用两个变量$x_1$和$x_2$记录中间值，$x_1$每次进行一次哈希，$x_2$每次进行两次哈希。即每次循环$x_1=H(x_1), x_2=H(H(x_2))$直到$x_1=x_2$

<img src="image\image-20220727123043443.png" alt="image-20220727123043443" width=350px />

然后再计算第一次相等的值即找到碰撞

<img src="image\image-20220727123207886.png" alt="image-20220727123207886" width=350px />

代码运行结果如下

<img src="image\image-20220727123352617.png" alt="image-20220727123352617" width=450px />

最终找到最长的碰撞是64bit

**0e fa a7 c8 f5 06 29 81 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00**

**的哈希值为**

**f0 9d d5 66 2e cd 5d 94 7e ce d3 49 b0 58 85 ff a9 99 81 43 63 cd 94 5c 33 95 e8 e7 3f 8d 7a f9**



**4a 66 c6 3b 69 30 48 5c 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00**

**的哈希值为**

**f0 9d d5 66 2e cd 5d 94 d0 31 6d c6 6a 3e db b1 2a 14 3b 64 3e 69 3c ae 68 16 7f 17 63 54 c3 3b**
