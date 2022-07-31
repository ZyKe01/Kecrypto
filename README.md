# 创新创业实践

小组成员：赵贇珂  

git账户：ZyKe01  

#### 完成的项目

##### SM3

implement the Rho method of reduced SM3.  

implement length extension attack for SM3, SHA256, etc.  

##### SM2

report on the application of this deduce technique in Ethereum with ECDSA.  

impl sm2 with RFC6979.  

verify the above pitfalls with proof-of-concept code.  

implement the above ECMH scheme.  

implement a PGP scheme with SM2.

implement sm2 2P sign with real network communication.  

##### Bitcoin

send a tx on  Bitcoin testnet, and  parse the tx data down  to every bit, better  write script yourself.  

forge a signature to pretend that you are Satoshi.  

#### 未完成的项目

implement the naïve birthday attack of reduced SM3.(实现了Rho)  

do your best to optimize SM3 implementation (software).  

Impl Merkle Tree following RFC6962.  

implement sm2 2P decrypt with real network communication.  

PoC impl of the scheme, or do implement analysis by Google.  

Real World Cryptanalyses

Real World zk-SNARKs

## 代码说明

本项目代码基于OpenSSL库，其中国密算法的源代码引用互联网

## SM3

#### implement the Rho method of reduced SM3.  

代码位置[Kecrypto](https://github.com/ZyKe01/Kecrypto)/**SM3**/sm3.cpp  

函数birthday()为生日攻击代码，设置要寻找的碰撞长度length（以字节为单位），选择初始输入$x_1=x_2=x_0$，用两个变量$x_1$和$x_2$记录中间值，$x_1$每次进行一次哈希，$x_2$每次进行两次哈希。即每次循环$x_1=H(x_1), x_2=H(H(x_2))$直到$x_1=x_2$



```c++
for (i;; i++) {
	EVP_Digest(x1, x1_len, x1, &x1_len, EVP_sm3(), NULL);
	x1_len = length;	//只要求前length字节相同

	EVP_Digest(x2, x2_len, x2, &x2_len, EVP_sm3(), NULL);
	x2_len = length;	//只要求前length字节相同
	EVP_Digest(x2, x2_len, x2, &x2_len, EVP_sm3(), NULL);
	x2_len = length;	//只要求前length字节相同

	if (!memcmp(x1, x2, length)) {
		printf("存在%dbytes相同\n", length);
		memcpy(x2, x1, x1_len);
		memcpy(x1, x0, x0_len);
		x2_len = x1_len;
		x1_len = x0_len;
		break;
	}
}
```


然后再计算第一次相等的值即找到碰撞



```c++
for (unsigned long long j = 1; j <= i; j++) {
	EVP_Digest(x1, x1_len, out1, &out1_len, EVP_sm3(), NULL);
	out1_len = length;
	EVP_Digest(x2, x2_len, out2, &out2_len, EVP_sm3(), NULL);
	out2_len = length;
	if (!memcmp(out1, out2, length)) {
		memcpy(str1, x1, x1_len);
		memcpy(str2, x2, x2_len);
		printf("j:%lld\n", j);
		return 1;
	}
	memcpy(x1, out1, out1_len);
	memcpy(x2, out2, out2_len);
	x1_len = out1_len;
	x2_len = out2_len;
}
```


代码运行结果如下

<img src="image\image-20220727123352617.png" alt="image-20220727123352617" />

最终找到最长的碰撞是64bit

**0e fa a7 c8 f5 06 29 81 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00**

**的哈希值为**

**f0 9d d5 66 2e cd 5d 94 7e ce d3 49 b0 58 85 ff a9 99 81 43 63 cd 94 5c 33 95 e8 e7 3f 8d 7a f9**



**4a 66 c6 3b 69 30 48 5c 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00**

**的哈希值为**

**f0 9d d5 66 2e cd 5d 94 d0 31 6d c6 6a 3e db b1 2a 14 3b 64 3e 69 3c ae 68 16 7f 17 63 54 c3 3b**
#### implement length extension attack for SM3, SHA256, etc

SM3和SHA256算法使用Merkel-Damgard结构，存在长度扩展攻击。以SM3为例，便于展示，对消息填充进行修改，不在消息后填充消息长度，并且只选择特定长度的消息。

选取消息$M_1,M_2$和$M_3=M_1||M_2$，首先计算$H(M_1)$得到$H_1$，并将$H_1$作为哈希函数的初始向量计算$M_2$的哈希值，得到消息$M_3$的哈希值。

<img src="image\image-20220727152708656.png" alt="image-20220727152708656" style="zoom:67%;" />

使用前一个消息块的输出作为后一个消息块的初始向量

```c++
unsigned char buf[4];
for (int i = 0; i < 8; i++) {
	memcpy(buf, IV + 3 + 4 * i, 1);
	memcpy(buf + 1, IV + 2 + 4 * i, 1);
	memcpy(buf + 2, IV + 1 + 4 * i, 1);
	memcpy(buf + 3, IV + 0 + 4 * i, 1);
	memcpy(&ctx->digest[i], buf, 4);
}
	
ctx->nblocks = 0;
ctx->num = 0;
```

构造消息块$M_1,M_2,M_3=M_1||M_2$

```c++
memset(a, 0x3f, 64);
memset(b, 0xbc, 64);
memset(c, 0x3f, 64);
memset(c + 64, 0xbc, 64);
```

运行结果，输出相同：

<img src="image\image-20220727154257569.png" alt="image-20220727154257569" style="zoom:67%;" />

以上两个实验都在main()中提供实例



## SM2

#### impl sm2 with RFC6979.  

一种生成随机数的方式，使用SM3作为哈希函数

```pseudocode
h1 = H(m)
V = 0x01 0x01 0x01 ... 0x01
K = 0x00 0x00 0x00 ... 0x00
K = HMAC_K(V||0x00||int2octets(x)||bits2octets(h1))	//x是私钥
V = HMAC_K(V)
K = HMAC_K(V||0x01||int2octets(x)||bits2octets(h1))
V = HMAC_K(V)
while(){
	//初始T为空，tlen=0
	while(tlen < qlen){
		V = HMAC_K(V)
		T = T || V
	}
	k = bits2int(T)
	if(k > 1 && k < q-1)
		return k
	else{
		K = HMAC_K(V||0x00)
		V = HMAC_(V)
	}
}
```

以上具体代码在sm2_sign_and_verify.h中的generate_k_rand()函数。修改随机数k后的签名方案在sm2_sign_and_verify_example.h中提供实例代码，在源.cpp中

```c++
if (example()) {
    printf("BBBBBBBBBBBBBBBBBBBBBBBBBBig failure!\n");
}
printf("BBBBBBBBBBBBBBBBBBBBBBBBBBig success!\n");
```

调用了该函数

<img src="image\image-20220727180313223.png" alt="image-20220727180313223" style="zoom: 67%;" />

#### verify the above pitfalls with proof-of-concept code.  

###### Leaking $k$ leads to leaking of $d$

- Compute $d_A$ with $\sigma=(r,s)$ and $k$
- $s=((1+d_A)^{-1}(k-rd_A))\mod n$
- $s(1+d_A)=(k-rd_A)\mod n$
- $d_A=(s+r)^{-1}(k-s)\mod n$

改写签名函数让我们可以得到签名所用的$k$，然后按照上面步骤恢复私钥$d$

```c++
BN_bin2bn(key_pair->pri_key, 32, bn_d);
BN_bin2bn(sig.r_coordinate, 32, r);
BN_bin2bn(sig.s_coordinate, 32, s);
BN_mod_add(r, s, r, n, ctx);
BN_mod_inverse(r, r, n, ctx);
BN_mod_sub(s, k, s, n, ctx);
BN_mod_mul(d, r, s, n, ctx);
if (BN_cmp(d,bn_d) == 0) {
	printf("Success!  We've got the private key!\n");
	return 1;
}
printf("Failure!\n");
return 0;
```

###### Reusing $k$ leads to leaking of $d$

- Recover $d_A$ with 2 signatures $(r_1,s_1),(r_2,s_2)$
- $s_1(1+d_A)=(k-r_1d_A)\mod n$
- $s_2(1+d_A)=(k-r_2d_A)\mod n$
- $d_A=\frac{s_2-s_1}{s_1-s_2+r_1-r_2}\mod n$

按照上面步骤恢复私钥$d$

```c++
BN_mod_sub(tmp, s2, s1, n, ctx);
BN_mod_sub(s1, s1, s2, n, ctx);
BN_mod_sub(r1, r1, r2, n, ctx);
BN_mod_add(s1, s1, r1, n, ctx);
BN_mod_inverse(s1, s1, n, ctx);
BN_mod_mul(d, tmp, s1, n, ctx);
if (BN_cmp(d, bn_d) == 0) {
	printf("Success!  We've got the private key!\n");
	return 1;
}
printf("Failure!\n");
return 0;
```

###### Two users, using $k$ leads to leaking of $d$, that is they  can deduce each other’s $d$

- Alice can deduce Bob's secret key
- $d_B=\frac{k-s_2}{s_2+r_2}$
- Bob can deduce Alice's secret key
- $d_A=\frac{k-s_1}{s_1+r_1}$

按照上面步骤恢复私钥$d$

```c++
BN_mod_add(r2, s2, r2, n, ctx);
BN_mod_inverse(r2, r2, n, ctx);
BN_mod_sub(s2, k, s2, n, ctx);
BN_mod_mul(d2, r2, s2, n, ctx);
BN_mod_add(r1, s1, r1, n, ctx);
BN_mod_inverse(r1, r1, n, ctx);
BN_mod_sub(s1, k, s1, n, ctx);
BN_mod_mul(d1, r1, s1, n, ctx);
```

###### Malleability, e.g. $(r,s)$ and $(r,-s)$ are both valid  signatures, lead to blockchain network split

```c++
/*signature (r,-s)*/
ECDSA_SIG* sig1 = NULL;
sig1 = ECDSA_SIG_new();
ECDSA_SIG_set0(sig1, r, s);

if (ECDSA_do_verify(msg, msg_len, sig1, ECDSA_key) != 1) {
	printf("Verifying failed!\n");
	return 0;
}
printf("Verifying succeed!\n");
return 1;
```

###### One can forge signature if the verification does not  check $m$

该实验与forge a signature to pretend that you are Satoshi相同，这里不详细描述，具体方法和代码见Bitcoin章节

上述实验示例代码在[Kecrypto](https://github.com/ZyKe01/Kecrypto)/**SM2**/pitfalls.h，在源.cpp中调用

```c++
printf("Leaking k leads to leaking of d!\n");
test_leaking_k();

printf("\n\n");
printf("Reusing k leads to leaking of d!\n");
test_reusing_k();

printf("\n\n");
printf("Reusing k by different users!\n");
test_reusing_k2();

printf("\n\n");
printf("Malleability!\n");
test_malleability();
```

运行结果：

<img src="image\image-20220727184018900.png" alt="image-20220727184018900" style="zoom:67%;" />

#### Implement the above ECMH scheme

将字符串哈希到椭圆曲线上的点，将哈希值作为横坐标，如果椭圆曲线上没有该横坐标的点，令横坐标加一

```c++
while (!EC_POINT_set_compressed_coordinates(group, point, coordinate_x, 0, NULL)) {
	BIGNUM* one = BN_new();
	BN_one(one);
	//try and increment
	BN_add(coordinate_x, coordinate_x, one);
}
```

然后我们就可以实现同态哈希，哈希集合中添加元素就是点的相加，移除元素就是点的相减

```c++
/*哈希集合中新的元素*/
int MultiSet_Hash_Update(EC_GROUP* group, EC_POINT* point, const unsigned char* msg, const unsigned int msg_len)
{
	EC_POINT* new_point = EC_POINT_new(group);
	if (hash2point(msg, msg_len, group, new_point)) {
		printf("Hash success!\n");
		EC_POINT_add(group, point, point, new_point, NULL);
		return 1;
	}
	return 0;
}

/*去除集合中元素*/
int MultiSet_Hash_Remove(EC_GROUP* group, EC_POINT* point, const unsigned char* msg, const unsigned int msg_len)
{
	EC_POINT* new_point = EC_POINT_new(group);
	if (hash2point(msg, msg_len, group, new_point)) {
		printf("Hash success!\n");
		EC_POINT_invert(group, new_point, NULL);
		EC_POINT_add(group, point, point, new_point, NULL);
		return 1;
	}
	return 0;
}
```

上述代码和代码实例在[Kecrypto](https://github.com/ZyKe01/Kecrypto)/[SM2](https://github.com/ZyKe01/Kecrypto/tree/main/SM2)/**elliptic_curve_multiset_hash.h**，并在源.cpp

调用了实例代码，运行结果：

<img src="image\image-20220727212306115.png" alt="image-20220727212306115" style="zoom:67%;" />

#### implement a PGP scheme with SM2.

生成会话用的对称密钥

```c++
BN_rand_range(r, range);
unsigned char key[16];
BN_bn2bin(r, key);
```

用会话密钥加密数据，并用接收方的公钥加密会话密钥

```c++
sm2_encrypt(key, 16, pub_key, c1, c3, c2);
```

接收方收到密文，先用自己的私钥解密出会话密钥

```c++
sm2_decrypt(c1, c3, c2, c2_len, pri_key, key);
```

再用会话密钥解密出消息明文。以上代码和示例在[Kecrypto](https://github.com/ZyKe01/Kecrypto)/[SM2](https://github.com/ZyKe01/Kecrypto/tree/main/SM2)/**PGP.h**，运行结果

<img src="image\image-20220730211248462.png" alt="image-20220730211248462" style="zoom:67%;" />

#### implement sm2 2P sign with real network communication.  

<img src="image\image-20220731101839584.png" alt="image-20220730211248462" />

等价于私钥为$d=(d_1d_2)^{-1}-1$公钥为$P=[(d_1d_2)^{-1}-1]G$的SM2签名

代码位于[Kecrypto](https://github.com/ZyKe01/Kecrypto)/[SM2](https://github.com/ZyKe01/Kecrypto/tree/main/SM2)/**server.py**和[Kecrypto](https://github.com/ZyKe01/Kecrypto)/[SM2](https://github.com/ZyKe01/Kecrypto/tree/main/SM2)/**client.py**运行结果

<img src="image\image-20220731102207778.png" alt="image-20220730211248462" />

<img src="image\image-20220731102219897.png" alt="image-20220730211248462" />

## Bitcoin

#### send a tx on  Bitcoin testnet, and  parse the tx data down  to every bit, better  write script yourself 

<img src="image\image-20220730211948179.png" alt="image-20220730211948179" style="zoom:67%;" />

对于以下交易

<img src="image\image-20220730212357046.png" alt="image-20220730212357046" style="zoom:67%;" />

<img src="image\image-20220730212526493.png" alt="image-20220730212526493" style="zoom:67%;" />

我们对其原始数据进行解析，结果如下

<img src="image\image-20220730212613352.png" alt="image-20220730212613352" style="zoom:67%;" />

####  forge a signature to pretend that you are Satoshi

$\sigma=(r,s)$是消息$m$关于私钥$d$的合法签名，如果不检查签名的消息只检查消息的哈希值，我们可以伪造签名。

**choose $u,v\in F_n^*$**

**$R'=(x',y')=uG+vP$**

**choose $r'=x'\mod n$**

**$e'=r'u^{-1}\mod n$**

**$s'=r'v^{-1}\mod n$**

```c++
//compute R'
EC_POINT_mul(group, R, u, P, v, NULL);
//get x'
EC_POINT_get_affine_coordinates(group, R, x, y, NULL);
//compute e and s
BN_mod_inverse(v, v, n, ctx);
BN_mod_mul(e, r, u, n, ctx);
BN_mod_mul(e, e, v, n, ctx);
BN_mod_mul(s, r, v, n, ctx);
//create signature
ECDSA_SIG_set0(sig, r, s);
```

代码和示例在[Kecrypto](https://github.com/ZyKe01/Kecrypto)/[Bitcoin](https://github.com/ZyKe01/Kecrypto/tree/main/Bitcoin)/**forge_signature.h**

运行结果

<img src="image\image-20220730214321794.png" alt="image-20220730214321794" style="zoom: 80%;" />
