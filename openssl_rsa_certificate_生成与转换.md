# Openssl RSA Certificate 生成与转换

***Notice*** IOS系统中 <CommonCrypto/CommonCrypto.h> 提供的 `SecKeyEncrypt` 和 `SecKeyDecrypt` 方法可用于 RSA 非对称加密，加密使用公钥，解密使用私钥。

该文件主要对使用 Openssl 生成私钥、公钥进行简要说明，主要内容来自网络，若有错误不当的地方，请指正。

Email: littocats@gmail.com
 
#### Openssl 文件及证书协议说明

* .key格式：私有的密钥
* .csr格式：证书签名请求（证书请求文件），含有公钥信息，certificate signing request的缩写
* .crt格式：证书文件，certificate的缩写
* .crl格式：证书吊销列表，Certificate Revocation List的缩写
* .pem格式：用于导出，导入证书时候的证书的格式，有证书开头，结尾的格式

* x509v3: IETF的证书标准
* x.500:目录的标准
* SCEP:  简单证书申请协议，用http来进行申请，数据有PKCS#7封装，数据其实格式也是PKCS#10的
* PKCS#7:  是封装数据的标准，可以放置证书和一些请求信息
* PKCS#10:  用于离线证书申请的证书申请的数据格式，注意数据包是使用PKCS#7封装这个数据
* PKCS#12:  用于一个单一文件中交换公共和私有对象，就是公钥，私钥和证书，这些信息进行打包，加密放在存储目录中，CISCO放在NVRAM中，用户可以导出，以防证书服务器挂掉可以进行相应恢复。思科是.p12,微软是.pfx

#### 生成证书的步骤

网上有很多“无交互全自动命令”，但对我这样的新手来说，很难理解生成的过程，为了弄清楚整个过程，我采用的是按部就班的行式，逐步生成。

* 生成CA自签名根证书
* 生成么钥 -> 生成证书请求 -> 通过CA签名得到证书

* 把证书转换为需要的格式

生成过和是在 mac 下进行的，对其它环境没有测试。

###### 工作目录下应包括以下文件夹：

./demoCA/ 

./demoCA/newcerts/ 

./demoCA/private/ 

./demoCA/index.txt (空文件，生成证书时会将数据记录写入)

./demoCA/serial （在serial文件中写入第一个序列号“01”，在生成证书时会以此递增)

***特别说明:***

1. 自签名证书(一般用于顶级证书、根证书): 证书的名称和认证机构的名称相同.
2. 根证书：根证书是CA认证中心给自己颁发的证书,是信任链的起始点。安装根证书意味着对这个CA认证中心的信任


### 生成证书

1. 生成 `x509`格式的CA自签名根证书

```
openssl req -new -x509 -keyout ca.key -out ca.crt
```

2. 生成私钥（key）及证书请求(csr)

```
openssl genrsa -des3 -out server.key 1024
openssl req -new -key server.key -out server.csr
```

***Notice*** 1024 指密钥长度，越长越安全，但加解密消耗的资源越多。

3. 使用 CA 证书为证书请求签名，也可以发送给第三方认证级构进行签名

```
openssl ca -in server.csr -out server.crt -cert ca.crt -keyfile ca.key
```

***Notice*** 签名过程中，可以通过 `-days 365` 参数，指定证书有效期，默认为 365 天。

### 常用证书格式的转换

1. 生成 p12 证书（思科 .p12 , 微软是 .pfx）(IOS 中使用 RSA 解密方法 `SecKeyDecrypt` 时需要通过 `SecPKCS12Import` 方法导入p12证书，并获得私钥)

```
openssl pkcs12 -export -inkey server.key -in server.crt -out client.p12
```

2. PKCS (p12) 转换为 PEM

```
openssl pkcs12 -in server.pfx -out server.pem -nodes
```
***Notice*** `-nodes` 表示不对 PEM 文件进行加密

3. PEM 转换为DER (?? IOS 使用 RSA 加密方法 `SecKeyEncrypt` 时需通过 `SecCertificateCreateWithData` 方法载入 der 证书，并得到公钥)

```
openssl x509 -outform der -in server.pem -out server.der
```

4. PEM提取KEY

```
 openssl RSA -in server.pem -out server.key
```

5. DER转换为PEM

```
 openssl x509 -inform der -in server.[cer|crt] -out server.pem
```

6. PEM转换为PKCS

```
openssl pkcs12 -export -out myserver.pfx -inkey server.key -in server.pem -certfile ca.crt
```