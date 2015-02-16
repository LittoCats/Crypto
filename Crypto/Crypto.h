//
//  Crypto.h
//  Crypto
//
//  Created by 程巍巍 on 2/13/15.
//  Copyright (c) 2015 Littocats. All rights reserved.
//

#import <Foundation/Foundation.h>

#ifndef CRYPTO
#define CRYPTO

// 不可改变 Crypto 中方法指针的顺序
FOUNDATION_EXTERN struct {
    NSString *(*MD5Encode)(NSData *data);
    NSString *(*MD5EncodeFile)(NSString *file);
    
    NSString *(*Base64Encode)(NSData *data);
    NSData *(*Base64Decode)(NSString *base);
    
    NSData *(*AES128Encrypt)(NSData *data, NSString *password);
    NSData *(*AES128Decrypt)(NSData *data, NSString *password);
    NSData *(*AES192Encrypt)(NSData *data, NSString *password);
    NSData *(*AES192Decrypt)(NSData *data, NSString *password);
    NSData *(*AES256Encrypt)(NSData *data, NSString *password);
    NSData *(*AES256Decrypt)(NSData *data, NSString *password);
    
    NSData *(*DESEncrypt)(NSData *data, NSString *password);
    NSData *(*DESDecrypt)(NSData *data, NSString *password);
    NSData *(*DES3Encrypt)(NSData *data, NSString *password);
    NSData *(*DES3Decrypt)(NSData *data, NSString *password);
    
    // 证书生成可参照项目文件夹中的 openssl_rsa_certificate_生成与转换.md 文件
    NSData *(*RSAEncrypt)(NSData *data, NSData *certificateFileData); // certificateFileData 为 DER encoded X.509 certificate data
    NSData *(*RSADecrypt)(NSData *data, NSData *certificateFileData, NSString *password); // certificateFileData 为 PKCS#12 formatted data
}  Crypto;

#endif
