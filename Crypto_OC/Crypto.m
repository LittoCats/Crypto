//
//  Crypto.m
//  Crypto
//
//  Created by 程巍巍 on 2/13/15.
//  Copyright (c) 2015 Littocats. All rights reserved.
//

#import "Crypto.h"

#import <CommonCrypto/CommonCrypto.h>

#pragma mark- MD5

static NSString *MD5Encode(NSData *data){
    const void *cData = [data bytes];
    unsigned char md[CC_MD5_DIGEST_LENGTH];
    CC_MD5(cData, (CC_LONG)data.length, md);
    
    char mBuffer[CC_MD5_DIGEST_LENGTH*2] = {0};
    void *p = mBuffer;
    for (int index = 0; index < CC_MD5_DIGEST_LENGTH; index ++) {
        sprintf(p, "%.2X",md[index]);
        p += 2;
    }
    
    return [[NSString alloc] initWithBytes:mBuffer length:CC_MD5_DIGEST_LENGTH*2 encoding:NSUTF8StringEncoding];
}
static NSString *MD5EncodeFile(NSString *file){
    NSInputStream *inputStream = [[NSInputStream alloc] initWithFileAtPath:file];
    if (!inputStream) return nil;
    
    [inputStream open];
    if (inputStream.streamStatus != NSStreamStatusOpen) return nil;
    
    CC_MD5_CTX hashObject;
    CC_MD5_Init(&hashObject);
    
    BOOL hasMoreData = YES;
    UInt8 *buffer = malloc(4096);
    while (hasMoreData) {
        NSUInteger readBytesCount = [inputStream read:buffer maxLength:4096];
        if (readBytesCount == -1) break;
        if (readBytesCount == 0) {
            hasMoreData = false;
            continue;
        }
        CC_MD5_Update(&hashObject,
                      (const void *)buffer,
                      (CC_LONG)readBytesCount);
    }
    free(buffer);
    
    unsigned char md[CC_MD5_DIGEST_LENGTH];
    CC_MD5_Final(md, &hashObject);
    
    char mBuffer[CC_MD5_DIGEST_LENGTH*2] = {0};
    void *p = mBuffer;
    for (int index = 0; index < CC_MD5_DIGEST_LENGTH; index ++) {
        sprintf(p, "%.2X",md[index]);
        p += 2;
    }
    
    return [[NSString alloc] initWithBytes:mBuffer length:CC_MD5_DIGEST_LENGTH*2 encoding:NSUTF8StringEncoding];
}

#pragma mark- Base64
static const char base64_table[64] =
{   'A','B','C','D','E','F','G','H',
    'I','J','K','L','M','N','O','P',
    'Q','R','S','T','U','V','W','X',
    'Y','Z','a','b','c','d','e','f',
    'g','h','i','j','k','l','m','n',
    'o','p','q','r','s','t','u','v',
    'w','x','y','z','0','1','2','3',
    '4','5','6','7','8','9','+','/'
};
static const char deBase64_table[] =
{
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x3E,0x00,0x00,0x00,0x3F,
    0x34,0x35,0x36,0x37,0x38,0x39,0x3A,0x3B,0x3C,0x3D,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,
    0x0F,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x00,0x00,0x00,0x00,0x00,
    0x00,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,
    0x29,0x2A,0x2B,0x2C,0x2D,0x2E,0x2F,0x30,0x31,0x32,0x33,0x00,0x00,0x00,0x00,0x00
};
static NSString *Base64Encode(NSData *data){
    const char *srcData = [data bytes];
    NSInteger destLenght = (data.length/3 + ((data.length) % 3 ? 1 : 0)) * 4;
    unsigned char *destData = malloc(sizeof(char)*destLenght);
    unsigned char *base = destData;
    double index = data.length / 3;
    while (index --) {
        base[0] = base64_table[srcData[0] >> 2];
        base[1] = base64_table[(srcData[0] & 0b11) << 4 | (srcData[1] >> 4)];
        base[2] = base64_table[(srcData[1] & 0b1111) << 2 | (srcData[2] >> 6)];
        base[3] = base64_table[srcData[2] & 0b111111];
        srcData += 3;
        base += 4;
    }
    if (data.length%3 == 1) {
        base[0] = base64_table[srcData[0] >> 2];
        base[1] = base64_table[(srcData[0] & 0b11) << 4 | 0];
        base[2] = '=';
        base[3] = '=';
    }else if (data.length%3 == 2){
        base[0] = base64_table[srcData[0] >> 2];
        base[1] = base64_table[(srcData[0] & 0b11) << 4 | (srcData[1] >> 4)];
        base[2] = base64_table[(srcData[1] & 0b1111) << 2 | 0];
        base[3] = '=';
    }
    
    return [[NSString alloc] initWithBytesNoCopy:destData length:destLenght encoding:NSUTF8StringEncoding freeWhenDone:YES];
}
static NSData *Base64Decode(NSString *base64string){
    if (base64string.length%4) {
        printf("ESCCrypt error : The source data is not correct base64 code .");
        return nil;
    }
    
    if (base64string.length == 0) return [NSData new];
    
    NSInteger destLenght = base64string.length/4*3;
    unsigned char *destBytes = malloc(sizeof(char)*destLenght);
    unsigned char *buffer = destBytes;
    int32_t temp = 0;
    NSUInteger index = base64string.length/4-1;
    const char *srcBytes = [base64string UTF8String];
    while (index --) {
        temp |= deBase64_table[srcBytes[0]];
        temp <<= 6;
        temp |= deBase64_table[srcBytes[1]];
        temp <<= 6;
        temp |= deBase64_table[srcBytes[2]];
        temp <<= 6;
        temp |= deBase64_table[srcBytes[3]];
        buffer[0] = (temp & 0xFF0000) >> 16;
        buffer[1] = (temp & 0x00FF00) >> 8;
        buffer[2] = (temp & 0x0000FF);
        temp = 0;
        srcBytes += 4;
        buffer += 3;
    }
    
    if (srcBytes[2] == '=') {
        temp |= deBase64_table[srcBytes[0]];
        temp <<= 6;
        temp |= deBase64_table[srcBytes[1]];
        buffer[0] = temp >> 4;
        destLenght -= 2;
    }else if (srcBytes[3] == '='){
        temp |= deBase64_table[srcBytes[0]];
        temp <<= 6;
        temp |= deBase64_table[srcBytes[1]];
        temp <<= 6;
        temp |= deBase64_table[srcBytes[2]];
        buffer[0] = (temp >> 2 & 0xFF00) >> 8;
        buffer[1] = (temp >> 2 & 0x00FF);
        destLenght -= 1;
    }else {
        temp |= deBase64_table[srcBytes[0]];
        temp <<= 6;
        temp |= deBase64_table[srcBytes[1]];
        temp <<= 6;
        temp |= deBase64_table[srcBytes[2]];
        temp <<= 6;
        temp |= deBase64_table[srcBytes[3]];
        buffer[0] = (temp & 0xFF0000) >> 16;
        buffer[1] = (temp & 0x00FF00) >> 8;
        buffer[2] = (temp & 0x0000FF);
    }
    
    return [[NSData alloc] initWithBytesNoCopy:destBytes length:destLenght];
}

#pragma mark- Symmetric Crypt AES DES

static NSData *SymmetricCrypt(NSData *data, NSString *keyStr, NSInteger keySize, CCAlgorithm algorithm, CCOperation operation){
    NSInteger keyLength = (keyStr.length/keySize+1)*keySize+1;
    char *key = malloc(keyLength);
    bzero(key, keyLength);
    [keyStr getCString:key maxLength:keyLength encoding:NSUTF8StringEncoding];
    
    NSUInteger dataLength = [data length];
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    bzero(buffer, bufferSize);
    
    CCCryptorStatus status = CCCrypt(operation,
                                     algorithm,
                                     kCCOptionPKCS7Padding | kCCOptionECBMode,
                                     key, keySize,
                                     NULL,
                                     [data bytes], dataLength,
                                     buffer, bufferSize,
                                     &bufferSize);
    
    NSData *result;
    if (status == kCCSuccess)
        result = [NSData dataWithBytesNoCopy:buffer length:bufferSize freeWhenDone:YES];
    
    if (key) free(key);
    
    return result;

}

static NSData *AES128Encrypt(NSData *data, NSString *password)
{
    return SymmetricCrypt(data, password, kCCKeySizeAES128, kCCAlgorithmAES, kCCEncrypt);
}
static NSData *AES128Decrypt(NSData *data, NSString *password)
{
    return SymmetricCrypt(data, password, kCCKeySizeAES128, kCCAlgorithmAES, kCCDecrypt);
}
static NSData *AES192Encrypt(NSData *data, NSString *password)
{
    return SymmetricCrypt(data, password, kCCKeySizeAES192, kCCAlgorithmAES, kCCEncrypt);
}
static NSData *AES192Decrypt(NSData *data, NSString *password)
{
    return SymmetricCrypt(data, password, kCCKeySizeAES192, kCCAlgorithmAES, kCCDecrypt);
}
static NSData *AES256Encrypt(NSData *data, NSString *password)
{
    return SymmetricCrypt(data, password, kCCKeySizeAES256, kCCAlgorithmAES, kCCEncrypt);
}
static NSData *AES256Decrypt(NSData *data, NSString *password)
{
    return SymmetricCrypt(data, password, kCCKeySizeAES256, kCCAlgorithmAES, kCCDecrypt);
}

static NSData *DESEncrypt(NSData *data, NSString *password)
{
    return SymmetricCrypt(data, password, kCCKeySizeDES, kCCAlgorithmDES, kCCEncrypt);
}
static NSData *DESDecrypt(NSData *data, NSString *password)
{
    return SymmetricCrypt(data, password, kCCKeySizeDES, kCCAlgorithmDES, kCCDecrypt);
}
static NSData *DES3Encrypt(NSData *data, NSString *password)
{
    return SymmetricCrypt(data, password, kCCKeySize3DES, kCCAlgorithm3DES, kCCEncrypt);
}
static NSData *DES3Decrypt(NSData *data, NSString *password)
{
    return SymmetricCrypt(data, password, kCCKeySize3DES, kCCAlgorithm3DES, kCCEncrypt);
}

#pragma mark- Asymmetric Crypt RSA SSH

static SecKeyRef RSAPrivateKeyLoad(NSData *data, NSString *password)
{
    if (!data) [NSException raise:@"ESCCrypt warning : RSAPrivateKey maybe empty !" format:@""];
    
    CFDataRef p12Data = CFBridgingRetain(data);
    CFStringRef pw = CFBridgingRetain(password);
    
    SecKeyRef privateKey = NULL;
    CFMutableDictionaryRef options = CFDictionaryCreateMutable(NULL, 1, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(options, kSecImportExportPassphrase, pw);
    
    CFArrayRef items = NULL;
    OSStatus status = SecPKCS12Import(p12Data, options, &items);
    if (status == noErr && CFArrayGetCount(items) > 0) {
        CFDictionaryRef identities = CFArrayGetValueAtIndex(items, 0);
        SecIdentityRef identity = (SecIdentityRef)CFDictionaryGetValue(identities, kSecImportItemIdentity);
        status = SecIdentityCopyPrivateKey(identity, &privateKey);
        if (status != noErr) privateKey = NULL;
    }
    
    if (items) CFRelease(items);
    if (options) CFRelease(options);
    if (pw) CFRelease(pw);
    if (p12Data) CFRelease(p12Data);
    
    if (!privateKey) [NSException raise:@"Crypto error : RSA privateKey key load faild." format:@""];
    return privateKey;

}
static SecKeyRef RSAPublicKeyLoad(NSData *data)
{
    if (!data) [NSException raise:@"Crypto error : RSAPublicKey maybe empty !" format:@""];
    
    CFDataRef cerData = CFBridgingRetain(data);
    SecCertificateRef certification = SecCertificateCreateWithData(kCFAllocatorDefault, cerData);
    SecPolicyRef policy = SecPolicyCreateBasicX509();
    SecTrustRef trust = NULL;
    OSStatus status =  SecTrustCreateWithCertificates(certification, policy, &trust);
    SecTrustResultType trustResult;
    if (status == noErr) status = SecTrustEvaluate(trust, &trustResult);
    
    SecKeyRef publicKey = status == noErr ? SecTrustCopyPublicKey(trust) : NULL;
    
    if (trust) CFRelease(trust);
    if (policy) CFRelease(policy);
    if (certification) CFRelease(certification);
    if (cerData) CFRelease(cerData);
    
    if (!publicKey) [NSException raise:@"Crypto error : RSA public key load faild." format:@""];
    return publicKey;
}

static NSData *RSAEncrypt(NSData *data, NSData *publicKey)
{
    SecKeyRef secKey = RSAPublicKeyLoad(publicKey);
    CFDataRef srcData = CFBridgingRetain(data);
    size_t dataLength = CFDataGetLength(srcData);
    
    // Notice 这里有三个数据长度的变量：blockSize chiperTextLength plaintextLength
    size_t blockSize            = SecKeyGetBlockSize(secKey)-11;    // When PKCS1 padding is performed, the maximum length of data that can be encrypted is the value returned by SecKeyGetBlockSize() - 11. (SecKey.h)
    size_t blockCount           = (size_t)ceil(dataLength/blockSize)+1;
    
    size_t chiperTextLength;
    UInt8  *chiperText          = malloc(blockSize * sizeof(UInt8));    // 缓存待加密的数据块

    size_t plainTextLength      = blockSize;
    UInt8 *plainText        = malloc(plainTextLength*sizeof(UInt8));    // 缓存加密后的数据
    
    CFMutableDataRef encryptedData = CFDataCreateMutable(NULL, 0);
    
    for (size_t i = 0; i < blockCount; i ++){
        plainTextLength  = MIN(blockSize, dataLength - i*blockSize);
        CFDataGetBytes(srcData, CFRangeMake(i*blockSize, plainTextLength), plainText);
        OSStatus status = SecKeyEncrypt(secKey,
                                        kSecPaddingPKCS1,
                                        plainText, plainTextLength,
                                        chiperText, &chiperTextLength);
        if (status == noErr) CFDataAppendBytes(encryptedData, chiperText, chiperTextLength);
        else i = blockCount;
    }
    
    if (plainText)  free(plainText);
    if (chiperText) free(chiperText);
    if (secKey)     free(secKey);
    
    return CFBridgingRelease(encryptedData);
}

static NSData *RSADecrypt(NSData *data, NSData *private, NSString *password)
{
    CFDataRef srcData = CFBridgingRetain(data);
    size_t dataLength = CFDataGetLength(srcData);
    SecKeyRef  secKey = RSAPrivateKeyLoad(private, password);
    
    // Notice 这里有三个数据长度的变量：blockSize chiperTextLength plaintextLength
    size_t blockSize        = SecKeyGetBlockSize(secKey);
    size_t blockCount       = (size_t)ceil(dataLength/blockSize)+1;
    
    size_t chiperTextLength ;
    UInt8 *chiperText       = malloc(blockSize*sizeof(UInt8));          //  缓存待解密数据
    
    size_t plainTextLength      = blockSize;
    UInt8 *plainText        = malloc(plainTextLength*sizeof(UInt8));    // 缓存解密后的数据
    
    CFMutableDataRef decryptedData = CFDataCreateMutable(NULL, dataLength);
    
    for (size_t i = 0; i < blockCount; i ++) {
        plainTextLength = MIN(blockSize, dataLength - i * blockSize);
        CFDataGetBytes(srcData, CFRangeMake(i*blockSize, plainTextLength), plainText);
        OSStatus status = SecKeyDecrypt(secKey,
                                        kSecPaddingPKCS1,
                                        plainText, plainTextLength,
                                        chiperText, &chiperTextLength);
        if (status == noErr) CFDataAppendBytes(decryptedData, chiperText, chiperTextLength);
        else i = blockCount;
    }
    
    if (plainText)  free(plainText);
    if (chiperText) free(chiperText);
    if (secKey)     free(secKey);
    
    return CFBridgingRelease(decryptedData);
}

#pragma mark- public

typeof(ECrypto) ECrypto = (typeof(ECrypto)){
    MD5Encode,
    MD5EncodeFile,

    Base64Encode,
    Base64Decode,

    AES128Encrypt,
    AES128Decrypt,
    AES192Encrypt,
    AES192Decrypt,
    AES256Encrypt,
    AES256Decrypt,
    
    DESEncrypt,
    DESDecrypt,
    DES3Encrypt,
    DES3Decrypt,
    
    RSAEncrypt,
    RSADecrypt
};