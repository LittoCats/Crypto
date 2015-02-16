//
//  CryptoTest.m
//  Crypto
//
//  Created by 程巍巍 on 2/13/15.
//  Copyright (c) 2015 Littocats. All rights reserved.
//

#import <UIKit/UIKit.h>
#import <XCTest/XCTest.h>

#import "Crypto.h"

@interface CryptoTest : XCTestCase

@end

@implementation CryptoTest

- (void)setUp {
    [super setUp];
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}

- (void)testMD5 {
    // This is an example of a functional test case.
    NSString *source = @"    // This is an example of a functional test case.";
    
    NSString *md5 = Crypto.MD5Encode([source dataUsingEncoding:NSUTF8StringEncoding]);
    
    XCTAssertEqualObjects(md5, @"F522975CA887A0995164F45AAF85F99E");
    XCTAssert(YES, @"Pass");
}

- (void)testAESDES {
    NSString *source = @"// Put teardown code here. This method is called after the invocation of each test method in the class.";
    NSString *key = @"Littocats";
    NSData *cryptData = Crypto.AES128Encrypt([source dataUsingEncoding:NSUTF8StringEncoding], key);
    
    NSString *deSource = [[NSString alloc] initWithData:Crypto.AES128Decrypt(cryptData, key) encoding:NSUTF8StringEncoding];
    XCTAssertEqualObjects(source, deSource);
}

- (void)testRSA{
    NSData *privateKey = [NSData dataWithContentsOfFile:[[NSBundle mainBundle] pathForResource:@"Certificates" ofType:@"p12"]];
    NSData *publicKey = [NSData dataWithContentsOfFile:[[NSBundle mainBundle] pathForResource:@"public" ofType:@"pem"]];
    NSString *password = @"dujuanhuakai";
    
    NSString *source = @"NSData *privateKey = [NSData dataWithContentsOfFile:[[NSBundle mainBundle] pathForResource:@\"Certificates\" ofType:@\"p12\"]];";
    
    NSData *encryptData = Crypto.RSAEncrypt([source dataUsingEncoding:NSUTF8StringEncoding], privateKey, password);
    NSData *decryptData = Crypto.RSADecrypt(encryptData, publicKey);
    NSString *deSource = [[NSString alloc] initWithData:decryptData encoding:NSUTF8StringEncoding];
    
    XCTAssertEqualObjects(source, deSource);
}

- (void)testPerformanceExample {
    // This is an example of a performance test case.
    [self measureBlock:^{
        // Put the code you want to measure the time of here.
    }];
}

@end
