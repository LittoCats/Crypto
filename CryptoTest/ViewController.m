//
//  ViewController.m
//  CryptoTest
//
//  Created by 程巍巍 on 2/15/15.
//  Copyright (c) 2015 Littocats. All rights reserved.
//

#import "ViewController.h"

#import "Crypto.h"

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
    
    NSData *privateKey = [NSData dataWithContentsOfFile:[[NSBundle mainBundle] pathForResource:@"server" ofType:@"p12"]];
    NSData *publicKey = [NSData dataWithContentsOfFile:[[NSBundle mainBundle] pathForResource:@"server" ofType:@"der"]];
    NSString *password = @"dujuanhuakai";
    
    NSString *source = @"NSData *privateKey = [NSData dataWithContentsOfFile:[[NSBundle mainBundle] pathForResource:@\"Certificates\" ofType:@\"p12\"]];";
    
    NSData *encryptData = Crypto.RSAEncrypt([source dataUsingEncoding:NSUTF8StringEncoding], publicKey);
    NSData *decryptData = Crypto.RSADecrypt(encryptData, privateKey, password);
    NSString *deSource = [[NSString alloc] initWithData:decryptData encoding:NSUTF8StringEncoding];
    
    printf("%s\n",[source UTF8String]);
    printf("%s\n",[deSource UTF8String]);
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

@end
