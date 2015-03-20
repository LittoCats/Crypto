//
//  CryptoTests.swift
//  CryptoTests
//
//  Created by 程巍巍 on 3/19/15.
//  Copyright (c) 2015 Littocats. All rights reserved.
//

import UIKit
import XCTest

class CryptoTests: XCTestCase {
    
    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }
    
    func testExample() {
        // This is an example of a functional test case.
        
        var data = ("        // This is an example of a functional test case." as NSString).dataUsingEncoding(NSUTF8StringEncoding)
        var md5 = Crypto.MD5(data: data!)
        println(md5)
        
        var encodedData = Crypto.AES128Encrypt(data!, withPassword: "dujuanhuakai")
        var decodedData = Crypto.AES128Decrypt(encodedData, withPassword: "dujuanhuakai")
        
        var str = NSString(data: decodedData, encoding: NSUTF8StringEncoding)
        
        println(str)
        XCTAssert(true, "Pass")
    }
    
    func testRSA(){
        let publicKey: NSData = NSData(contentsOfFile: NSBundle.mainBundle().pathForResource("server", ofType: "der")!)!
        let privateKey: NSData = NSData(contentsOfFile: NSBundle.mainBundle().pathForResource("server", ofType: "p12")!)!
        
        let password = "dujuanhuakai"
        
        var source: NSString = "NSData *privateKey = [NSData dataWithContentsOfFile:[[NSBundle mainBundle] pathForResource:@\"Certificates\" ofType:@\"p12\"]];"
        
        var encryptData = Crypto.RSAEncrypt(source.dataUsingEncoding(NSUTF8StringEncoding)!, publicKey: publicKey)
        var decryptData = Crypto.RSADecrypt(encryptData, privateKey: privateKey, password: password)
        
        println("\(source)\n\(NSString(data: decryptData, encoding: NSUTF8StringEncoding))")
    }
    
    func testPerformanceExample() {
        // This is an example of a performance test case.
        self.measureBlock() {
            // Put the code you want to measure the time of here.
        }
    }
    
}
