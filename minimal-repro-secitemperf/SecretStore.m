//
//  CredentialsStore.m
//  Strongbox
//
//  Created by Mark on 13/01/2020.
//  Copyright © 2014-2021 Mark McGuill. All rights reserved.
//
// Reference Reading... Very helpful
//
// https://darthnull.org/security/2018/05/31/secure-enclave-ecies/
// https://gist.github.com/dschuetz/2ff54d738041fc888613f925a7708a06
// https://medium.com/@alx.gridnev/ios-keychain-using-secure-enclave-stored-keys-8f7c81227f4
// https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/storing_keys_in_the_keychain?language=objc
// https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/using_keys_for_encryption?language=objc

#import "SecretStore.h"

// NB: OSX 10.11 (El Capitan) is NOT supported

static NSString* const kKeyApplicationLabel = @"Strongbox-Credential-Store-Key";
static NSString* const kEncryptedBlobServiceName = @"Strongbox-Credential-Store";
static NSString* const kWrappedObjectObjectKey = @"theObject";

@implementation SecretStore

+ (NSString *)getSecureString:(NSString *)identifier {
    // NSLog(@"XXXX - getSecureObject - [%@]", identifier);
    
    NSDictionary* wrapped = [self getWrappedObject:identifier];
    if(wrapped == nil) {
        // NSLog(@"XXXX - Could not get wrapped object. [%@]", identifier);
        return nil;
    }

    return wrapped[kWrappedObjectObjectKey];
}
    
+ (BOOL)setSecureString:(NSString *)object forIdentifier:(NSString *)identifier {
    [self deleteSecureItem:identifier]; // Clear any existing password first...

    if(object == nil) { // Nil is equivalent to delete
        return YES;
    }
    
    return [self wrapSerializeAndEncryptObject:object forIdentifier:identifier];
}

+ (BOOL)wrapSerializeAndEncryptObject:(id)object
                        forIdentifier:(NSString *)identifier {
    SecAccessControlRef access = [SecretStore createAccessControl];
    if(!access) {
        return NO;
    }
    
    NSDictionary *attributes = [SecretStore createKeyPairAttributes:identifier
                                                      accessControl:access];
    
    // Create the Key Pair...
    
    CFErrorRef cfError = nil;
    SecKeyRef privateKey = SecKeyCreateRandomKey((__bridge CFDictionaryRef)attributes, &cfError);
    if (!privateKey) {
        if (access)     { CFRelease(access);     }
        
        NSLog(@"Error creating AccessControl: [%@]", (__bridge NSError *)cfError);
        return NO;
    }

    // Now get the matching Public Key
    
    SecKeyRef publicKey = SecKeyCopyPublicKey(privateKey);
    if ( !publicKey ) {
        if (privateKey) { CFRelease(privateKey); }
        if (access)     { CFRelease(access);     }

        NSLog(@"Error getting match public key....");
        return NO;
    }

    SecKeyAlgorithm algorithm = [SecretStore algorithm];
    if( !SecKeyIsAlgorithmSupported(publicKey, kSecKeyOperationTypeEncrypt, algorithm) ) {
        if (privateKey) { CFRelease(privateKey); }
        if (publicKey)  { CFRelease(publicKey);  }
        if (access)     { CFRelease(access);     }

        NSLog(@"Error algorithm is not support....");
        return NO;
    }

    NSDictionary* wrapper = [self wrapObject:object identifier:identifier];
    NSData* clearData = [NSKeyedArchiver archivedDataWithRootObject:wrapper];

    CFDataRef cipherText = SecKeyCreateEncryptedData(publicKey, algorithm, (CFDataRef)clearData, &cfError);
    if(!cipherText) {
        if (privateKey) { CFRelease(privateKey); }
        if (publicKey)  { CFRelease(publicKey);  }
        if (access)     { CFRelease(access);     }

        NSLog(@"Error encrypting.... [%@]", (__bridge NSError *)cfError);
        return NO;
    }
        
    if(![self storeKeychainBlob:identifier encrypted:(__bridge NSData*)cipherText]) {
        if (privateKey) { CFRelease(privateKey); }
        if (publicKey)  { CFRelease(publicKey);  }
        if (access)     { CFRelease(access);     }
        if (cipherText) { CFRelease(cipherText); }

        NSLog(@"Error storing encrypted blob in Keychain...");
        return NO;
    }
    
    if (privateKey) { CFRelease(privateKey); }
    if (publicKey)  { CFRelease(publicKey);  }
    if (access)     { CFRelease(access);     }
    if (cipherText) { CFRelease(cipherText); }

    return YES;
}

// Delete

+ (void)deleteSecureItem:(NSString *)identifier {
    [self deleteKeychainBlob:identifier];
    
    NSDictionary* query = [SecretStore getPrivateKeyQuery:identifier limit1Match:NO];
    OSStatus status = SecItemDelete((__bridge CFDictionaryRef)query);
    if ( status != errSecSuccess && status != errSecItemNotFound ) {
        NSLog(@"Error Deleting Private Key: [%d]", (int)status);
    }
}

///////////////////////////////////////////////////////////////////

+ (CFStringRef)accessibility {
    return kSecAttrAccessibleWhenUnlockedThisDeviceOnly;
}

+ (CFStringRef)keyType {
#if TARGET_OS_IPHONE
    if (@available(iOS 10.0, *)) {
        return kSecAttrKeyTypeECSECPrimeRandom;
    }
    else {
        return kSecAttrKeyTypeEC;
    }
#else
    if (@available(macOS 10.12, *)) {
        return kSecAttrKeyTypeECSECPrimeRandom;
    }
    else {
        return kSecAttrKeyTypeEC;
    }
#endif
}

+ (SecKeyAlgorithm)algorithm {
#if TARGET_OS_IPHONE
    if (@available(iOS 11.0, *)) {
        return kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA256AESGCM;
    }
    else {
        return kSecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM;
    }
#else
    if (@available(macOS 10.13, *)) {
        return kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA256AESGCM;
    }
    else {
        return kSecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM;
    }
#endif
}

+ (SecAccessControlRef)createAccessControl {
    CFErrorRef cfError = nil;

    SecAccessControlRef access = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                                                 [SecretStore accessibility],
                                                                 kSecAccessControlPrivateKeyUsage,
                                                                 &cfError);
    
    if(!access) {
        NSLog(@"Error creating AccessControl: [%@]", (__bridge NSError *)cfError);
        return nil;
    }
    
    return access;
}

+ (NSDictionary*)createKeyPairAttributes:(NSString*)identifier
                           accessControl:(SecAccessControlRef)accessControl {
    NSDictionary* attributes =
        @{ (id)kSecAttrKeyType:             (id)[SecretStore keyType],
           (id)kSecAttrKeySizeInBits:       @256,
           (id)kSecAttrEffectiveKeySize :   @256,
           (id)kSecAttrApplicationLabel :   kKeyApplicationLabel,
           (id)kSecAttrTokenID:             (id)kSecAttrTokenIDSecureEnclave,
           (id)kSecPrivateKeyAttrs:
             @{ (id)kSecAttrIsPermanent:    @YES,
                (id)kSecAttrApplicationTag: [identifier dataUsingEncoding:NSUTF8StringEncoding],
                (id)kSecAttrAccessControl:  (__bridge id)accessControl,
              },
         };

    return attributes;
}

//

+ (NSDictionary*)getPrivateKeyQuery:(NSString*)identifier limit1Match:(BOOL)limit1Match {
    NSMutableDictionary* ret = [NSMutableDictionary dictionaryWithDictionary:@{
        (id)kSecClass :                 (id)kSecClassKey,
        (id)kSecAttrKeyType :           (id)[SecretStore keyType],
        (id)kSecAttrKeySizeInBits:      @256,
        (id)kSecAttrEffectiveKeySize :  @256,
        (id)kSecAttrApplicationLabel :  kKeyApplicationLabel,
        (id)kSecAttrApplicationTag :    [identifier dataUsingEncoding:NSUTF8StringEncoding],
        (id)kSecReturnRef :             @YES
    }];
    
    if ( limit1Match ) {
        ret[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitOne;
    }
    
    return ret;
}

+ (NSDictionary*)getWrappedObject:(NSString *)identifier {
    BOOL itemNotFound;
    NSData* keychainBlob = [self getKeychainBlob:identifier itemNotFound:&itemNotFound];
    
    if ( !keychainBlob ) {
        if ( itemNotFound ) {
            return nil;
        }
        else {
            NSLog(@"XXXX - Could not get encrypted blob but it appears to be present [%@]", identifier);
            return nil;
        }
    }
    
    return [self decryptAndDeserializeKeychainBlob:keychainBlob identifier:identifier];
}

+ (NSDictionary*)decryptAndDeserializeKeychainBlob:(NSData*)encrypted identifier:(NSString *)identifier {
    NSTimeInterval startTime = NSDate.timeIntervalSinceReferenceDate;

    NSDictionary* query = [SecretStore getPrivateKeyQuery:identifier limit1Match:YES];

    CFTypeRef pk;
    
//    NSLog(@"QQQQQQQQQQ query1 start");
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &pk);
//    NSLog(@"QQQQQQQQQQ query1 end");

    if( status != errSecSuccess ) {
        NSLog(@"Error getting key.... status = [%d]", (int)status);
        return nil;
    }

    double perf = NSDate.timeIntervalSinceReferenceDate - startTime;
    startTime = NSDate.timeIntervalSinceReferenceDate;

//    NSLog(@"====================================== PERF ======================================");
//    NSLog(@"query-1 took [%f] seconds", perf);
//    NSLog(@"====================================== PERF ======================================");

    SecKeyAlgorithm algorithm = [SecretStore algorithm];
    SecKeyRef privateKey = (SecKeyRef)pk;
    if(!SecKeyIsAlgorithmSupported(privateKey, kSecKeyOperationTypeDecrypt, algorithm)) {
       NSLog(@"Error algorithm is not available....");
       return nil;
    }
    
    NSDictionary * wrapped = [self decryptWrappedObject:encrypted privateKey:privateKey];
    
    if (privateKey) {
        CFRelease(privateKey);
    }
    
    if(!wrapped) {
        NSLog(@"Could not unwrap secure item. Cleaning it up.");
        [self deleteSecureItem:identifier];
        return nil;
    }
    
    perf = NSDate.timeIntervalSinceReferenceDate - startTime;
    
//    NSLog(@"====================================== PERF ======================================");
//    NSLog(@"decryptAndDeserializeKeychainBlob-2 took [%f] seconds", perf);
//    NSLog(@"====================================== PERF ======================================");

    return wrapped;
}

+ (NSDictionary*)decryptWrappedObject:(NSData*)encrypted privateKey:(SecKeyRef)privateKey {
    CFErrorRef cfError = nil;
    SecKeyAlgorithm algorithm = [SecretStore algorithm];
    CFDataRef pt = SecKeyCreateDecryptedData(privateKey, algorithm, (CFDataRef)encrypted, &cfError);
    
    if(!pt) {
        NSLog(@"Could not decrypt...");
        return nil;
    }
    
    NSDictionary *wrapped = nil;
    @try {
        wrapped = [NSKeyedUnarchiver unarchiveObjectWithData:(__bridge NSData *)pt];
    }
    @catch (NSException *e) {
        NSLog(@"Error Ubarchiving: %@", e);
    }
    @finally {}
    
    if (pt) {
        CFRelease(pt);
    }
    
    return wrapped;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////// //
// Encrypted Blob Storage...

+ (NSDictionary*)wrapObject:(id)object identifier:(NSString*)identifier {
    return @{ kWrappedObjectObjectKey : object };
}

+ (BOOL)storeKeychainBlob:(NSString*)identifier encrypted:(NSData*)encrypted {
    NSDictionary* searchQuery = [self getBlobQuery:identifier];
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)searchQuery, nil);
    
    if (status == errSecSuccess) {
        NSMutableDictionary* query = [[NSMutableDictionary alloc]init];
        
        [query setObject:encrypted forKey:(__bridge id)kSecValueData];
        [query setObject:(__bridge id)[SecretStore accessibility] forKey:(__bridge id)kSecAttrAccessible];
        
        status = SecItemUpdate((__bridge CFDictionaryRef)(searchQuery), (__bridge CFDictionaryRef)(query));
    }
    else if(status == errSecItemNotFound) {
        NSMutableDictionary* query = [self getBlobQuery:identifier];
        
        [query setObject:encrypted forKey:(__bridge id)kSecValueData];
        [query setObject:(__bridge id)[SecretStore accessibility] forKey:(__bridge id)kSecAttrAccessible];

        status = SecItemAdd((__bridge CFDictionaryRef)query, NULL);
    }
    
    if (status != errSecSuccess) {
        NSLog(@"Error storing encrypted blob: %d", (int)status);
    }
 
    return (status == errSecSuccess);
}

+ (NSData*)getKeychainBlob:(NSString*)identifier itemNotFound:(BOOL*)itemNotFound {
    NSTimeInterval startDecryptTime = NSDate.timeIntervalSinceReferenceDate;
        
    NSMutableDictionary *query = [self getBlobQuery:identifier];
    
    [query setObject:@YES forKey:(__bridge id)kSecReturnData];
    [query setObject:(__bridge id)kSecMatchLimitOne forKey:(__bridge id)kSecMatchLimit];

    CFTypeRef result = NULL;
    
//    NSLog(@"QQQQQQQQQQ query2 start");
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
//    NSLog(@"QQQQQQQQQQ query2 end");
    
    double perf = NSDate.timeIntervalSinceReferenceDate - startDecryptTime;
    if ( perf > 0.5f ) {
        NSLog(@"====================================== PERF ======================================");
        NSLog(@"getKeychainBlob (query2) [%@] [%f] seconds", identifier, perf);
        NSLog(@"====================================== PERF ======================================");
    }
    
    if ( status == errSecSuccess ) {
        *itemNotFound = NO;
        return (__bridge_transfer NSData *)result;
    }
    else if (status == errSecItemNotFound) {
        *itemNotFound = YES;
        return nil;
    }
    else {
        *itemNotFound = NO;
        NSLog(@"getKeychainBlob: Could not get: %d", (int)status);
        return nil;
    }
}

+ (void)deleteKeychainBlob:(NSString*)identifier {
    NSMutableDictionary *query = [self getBlobQuery:identifier];
    
//    NSLog(@"deleteKeychainBlob: Enter");
    OSStatus status = SecItemDelete((__bridge CFDictionaryRef)query);
    if ( status != errSecSuccess && status != errSecItemNotFound ) {
        NSLog(@"Error Deleting Keychain Blob: [%d]", (int)status);
    }
    
//    NSLog(@"deleteKeychainBlob: Exit %d", (int)status);
}

+ (NSMutableDictionary*)getBlobQuery:(NSString*)identifier {
    NSString* blobId = [NSString stringWithFormat:@"strongbox-credential-store-encrypted-blob-%@", identifier];

    NSMutableDictionary *dictionary = [NSMutableDictionary dictionaryWithCapacity:4];
    
    [dictionary setObject:(__bridge id)kSecClassGenericPassword forKey:(__bridge id)kSecClass];
    [dictionary setObject:kEncryptedBlobServiceName forKey:(__bridge id)kSecAttrService];
    [dictionary setObject:blobId forKey:(__bridge id)kSecAttrAccount];
    [dictionary setObject:@NO forKey:(__bridge id)(kSecAttrSynchronizable)]; // No iCloud Sync
    
#if TARGET_OS_OSX
    if (@available(macOS 10.15, *)) {
        [dictionary setObject:@YES forKey:(__bridge id)(kSecUseDataProtectionKeychain)];
    }
#endif
    
    return dictionary;
}

@end
