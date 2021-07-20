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

static NSString* const kKeyApplicationLabel = @"Strongbox-Credential-Store-Key";
static NSString* const kEncryptedBlobServiceName = @"Strongbox-Credential-Store";

@implementation SecretStore

+ (NSString *)getSecureString:(NSString *)identifier {
    NSData* keychainBlob = [self getEncryptedFromKeychain:identifier];
        
    return [self decrypt:keychainBlob identifier:identifier];
}
    
+ (BOOL)setSecureString:(NSString *)object forIdentifier:(NSString *)identifier {
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

    NSData* clearData = [object dataUsingEncoding:NSUTF8StringEncoding];

    CFDataRef cipherText = SecKeyCreateEncryptedData(publicKey, algorithm, (CFDataRef)clearData, &cfError);
    if(!cipherText) {
        if (privateKey) { CFRelease(privateKey); }
        if (publicKey)  { CFRelease(publicKey);  }
        if (access)     { CFRelease(access);     }

        NSLog(@"Error encrypting.... [%@]", (__bridge NSError *)cfError);
        return NO;
    }
        
    if(![self storeInKeychain:identifier encrypted:(__bridge NSData*)cipherText]) {
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

///////////////////////////////////////////////////////////////////

+ (CFStringRef)accessibility {
    return kSecAttrAccessibleWhenUnlockedThisDeviceOnly;
}

+ (CFStringRef)keyType {
    return kSecAttrKeyTypeECSECPrimeRandom;
}

+ (SecKeyAlgorithm)algorithm {
    return kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA256AESGCM;
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

+ (NSString*)decrypt:(NSData*)encrypted identifier:(NSString *)identifier {
    NSDictionary* query = [SecretStore getPrivateKeyQuery:identifier limit1Match:YES];

    CFTypeRef pk;
    
    NSLog(@"QQQQQQQQQQ decrypt START");

    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &pk);

    NSLog(@"QQQQQQQQQQ decrypt END");

    if( status != errSecSuccess ) {
        NSLog(@"Error getting key.... status = [%d]", (int)status);
        return nil;
    }

    SecKeyAlgorithm algorithm = [SecretStore algorithm];
    SecKeyRef privateKey = (SecKeyRef)pk;
    if(!SecKeyIsAlgorithmSupported(privateKey, kSecKeyOperationTypeDecrypt, algorithm)) {
       NSLog(@"Error algorithm is not available....");
       return nil;
    }
    
    NSString* wrapped = [self decryptWithPrivateKey:encrypted privateKey:privateKey];
    
    if (privateKey) {
        CFRelease(privateKey);
    }
        
    return wrapped;
}

+ (NSString*)decryptWithPrivateKey:(NSData*)encrypted privateKey:(SecKeyRef)privateKey {
    CFErrorRef cfError = nil;
    SecKeyAlgorithm algorithm = [SecretStore algorithm];
    CFDataRef pt = SecKeyCreateDecryptedData(privateKey, algorithm, (CFDataRef)encrypted, &cfError);
    
    if(!pt) {
        NSLog(@"Could not decrypt...");
        return nil;
    }
    
    NSData* plaintextData = (__bridge NSData *)pt;

    NSString* ret = [[NSString alloc] initWithData:plaintextData encoding:NSUTF8StringEncoding];
    
    CFRelease(pt);
    
    return ret;
}

+ (BOOL)storeInKeychain:(NSString*)identifier encrypted:(NSData*)encrypted {
    NSDictionary* searchQuery = [self getKeychainBlobQuery:identifier];
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)searchQuery, nil);
    
    if (status == errSecSuccess) {
        NSMutableDictionary* query = [[NSMutableDictionary alloc]init];
        
        [query setObject:encrypted forKey:(__bridge id)kSecValueData];
        [query setObject:(__bridge id)[SecretStore accessibility] forKey:(__bridge id)kSecAttrAccessible];
        
        status = SecItemUpdate((__bridge CFDictionaryRef)(searchQuery), (__bridge CFDictionaryRef)(query));
    }
    else if(status == errSecItemNotFound) {
        NSMutableDictionary* query = [self getKeychainBlobQuery:identifier];
        
        [query setObject:encrypted forKey:(__bridge id)kSecValueData];
        [query setObject:(__bridge id)[SecretStore accessibility] forKey:(__bridge id)kSecAttrAccessible];

        status = SecItemAdd((__bridge CFDictionaryRef)query, NULL);
    }
    
    if (status != errSecSuccess) {
        NSLog(@"Error storing encrypted blob: %d", (int)status);
    }
 
    return (status == errSecSuccess);
}

+ (NSData*)getEncryptedFromKeychain:(NSString*)identifier {
    NSMutableDictionary *query = [self getKeychainBlobQuery:identifier];
    
    [query setObject:@YES forKey:(__bridge id)kSecReturnData];
    [query setObject:(__bridge id)kSecMatchLimitOne forKey:(__bridge id)kSecMatchLimit];

    CFTypeRef result = NULL;
    
    
    NSLog(@"QQQQQQQQQQ getEncryptedFromKeychain START");

    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);

    NSLog(@"QQQQQQQQQQ getEncryptedFromKeychain END");
    
    
    if ( status == errSecSuccess ) {
        return (__bridge_transfer NSData *)result;
    }
    else {
        NSLog(@"getKeychainBlob: Could not get: %d", (int)status);
        return nil;
    }
}

+ (NSMutableDictionary*)getKeychainBlobQuery:(NSString*)identifier {
    NSString* blobId = [NSString stringWithFormat:@"strongbox-credential-store-encrypted-blob-%@", identifier];

    NSMutableDictionary *dictionary = [NSMutableDictionary dictionaryWithCapacity:4];
    
    [dictionary setObject:(__bridge id)kSecClassGenericPassword forKey:(__bridge id)kSecClass];
    [dictionary setObject:kEncryptedBlobServiceName forKey:(__bridge id)kSecAttrService];
    [dictionary setObject:blobId forKey:(__bridge id)kSecAttrAccount];
    [dictionary setObject:@NO forKey:(__bridge id)(kSecAttrSynchronizable)]; // No iCloud Sync
        
    return dictionary;
}

@end
