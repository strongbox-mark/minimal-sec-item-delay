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
static NSString* const kWrappedObjectExpiryKey = @"expiry";
static NSString* const kWrappedObjectExpiryModeKey = @"expiryMode";

@interface SecretStore ()

@property BOOL _secureEnclaveAvailable;

@end

@implementation SecretStore

+ (instancetype)sharedInstance {
    static SecretStore *sharedInstance = nil;
    static dispatch_once_t onceToken;
    
    dispatch_once(&onceToken, ^{
        sharedInstance = [[SecretStore alloc] init];
    });
    
    return sharedInstance;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        self._secureEnclaveAvailable = [SecretStore isSecureEnclaveAvailable];
    }
    
    return self;
}

///////////////////////////////////////////////////////////////////
// Get

- (id)getSecureObject:(NSString *)identifier {
    return [self getSecureObject:identifier expired:nil];
}

- (NSString *)getSecureString:(NSString *)identifier {
    return [self getSecureObject:identifier];
}

- (id)getSecureObject:(NSString *)identifier expired:(BOOL*)expired {
    // NSLog(@"XXXX - getSecureObject - [%@]", identifier);
    
    if ([SecretStore isUnsupportedOS]) {
        NSLog(@"Unsupported OS...");
        return nil;
    }

    NSDictionary* wrapped = [self getWrappedObject:identifier];
    if(wrapped == nil) {
        // NSLog(@"XXXX - Could not get wrapped object. [%@]", identifier);
        return nil;
    }

    return wrapped[kWrappedObjectObjectKey];
}
    
// Set

- (BOOL)setSecureString:(NSString *)object forIdentifier:(NSString *)identifier {
    if ([SecretStore isUnsupportedOS]) {
        NSLog(@"SecretStore: Cannot set secure object - Unsupported OS...");
        return NO;
    }

    [self deleteSecureItem:identifier]; // Clear any existing password first...

    if(object == nil) { // Nil is equivalent to delete
        return YES;
    }
    
    if (@available(ios 10.0, *)) {
        return [self wrapSerializeAndEncryptObject:object forIdentifier:identifier expiryMode:expiryMode expiresAt:expiresAt];
    }
}

- (BOOL)wrapAndSerializeObject:(id)object forIdentifier:(NSString *)identifier expiryMode:(SecretExpiryMode)expiryMode expiresAt:(NSDate *)expiresAt {
    NSDictionary* wrapper = [self wrapObject:object expiryMode:expiryMode expiry:expiresAt identifier:identifier];
    NSData* clearData = [NSKeyedArchiver archivedDataWithRootObject:wrapper];

    if(![self storeKeychainBlob:identifier encrypted:clearData]) {
        NSLog(@"Error storing encrypted blob in Keychain...");
        return NO;
    }
    
    return YES;
}

- (BOOL)wrapSerializeAndEncryptObject:(id)object
                        forIdentifier:(NSString *)identifier
                           expiryMode:(SecretExpiryMode)expiryMode
                            expiresAt:(NSDate *)expiresAt {
    SecAccessControlRef access = [SecretStore createAccessControl:self.secureEnclaveAvailable];
    if(!access) {
        return NO;
    }
    
    NSDictionary *attributes = [SecretStore createKeyPairAttributes:identifier
                                                      accessControl:access
                                        requestSecureEnclaveStorage:self.secureEnclaveAvailable];
    
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

    NSDictionary* wrapper = [self wrapObject:object expiryMode:expiryMode expiry:expiresAt identifier:identifier];
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

- (void)deleteSecureItem:(NSString *)identifier {
    if ([SecretStore isUnsupportedOS]) {
        NSLog(@"Unsupported OS...");
        return;
    }

    [self deleteKeychainBlob:identifier];
    
    NSDictionary* query = [SecretStore getPrivateKeyQuery:identifier limit1Match:NO];
    OSStatus status = SecItemDelete((__bridge CFDictionaryRef)query);
    if ( status != errSecSuccess && status != errSecItemNotFound ) {
        NSLog(@"Error Deleting Private Key: [%d]", (int)status);
    }
}

///////////////////////////////////////////////////////////////////

- (SecretExpiryMode)getSecureObjectExpiryMode:(NSString *)identifier {
    if ([SecretStore isUnsupportedOS]) {
        NSLog(@"Unsupported OS...");
        return kUnknown;
    }

    NSDictionary* wrapped = [self getWrappedObject:identifier];
    if(wrapped == nil) {
        return kUnknown;
    }

    NSNumber* expiryModeNumber = wrapped[kWrappedObjectExpiryModeKey];
    return (SecretExpiryMode)expiryModeNumber.integerValue;
}

- (NSDate *)getSecureObjectExpiryDate:(NSString *)identifier {
    if ([SecretStore isUnsupportedOS]) {
        NSLog(@"Unsupported OS...");
        return nil;
    }

    NSDictionary* wrapped = [self getWrappedObject:identifier];
    if(wrapped == nil) {
        return nil;
    }

    NSNumber* expiryModeNumber = wrapped[kWrappedObjectExpiryModeKey];
    SecretExpiryMode mode = expiryModeNumber.integerValue;

    if(mode == kExpiresAtTime) {
        return wrapped[kWrappedObjectExpiryKey];
    }
    
    return nil;
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

- (BOOL)secureEnclaveAvailable {
    return self._secureEnclaveAvailable;
}

+ (BOOL)isUnsupportedOS {
#if TARGET_OS_OSX
    if (@available(macOS 10.12, *)) { } else {
        NSLog(@"Mac OSX < 10.12 is not supported by the Strongbox Secret Store");
        return YES;
    }
#endif
    
    return NO;
}

+ (BOOL)isSecureEnclaveAvailable {
    if (TARGET_OS_SIMULATOR != 0) { // Check here because we get a crash if we try to run below code on a sim
//        NSLog(@"Secure Enclave not available on Simulator");
        return NO;
    }

    if ([SecretStore isUnsupportedOS]) {
        NSLog(@"Unsupported OS...");
        return NO;
    }

    if (@available(iOS 10.0, *)) { } else {
        NSLog(@"Secure Enclave unavailable on iOS < 10.0");
        return NO;
    }
    
    // It seems the only right way to check outside of device checks is to try create a secure enclave key...

    SecAccessControlRef accessControl = [SecretStore createAccessControl:YES];
    if(!accessControl) {
        return NO;
    }
    
    NSString* identifier = NSUUID.UUID.UUIDString;
    
    NSDictionary* attributes = [SecretStore createKeyPairAttributes:identifier accessControl:accessControl requestSecureEnclaveStorage:YES];
    
    // Try to create the Key Pair...

    CFErrorRef cfError = nil;
    SecKeyRef privateKey = SecKeyCreateRandomKey((__bridge CFDictionaryRef)attributes, &cfError);
    BOOL available = privateKey != nil;

    if ( privateKey ) {
        NSDictionary* query = [SecretStore getPrivateKeyQuery:identifier limit1Match:NO];
        OSStatus status = SecItemDelete((__bridge CFDictionaryRef)query);
        if ( status != errSecSuccess ) {
            NSLog(@"Error Deleting Private Key: [%d]", (int)status);
        }
        CFRelease(privateKey);
    }
    CFRelease(accessControl);

    if(!available) {
        NSLog(@"WARNWARN: SECURE ENCLAVE NOT AVAILABLE");
    }
    else {
        NSLog(@"OK. Secure Enclave available on device.");
    }
    
    return available;
}

+ (SecAccessControlRef)createAccessControl:(BOOL)requestSecureEnclaveStorage {
    CFErrorRef cfError = nil;

    SecAccessControlRef access = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                                                 [SecretStore accessibility],
                                                                 requestSecureEnclaveStorage ? kSecAccessControlPrivateKeyUsage : 0L,
                                                                 &cfError);
    
    if(!access) {
        NSLog(@"Error creating AccessControl: [%@]", (__bridge NSError *)cfError);
        return nil;
    }
    
    return access;
}

+ (NSDictionary*)createKeyPairAttributes:(NSString*)identifier
                           accessControl:(SecAccessControlRef)accessControl
             requestSecureEnclaveStorage:(BOOL)requestSecureEnclaveStorage {
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

    if ( !requestSecureEnclaveStorage ) {
        NSMutableDictionary* foo = attributes.mutableCopy;
        [foo removeObjectForKey:(id)kSecAttrTokenID];
        attributes = foo.copy;
    }

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

- (NSDictionary*)getWrappedObject:(NSString *)identifier {
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
    
#if TARGET_OS_IPHONE
    if (@available(ios 10.0, *)) {
        return [self decryptAndDeserializeKeychainBlob:keychainBlob identifier:identifier];
    }
    else {
        return [self deserializeKeychainBlob:keychainBlob identifier:identifier];
    }
#else
    return [self decryptAndDeserializeKeychainBlob:keychainBlob identifier:identifier];
#endif
}

- (NSDictionary*)decryptAndDeserializeKeychainBlob:(NSData*)encrypted identifier:(NSString *)identifier {
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

- (NSDictionary*)deserializeKeychainBlob:(NSData*)plaintext identifier:(NSString *)identifier {
    NSDictionary *wrapped = nil;
    @try {
        wrapped = [NSKeyedUnarchiver unarchiveObjectWithData:plaintext];
    }
    @catch (NSException *e) {
        NSLog(@"Error Ubarchiving: %@", e);
    }
    @finally {}

    if(!wrapped) {
        NSLog(@"Could not unwrap secure item. Cleaning it up.");
        [self deleteSecureItem:identifier];
        return nil;
    }
    
    return wrapped;
}

- (NSDictionary*)decryptWrappedObject:(NSData*)encrypted privateKey:(SecKeyRef)privateKey {
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

- (NSDictionary*)wrapObject:(id)object expiryMode:(SecretExpiryMode)expiryMode expiry:(NSDate*_Nullable)expiry identifier:(NSString*)identifier {
    NSMutableDictionary *wrapped = @{
        kWrappedObjectExpiryModeKey : @(expiryMode)
    }.mutableCopy;
    
    if(expiryMode == kExpiresAtTime) {
        wrapped[kWrappedObjectExpiryKey] = expiry;
    }

    if(expiryMode != kExpiresOnAppExitStoreSecretInMemoryOnly) {
        wrapped[kWrappedObjectObjectKey] = object;
    }
    
    return wrapped;
}

- (BOOL)storeKeychainBlob:(NSString*)identifier encrypted:(NSData*)encrypted {
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

- (NSData*)getKeychainBlob:(NSString*)identifier itemNotFound:(BOOL*)itemNotFound {
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

- (void)deleteKeychainBlob:(NSString*)identifier {
    NSMutableDictionary *query = [self getBlobQuery:identifier];
    
//    NSLog(@"deleteKeychainBlob: Enter");
    OSStatus status = SecItemDelete((__bridge CFDictionaryRef)query);
    if ( status != errSecSuccess && status != errSecItemNotFound ) {
        NSLog(@"Error Deleting Keychain Blob: [%d]", (int)status);
    }
    
//    NSLog(@"deleteKeychainBlob: Exit %d", (int)status);
}

- (NSMutableDictionary*)getBlobQuery:(NSString*)identifier {
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

- (BOOL)entryIsExpired:(NSDate*)expiry {
    return ([expiry timeIntervalSinceNow] < 0);
}

// Minimal

//+ (NSData*)getExample {
//    NSTimeInterval startTime = NSDate.timeIntervalSinceReferenceDate;
//
//    NSMutableDictionary *dictionary = [NSMutableDictionary dictionary];
//
//    [dictionary setObject:(__bridge id)kSecClassGenericPassword forKey:(__bridge id)kSecClass];
//    [dictionary setObject:@"foo-service" forKey:(__bridge id)kSecAttrService];
//    [dictionary setObject:@"foo-account" forKey:(__bridge id)kSecAttrAccount];
//    [dictionary setObject:@NO forKey:(__bridge id)(kSecAttrSynchronizable)]; // No iCloud Sync
//    [dictionary setObject:@YES forKey:(__bridge id)kSecReturnData];
//    [dictionary setObject:(__bridge id)kSecMatchLimitOne forKey:(__bridge id)kSecMatchLimit];
//
//    CFTypeRef result = NULL;
//    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)dictionary, &result);
//
//    NSTimeInterval perf = NSDate.timeIntervalSinceReferenceDate - startTime;
//
//    NSLog(@"====================================== PERF ======================================");
//    NSLog(@"Get took [%f] seconds", perf);
//    NSLog(@"====================================== PERF ======================================");
//
//    if ( status == errSecSuccess ) {
//        return (__bridge_transfer NSData *)result;
//    }
//    else {
//        return nil;
//    }
//}
//
//+ (BOOL)setExample:(NSData*)foo {
//    NSTimeInterval startTime = NSDate.timeIntervalSinceReferenceDate;
//
//    NSMutableDictionary *searchQuery = [NSMutableDictionary dictionary];
//
//    [searchQuery setObject:(__bridge id)kSecClassGenericPassword forKey:(__bridge id)kSecClass];
//    [searchQuery setObject:@"foo-service" forKey:(__bridge id)kSecAttrService];
//    [searchQuery setObject:@"foo-account" forKey:(__bridge id)kSecAttrAccount];
//    [searchQuery setObject:@NO forKey:(__bridge id)(kSecAttrSynchronizable)]; // No iCloud Sync
//
//    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)searchQuery, nil);
//
//    if (status == errSecSuccess) { // Update
//        NSMutableDictionary* query = [NSMutableDictionary dictionary];
//
//        [query setObject:foo forKey:(__bridge id)kSecValueData];
//        [query setObject:(__bridge id)[SecretStore accessibility] forKey:(__bridge id)kSecAttrAccessible];
//
//        status = SecItemUpdate((__bridge CFDictionaryRef)(searchQuery), (__bridge CFDictionaryRef)(query));
//    }
//    else if(status == errSecItemNotFound) { // Add
//        [searchQuery setObject:foo forKey:(__bridge id)kSecValueData];
//        [searchQuery setObject:(__bridge id)[SecretStore accessibility] forKey:(__bridge id)kSecAttrAccessible];
//
//        status = SecItemAdd((__bridge CFDictionaryRef)searchQuery, NULL);
//    }
//
//    NSTimeInterval perf = NSDate.timeIntervalSinceReferenceDate - startTime;
//
//    NSLog(@"====================================== PERF ======================================");
//    NSLog(@"Set took [%f] seconds", perf);
//    NSLog(@"====================================== PERF ======================================");
//
//    return (status == errSecSuccess);
//}
//
//+ (void)getKey:(NSString*)identifier {
//    NSDictionary* query = @{
//        (id)kSecClass :                 (id)kSecClassKey,
//        (id)kSecAttrKeyType :           (id)kSecAttrKeyTypeECSECPrimeRandom,
//        (id)kSecAttrKeySizeInBits:      @256,
//        (id)kSecAttrEffectiveKeySize :  @256,
//        (id)kSecAttrApplicationLabel :  @"Strongbox-Credential-Store-Key",
//        (id)kSecAttrApplicationTag :    [identifier dataUsingEncoding:NSUTF8StringEncoding],
//        (id)kSecReturnRef :             @YES,
//        (id)kSecMatchLimit :            (id)kSecMatchLimitOne, // This doesn't appear to make much/any difference
//    };
//
//    CFTypeRef pk;
//
//    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &pk);
//
//    NSLog(@"%d", (int)status);
//
//    // Can take 2-4 seconds at times, possibly longer, sometimes around 0.5 seconds. Cold starts are slow. Switching away from app and back can lead to it
//    // being slow too. If app is kept in foreground then subsequent reads are reasonably fast, 0.02 seconds-ish
//}

@end
