//
//  CredentialsStore.h
//  Strongbox
//
//  Created by Mark on 13/01/2020.
//  Copyright © 2014-2021 Mark McGuill. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface SecretStore : NSObject

+ (BOOL)setSecureString:(NSString* _Nullable)string forIdentifier:(NSString*)identifier;

+ (NSString*_Nullable)getSecureString:(NSString*)identifier;

@end

NS_ASSUME_NONNULL_END
