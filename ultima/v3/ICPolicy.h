#import <Foundation/Foundation.h>
FOUNDATION_EXPORT NSString *ICDecodeKey(NSData *data);
FOUNDATION_EXPORT NSString *ICResolveKey(NSString *value, BOOL fromUltima, NSString *serverKey);
FOUNDATION_EXPORT NSString *ICRebrandText(NSString *value, NSString *serverKey);
FOUNDATION_EXPORT NSURL *ICRedirectURL(NSURL *url, BOOL fromUltima);
FOUNDATION_EXPORT BOOL ICIsUltimaPath(const char *path);

FOUNDATION_EXPORT id ICNormalizePayload(id value, NSString *serverKey, BOOL *changed);
