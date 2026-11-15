#import <Foundation/Foundation.h>
FOUNDATION_EXPORT NSString *ICServerKey(void);
FOUNDATION_EXPORT BOOL ICInputReader(const void *address);
FOUNDATION_EXPORT void ICRelayRecord(unsigned stage, BOOL mapped);
FOUNDATION_EXPORT void ICInstallRelay(void);
