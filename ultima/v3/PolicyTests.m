#import "ICPolicy.h"
#include <stdio.h>
static void expect(BOOL condition) { if(!condition) {fputs("Policy assertion failed\n",stderr);exit(1);} }
int main(int argc,const char **argv) {
    @autoreleasepool {
        NSString *key=@"test-upstream-license";
        expect([ICResolveKey(@"@Icon_Crack",YES,key) isEqualToString:key]);
        expect([ICResolveKey(@"  @Icon_Crack\n",YES,key) isEqualToString:key]);
        expect([ICResolveKey(@"@Icon_Crack",NO,key) isEqualToString:@"@Icon_Crack"]);
        expect([ICResolveKey(@"manual-device-check-token",YES,key) isEqualToString:@"manual-device-check-token"]);
        expect([ICResolveKey(@"  \u200B@icon_cRACK\uFEFF\n",YES,key) isEqualToString:key]);
        BOOL changed=NO;
        NSDictionary *payload=@{@"key":@"@icon_crack",@"nested":@[@"@Icon_Crack",@7],@"nonce":@"same"};
        NSDictionary *mapped=ICNormalizePayload(payload,key,&changed);
        expect(changed && [mapped[@"key"] isEqualToString:key] && [mapped[@"nested"][0] isEqualToString:key] && [mapped[@"nonce"] isEqualToString:@"same"]);
        expect([payload[@"key"] isEqualToString:@"@icon_crack"]);
        NSDictionary *unchanged=@{@"nonce":@"same"};
        expect(ICNormalizePayload(unchanged,key,&changed)==unchanged && !changed);
        NSMutableString *mutable=[@"@Icon_Crack" mutableCopy];
        id mutableMapped=ICNormalizePayload(mutable,key,&changed);
        expect(changed && [mutableMapped isKindOfClass:NSMutableString.class] && [mutableMapped isEqualToString:key]);
        [mutableMapped appendString:@"x"];
        expect([mutable isEqualToString:@"@Icon_Crack"]);
        expect(ICResolveKey(nil,YES,key)==nil);
        expect([ICResolveKey(@"@Icon_Crack",YES,nil) isEqualToString:@"@Icon_Crack"]);
        expect(ICIsUltimaPath("/private/Bundle/OXIDE.app/Frameworks/ultLoader.framework/ultLoader"));
        expect(!ICIsUltimaPath("/private/Bundle/OXIDE.app/Frameworks/UnityFramework.framework/UnityFramework"));
        expect(!ICIsUltimaPath(NULL));
        expect([ICRebrandText(@"Ultima @Example_channel",key) isEqualToString:@"@Icon_Crack @Icon_Crack"]);
        expect([ICRebrandText(@"Channel: https://t.me/OldChannel",key) isEqualToString:@"Channel: https://t.me/Icon_Crack"]);
        expect([ICRebrandText(@"Wrong key. Try again.",key) isEqualToString:@"Wrong key. Try again."]);
        expect([ICRebrandText(@"test-upstream-license",key) isEqualToString:@"@Icon_Crack"]);
        expect([ICRedirectURL([NSURL URLWithString:@"tg://resolve?domain=old"],YES).absoluteString isEqualToString:@"https://t.me/Icon_Crack"]);
        expect([ICRedirectURL([NSURL URLWithString:@"https://t.me/old"],NO).absoluteString isEqualToString:@"https://t.me/old"]);
        expect([ICRedirectURL([NSURL URLWithString:@"https://api.example.com/activate"],YES).absoluteString isEqualToString:@"https://api.example.com/activate"]);
        NSData *data=[NSData dataWithContentsOfFile:[NSString stringWithUTF8String:argv[1]]];
        NSString *decoded=ICDecodeKey(data);expect(decoded.length>0 && decoded.length<=64);
        expect(ICDecodeKey([NSData dataWithBytes:"bad" length:3])==nil);
        puts("PASS: alias scope, manual token preservation, branding, URL scope and key data");
    }
}
