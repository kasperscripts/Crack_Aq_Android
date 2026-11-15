#import "ICPolicy.h"
#include <string.h>
BOOL ICIsUltimaPath(const char *path) {
    return path && strstr(path,"/ultLoader.framework/ultLoader") != NULL;
}
NSString *ICDecodeKey(NSData *data) {
    if (data.length < 10 || memcmp(data.bytes,"ICKEY01\0",8)) return nil;
    const unsigned char *raw = data.bytes;
    NSUInteger count = raw[8];
    if (!count || count > 64 || data.length != 9 + count) return nil;
    unsigned char decoded[64];
    for (NSUInteger i=0; i<count; ++i) decoded[i]=raw[9+i]^((0x5a+i*29)&255);
    return [[NSString alloc] initWithBytes:decoded length:count encoding:NSUTF8StringEncoding];
}
NSString *ICResolveKey(NSString *value, BOOL fromUltima, NSString *serverKey) {
    if (!fromUltima || !serverKey.length || !value || value.length>64) return value;
    NSString *trimmed=[value stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    for (NSString *mark in @[@"\u200B",@"\u200C",@"\u200D",@"\u200E",@"\u200F",@"\u2066",@"\u2067",@"\u2068",@"\u2069",@"\uFEFF"]) trimmed=[trimmed stringByReplacingOccurrencesOfString:mark withString:@""];
    return [trimmed caseInsensitiveCompare:@"@Icon_Crack"]==NSOrderedSame ? serverKey : value;
}
NSString *ICRebrandText(NSString *value, NSString *serverKey) {
    if (!value || value.length>16384) return value;
    NSString *out=value;
    if (serverKey.length) out=[out stringByReplacingOccurrencesOfString:serverKey withString:@"@Icon_Crack"];
    NSRegularExpression *tg=[NSRegularExpression regularExpressionWithPattern:@"(?i)(?:https?://)?(?:www\\.)?(?:t\\.me|telegram\\.me)/[^\\s<>]+" options:0 error:NULL];
    out=[tg stringByReplacingMatchesInString:out options:0 range:NSMakeRange(0,out.length) withTemplate:@"https://t.me/Icon_Crack"];
    NSRegularExpression *tag=[NSRegularExpression regularExpressionWithPattern:@"(?<![A-Za-z0-9._%+\\-])@[A-Za-z0-9_]{3,}" options:0 error:NULL];
    out=[tag stringByReplacingMatchesInString:out options:0 range:NSMakeRange(0,out.length) withTemplate:@"@Icon_Crack"];
    NSRegularExpression *brand=[NSRegularExpression regularExpressionWithPattern:@"(?i)\\b(?:Ultima|Ультима)\\b" options:0 error:NULL];
    return [brand stringByReplacingMatchesInString:out options:0 range:NSMakeRange(0,out.length) withTemplate:@"@Icon_Crack"];
}
NSURL *ICRedirectURL(NSURL *url, BOOL fromUltima) {
    if (!fromUltima || !url) return url;
    NSString *host=url.host.lowercaseString;
    if ([url.scheme.lowercaseString isEqualToString:@"tg"] || [host isEqualToString:@"t.me"] || [host isEqualToString:@"telegram.me"] || [host isEqualToString:@"www.t.me"] || [host isEqualToString:@"www.telegram.me"]) return [NSURL URLWithString:@"https://t.me/Icon_Crack"];
    return url;
}

static id ICNormalizeNode(id value, NSString *serverKey, BOOL *changed, NSUInteger depth) {
    if (!value || depth>16) return value;
    if ([value isKindOfClass:NSString.class]) {
        NSString *mapped=ICResolveKey(value,YES,serverKey);
        if (mapped==value) return value;
        *changed=YES;
        return [value isKindOfClass:NSMutableString.class] ? mapped.mutableCopy : mapped;
    }
    if ([value isKindOfClass:NSArray.class]) {
        NSMutableArray *copy=[NSMutableArray arrayWithCapacity:[value count]];BOOL any=NO;
        for (id item in value) {BOOL itemChanged=NO;[copy addObject:ICNormalizeNode(item,serverKey,&itemChanged,depth+1)];any|=itemChanged;}
        if (!any) return value;*changed=YES;
        return [value isKindOfClass:NSMutableArray.class] ? copy : copy.copy;
    }
    if ([value isKindOfClass:NSDictionary.class]) {
        NSMutableDictionary *copy=[value mutableCopy];BOOL any=NO;
        for (id key in value) {BOOL itemChanged=NO;id mapped=ICNormalizeNode([value objectForKey:key],serverKey,&itemChanged,depth+1);if(itemChanged)copy[key]=mapped;any|=itemChanged;}
        if (!any) return value;*changed=YES;
        return [value isKindOfClass:NSMutableDictionary.class] ? copy : copy.copy;
    }
    return value;
}
id ICNormalizePayload(id value, NSString *serverKey, BOOL *changed) {
    BOOL flag=NO;id mapped=ICNormalizeNode(value,serverKey,&flag,0);if(changed)*changed=flag;return mapped;
}
