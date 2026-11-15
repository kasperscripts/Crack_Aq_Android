#import "ICPolicy.h"
#import "ICRelay.h"
#import <objc/runtime.h>
static __thread BOOL ICInRelay;
static id ICRelayObject(id object, unsigned stage, const void *caller) {
    if (ICInRelay || !ICInputReader(caller)) return object;
    ICInRelay=YES;
    BOOL changed=NO;
    id mapped=ICNormalizePayload(object,ICServerKey(),&changed);
    ICRelayRecord(stage,changed);
    ICInRelay=NO;
    return mapped;
}
static BOOL ICInstallMethod(Class cls,SEL selector,IMP replacement,IMP *original) {
    Method m=cls?class_getInstanceMethod(cls,selector):NULL;
    if (!m) return NO;
    *original=method_getImplementation(m);method_setImplementation(m,replacement);return YES;
}
static NSString *(*OldUTF8)(id,SEL,const char *);
static NSString *NewUTF8(id cls, SEL selector, const char *text) {
    NSString *value=OldUTF8(cls,selector,text);
    return ICRelayObject(value,2,__builtin_return_address(0));
}
static NSString *(*OldCString)(id,SEL,const char *,NSStringEncoding);
static NSString *NewCString(id cls,SEL selector,const char *text,NSStringEncoding encoding) {
    NSString *value=OldCString(cls,selector,text,encoding);
    return ICRelayObject(value,2,__builtin_return_address(0));
}
static id (*OldDefaultObject)(id,SEL,NSString *);
static id NewDefaultObject(id object,SEL selector,NSString *key) {
    return ICRelayObject(OldDefaultObject(object,selector,key),4,__builtin_return_address(0));
}
static NSString *(*OldDefaultString)(id,SEL,NSString *);
static NSString *NewDefaultString(id object,SEL selector,NSString *key) {
    return ICRelayObject(OldDefaultString(object,selector,key),4,__builtin_return_address(0));
}
static NSDictionary *(*OldDefaultDictionary)(id,SEL,NSString *);
static NSDictionary *NewDefaultDictionary(id object,SEL selector,NSString *key) {
    return ICRelayObject(OldDefaultDictionary(object,selector,key),4,__builtin_return_address(0));
}
static NSData *(*OldJSON)(id,SEL,id,NSJSONWritingOptions,NSError *__autoreleasing *);
static NSData *NewJSON(id cls,SEL selector,id object,NSJSONWritingOptions options,NSError *__autoreleasing *error) {
    id mapped=ICRelayObject(object,8,__builtin_return_address(0));
    return OldJSON(cls,selector,mapped,options,error);
}
void ICInstallRelay(void) {
    ICInstallMethod(object_getClass(NSString.class),@selector(stringWithUTF8String:),(IMP)NewUTF8,(IMP *)&OldUTF8);
    ICInstallMethod(object_getClass(NSString.class),@selector(stringWithCString:encoding:),(IMP)NewCString,(IMP *)&OldCString);
    ICInstallMethod(NSUserDefaults.class,@selector(objectForKey:),(IMP)NewDefaultObject,(IMP *)&OldDefaultObject);
    ICInstallMethod(NSUserDefaults.class,@selector(stringForKey:),(IMP)NewDefaultString,(IMP *)&OldDefaultString);
    ICInstallMethod(NSUserDefaults.class,@selector(dictionaryForKey:),(IMP)NewDefaultDictionary,(IMP *)&OldDefaultDictionary);
    ICInstallMethod(object_getClass(NSJSONSerialization.class),@selector(dataWithJSONObject:options:error:),(IMP)NewJSON,(IMP *)&OldJSON);
}
