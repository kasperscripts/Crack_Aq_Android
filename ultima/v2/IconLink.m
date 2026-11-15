#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import "ICPolicy.h"
#include <dlfcn.h>
#include <stdatomic.h>
#include "ICEmbeddedKey.h"

@interface ICBuild10Anchor : NSObject @end
@implementation ICBuild10Anchor @end

static NSString *ICServerKey(void) {
    static NSString *key;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSData *data=[NSData dataWithBytes:ICEmbeddedAlias length:sizeof(ICEmbeddedAlias)];
        key=ICDecodeKey(data);
    });
    return key;
}
static BOOL ICCaller(const void *address) {
    Dl_info info;
    return address && dladdr(address,&info) && ICIsUltimaPath(info.dli_fname);
}
static BOOL ICReplace(Class cls, SEL selector, IMP replacement, IMP *original) {
    Method method=cls ? class_getInstanceMethod(cls,selector) : NULL;
    if (!method) return NO;
    *original=method_getImplementation(method);
    method_setImplementation(method,replacement);
    return YES;
}
static _Atomic(unsigned) ICAliasReads;
static BOOL ICInputReader(const void *address) {
    Dl_info info;
    if (!address || !dladdr(address,&info) || !info.dli_fname) return YES;
    const char *path=info.dli_fname;
    if (strstr(path,"/UIKitCore.framework/") || strstr(path,"/UIKit.framework/") || strstr(path,"/UIFoundation.framework/") || strstr(path,"/TextInputUI.framework/") || strstr(path,"/UnityFramework.framework/UnityFramework")) return NO;
    return YES;
}
static NSString *ICMapInput(NSString *value, BOOL reader) {
    NSString *key=ICServerKey();
    NSString *mapped=ICResolveKey(value,reader,key);
    if (mapped != value) atomic_fetch_add_explicit(&ICAliasReads,1,memory_order_relaxed);
    return mapped;
}
static NSString *ICFailureDetail(NSString *text) {
    if (!text) return nil;
    if ([text rangeOfString:@"AUTH-KEY-403"].location==NSNotFound || [text rangeOfString:@"IC2-"].location!=NSNotFound) return text;
    NSString *state=ICServerKey().length ? (atomic_load_explicit(&ICAliasReads,memory_order_relaxed) ? @"IC2-R1" : @"IC2-R0") : @"IC2-K0";
    return [text stringByAppendingFormat:@"\n[%@]",state];
}
static NSString *(*OldText)(id,SEL);
static NSString *NewText(id object, SEL selector) {
    return ICMapInput(OldText(object,selector),ICInputReader(__builtin_return_address(0)));
}
static NSString *(*OldTextView)(id,SEL);
static NSString *NewTextView(id object, SEL selector) {
    return ICMapInput(OldTextView(object,selector),ICInputReader(__builtin_return_address(0)));
}
static void (*OldLabel)(id,SEL,NSString *);
static void NewLabel(id object, SEL selector, NSString *text) {
    if (ICCaller(__builtin_return_address(0))) text=ICRebrandText(text,ICServerKey());
    OldLabel(object,selector,ICFailureDetail(text));
}
static void (*OldButton)(id,SEL,NSString *,UIControlState);
static void NewButton(id object, SEL selector, NSString *title, UIControlState state) {
    if (ICCaller(__builtin_return_address(0))) title=ICRebrandText(title,ICServerKey());
    OldButton(object,selector,title,state);
}
static void (*OldPlaceholder)(id,SEL,NSString *);
static void NewPlaceholder(id object, SEL selector, NSString *text) {
    if (ICCaller(__builtin_return_address(0))) {
        NSString *lower=text.lowercaseString;
        if ([lower isEqualToString:@"key"] || [lower isEqualToString:@"license key"] || [lower isEqualToString:@"enter key"] || [lower isEqualToString:@"ключ"] || [lower isEqualToString:@"введите ключ"]) text=@"@Icon_Crack";
        else text=ICRebrandText(text,ICServerKey());
    }
    OldPlaceholder(object,selector,text);
}
static UIAlertController *(*OldAlert)(id,SEL,NSString *,NSString *,UIAlertControllerStyle);
static UIAlertController *NewAlert(id object, SEL selector, NSString *title, NSString *message, UIAlertControllerStyle style) {
    if (ICCaller(__builtin_return_address(0))) {
        title=ICRebrandText(title,ICServerKey());
        message=ICRebrandText(message,ICServerKey());
    }
    return OldAlert(object,selector,title,ICFailureDetail(message),style);
}
static BOOL (*OldOpen)(id,SEL,NSURL *);
static BOOL NewOpen(id object, SEL selector, NSURL *url) {
    return OldOpen(object,selector,ICRedirectURL(url,ICCaller(__builtin_return_address(0))));
}
static void (*OldOpenOptions)(id,SEL,NSURL *,NSDictionary *,void (^)(BOOL));
static void NewOpenOptions(id object, SEL selector, NSURL *url, NSDictionary *options, void (^completion)(BOOL)) {
    OldOpenOptions(object,selector,ICRedirectURL(url,ICCaller(__builtin_return_address(0))),options,completion);
}
static void (*OldMenuLoad)(id,SEL);
static void ICAddCaption(UIViewController *controller) {
    UIView *view=controller.view;
    if (!view || [view viewWithTag:0x49434b]) return;
    UILabel *label=[UILabel new];
    label.tag=0x49434b;
    label.text=@"cracked by @Icon_Crack";
    label.font=[UIFont systemFontOfSize:12 weight:UIFontWeightMedium];
    label.textColor=UIColor.secondaryLabelColor;
    label.textAlignment=NSTextAlignmentRight;
    label.userInteractionEnabled=NO;
    label.translatesAutoresizingMaskIntoConstraints=NO;
    [view addSubview:label];
    UILayoutGuide *guide=view.safeAreaLayoutGuide;
    [NSLayoutConstraint activateConstraints:@[
        [label.leadingAnchor constraintEqualToAnchor:guide.leadingAnchor constant:12],
        [label.trailingAnchor constraintEqualToAnchor:guide.trailingAnchor constant:-12],
        [label.bottomAnchor constraintEqualToAnchor:guide.bottomAnchor constant:-4],
        [label.heightAnchor constraintEqualToConstant:18]
    ]];
}
static void NewMenuLoad(id object, SEL selector) {
    OldMenuLoad(object,selector);
    ICAddCaption(object);
}
static void ICInstallMenu(NSUInteger attempt) {
    Class menu=NSClassFromString(@"OxideUIKitMenuController");
    if (ICReplace(menu,@selector(viewDidLoad),(IMP)NewMenuLoad,(IMP *)&OldMenuLoad)) return;
    if (attempt<20) dispatch_after(dispatch_time(DISPATCH_TIME_NOW,NSEC_PER_SEC/2),dispatch_get_main_queue(),^{ICInstallMenu(attempt+1);});
}
__attribute__((constructor)) static void ICInstall(void) {
    @autoreleasepool {
        ICReplace(UITextField.class,@selector(text),(IMP)NewText,(IMP *)&OldText);
        ICReplace(UITextView.class,@selector(text),(IMP)NewTextView,(IMP *)&OldTextView);
        ICReplace(UILabel.class,@selector(setText:),(IMP)NewLabel,(IMP *)&OldLabel);
        ICReplace(UIButton.class,@selector(setTitle:forState:),(IMP)NewButton,(IMP *)&OldButton);
        ICReplace(UITextField.class,@selector(setPlaceholder:),(IMP)NewPlaceholder,(IMP *)&OldPlaceholder);
        ICReplace(object_getClass(UIAlertController.class),@selector(alertControllerWithTitle:message:preferredStyle:),(IMP)NewAlert,(IMP *)&OldAlert);
        ICReplace(UIApplication.class,@selector(openURL:),(IMP)NewOpen,(IMP *)&OldOpen);
        ICReplace(UIApplication.class,@selector(openURL:options:completionHandler:),(IMP)NewOpenOptions,(IMP *)&OldOpenOptions);
        ICInstallMenu(0);
    }
}
