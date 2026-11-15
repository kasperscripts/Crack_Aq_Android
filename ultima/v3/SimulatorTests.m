#import <UIKit/UIKit.h>
#import "ICPolicy.h"
#include <stdio.h>

@interface ICRelayDelegate : UIResponder <UIApplicationDelegate>
@property(nonatomic,strong) UIWindow *window;
@end
@implementation ICRelayDelegate
- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)options {
    self.window=[[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    self.window.rootViewController=[UIViewController new];
    [self.window makeKeyAndVisible];
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,NSEC_PER_SEC),dispatch_get_main_queue(),^{
        NSString *expected=[NSString stringWithContentsOfFile:[NSBundle.mainBundle pathForResource:@"expected" ofType:@"txt"] encoding:NSUTF8StringEncoding error:NULL];
        NSMutableDictionary *results=[NSMutableDictionary new];
        // Exercise the launch paths before creating any input field.
        results[@"native_utf8_factory"]=@([[NSString stringWithUTF8String:"@icon_crack"] isEqualToString:expected]);
        results[@"native_cstring_factory"]=@([[NSString stringWithCString:"@ICON_CRACK" encoding:NSUTF8StringEncoding] isEqualToString:expected]);
        NSMutableString *mutable=[NSMutableString stringWithUTF8String:"@Icon_Crack"];
        BOOL mutableMapped=[mutable isEqualToString:expected];
        [mutable appendString:@"x"];
        results[@"mutable_string_type_preserved"]=@(mutableMapped && [mutable isEqualToString:[expected stringByAppendingString:@"x"]]);
        NSUserDefaults *defaults=[[NSUserDefaults alloc] initWithSuiteName:@"com.icon.crack.relaytest-cache"];
        [defaults setObject:@"@Icon_Crack" forKey:@"license-key"];
        [defaults setObject:@{@"license":@"@icon_crack",@"nonce":@"keep-this-nonce"} forKey:@"cached-license"];
        results[@"cached_string_at_startup"]=@([[defaults stringForKey:@"license-key"] isEqualToString:expected]);
        results[@"cached_object_at_startup"]=@([[defaults objectForKey:@"license-key"] isEqualToString:expected]);
        NSDictionary *cached=[defaults dictionaryForKey:@"cached-license"];
        results[@"cached_dictionary_at_startup"]=@([cached[@"license"] isEqualToString:expected] && [cached[@"nonce"] isEqualToString:@"keep-this-nonce"]);
        NSDictionary *request=@{@"license_key":@"@Icon_Crack",@"nonce":@"keep-this-nonce",@"device":@"test-device"};
        NSData *requestData=[NSJSONSerialization dataWithJSONObject:request options:0 error:NULL];
        NSDictionary *encoded=[NSJSONSerialization JSONObjectWithData:requestData options:0 error:NULL];
        results[@"outgoing_json_before_encryption"]=@([encoded[@"license_key"] isEqualToString:expected]);
        results[@"request_fields_preserved"]=@([encoded[@"nonce"] isEqualToString:@"keep-this-nonce"] && [encoded[@"device"] isEqualToString:@"test-device"] && [request[@"license_key"] isEqualToString:@"@Icon_Crack"]);
        NSDictionary *response=[NSJSONSerialization JSONObjectWithData:[@"{\"error\":\"AUTH-KEY-403\",\"key\":\"@Icon_Crack\"}" dataUsingEncoding:NSUTF8StringEncoding] options:0 error:NULL];
        results[@"incoming_response_unmodified"]=@([response[@"error"] isEqualToString:@"AUTH-KEY-403"] && [response[@"key"] isEqualToString:@"@Icon_Crack"]);
        UITextField *field=[[UITextField alloc] initWithFrame:CGRectMake(0,0,240,44)];
        field.text=@"@Icon_Crack";
        results[@"direct_field_read"]=@([field.text isEqualToString:expected]);
        results[@"kvc_forwarded_read"]=@([[field valueForKey:@"text"] isEqualToString:expected]);
        results[@"visible_storage_preserved"]=@([field.attributedText.string isEqualToString:@"@Icon_Crack"]);
        field.text=@"  \u200B@iCon_cRack\uFEFF\n";
        results[@"pasted_alias"]=@([field.text isEqualToString:expected]);
        field.text=@"manual-device-check-token";
        results[@"manual_token_preserved"]=@([field.text isEqualToString:@"manual-device-check-token"]);
        UIAlertController *alert=[UIAlertController alertControllerWithTitle:@"Test" message:nil preferredStyle:UIAlertControllerStyleAlert];
        [alert addTextFieldWithConfigurationHandler:^(UITextField *f){f.text=@"@Icon_Crack";}];
        UITextField *alertField=alert.textFields.firstObject;
        results[@"private_alert_field"]=@([alertField.text isEqualToString:expected]);
        results[@"private_alert_kvc"]=@([[alertField valueForKey:@"text"] isEqualToString:expected]);
        UITextView *view=[UITextView new];view.text=@"@Icon_Crack";
        results[@"text_view_read"]=@([view.text isEqualToString:expected]);
        view.text=@"ordinary text";
        results[@"ordinary_text_preserved"]=@([view.text isEqualToString:@"ordinary text"]);
        field.text=@"@Icon_Crack";
        [self.window.rootViewController.view addSubview:field];
        [field becomeFirstResponder];
        [field insertText:@"x"];
        BOOL added=[field.text isEqualToString:@"@Icon_Crackx"];
        [field deleteBackward];
        results[@"editing_after_read"]=@(added && [field.text isEqualToString:expected]);
        UILabel *label=[UILabel new];label.text=@"Invalid license key. [AUTH-KEY-403]";
        results[@"failure_diagnostic"]=@([label.text containsString:@"IC3-S0F-M0F"]);
        BOOL passed=expected.length>0;
        for (NSNumber *value in results.allValues) passed=passed && value.boolValue;
        NSString *file=[NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,NSUserDomainMask,YES).firstObject stringByAppendingPathComponent:@"relay-tests.json"];
        NSData *data=[NSJSONSerialization dataWithJSONObject:results options:NSJSONWritingPrettyPrinted error:NULL];
        [data writeToFile:file atomically:YES];
        if (passed) puts("IC_UIKIT_PASS");else puts("IC_UIKIT_FAIL");
        fflush(stdout);exit(passed?0:1);
    });
    return YES;
}
@end
int main(int argc,char **argv) {
    @autoreleasepool {return UIApplicationMain(argc,argv,nil,NSStringFromClass(ICRelayDelegate.class));}
}
