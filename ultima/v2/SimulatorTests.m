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
        UITextField *field=[[UITextField alloc] initWithFrame:CGRectMake(0,0,240,44)];
        field.text=@"@Icon_Crack";
        results[@"direct_field_read"]=@([field.text isEqualToString:expected]);
        results[@"kvc_forwarded_read"]=@([[field valueForKey:@"text"] isEqualToString:expected]);
        results[@"visible_storage_preserved"]=@([field.attributedText.string isEqualToString:@"@Icon_Crack"]);
        field.text=@"  @Icon_Crack\n";
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
        results[@"failure_diagnostic"]=@([label.text containsString:@"IC2-R1"]);
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
