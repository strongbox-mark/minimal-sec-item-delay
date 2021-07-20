//
//  ViewController.m
//  minimal-repro-secitemperf
//
//  Created by Strongbox on 13/07/2021.
//

#import "ViewController.h"
#import "SecretStore.h"

@interface ViewController ()

@property (weak, nonatomic) IBOutlet UILabel *label;

@end

static NSString* const kString = @"bar";
static NSString* const kIdentifier = @"foo";

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    
    [SecretStore setSecureString:kString forIdentifier:kIdentifier];
}

- (IBAction)onGetSecret:(id)sender {
    NSTimeInterval startTime = NSDate.timeIntervalSinceReferenceDate;

    id obj = [SecretStore getSecureString:kIdentifier];
    
    NSTimeInterval perf = NSDate.timeIntervalSinceReferenceDate - startTime;
    
    NSLog(@"onGetSecret took [%f] seconds with object: [%@]", perf, obj);
    
    self.label.text = [NSString stringWithFormat:@"Took %f seconds", perf];
}

@end
