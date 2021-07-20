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
@property NSString* identifier;

@end

static NSString* const kString = @"bar";

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    
    self.identifier = NSUUID.UUID.UUIDString;
    
    [SecretStore setSecureString:kString forIdentifier:self.identifier];
}

- (IBAction)onGetSecret:(id)sender {
    NSTimeInterval startTime = NSDate.timeIntervalSinceReferenceDate;

    id obj = [SecretStore getSecureString:self.identifier];
    
    NSTimeInterval perf = NSDate.timeIntervalSinceReferenceDate - startTime;
    
    NSLog(@"onGetSecret took [%f] seconds with object: [%@]", perf, obj);
    
    self.label.text = [NSString stringWithFormat:@"Took %f seconds", perf];
}

@end
