#import "PMMD5Utils.h"

@implementation PMMD5Utils

#define CC_SHA256_DIGEST_LENGTH 32

+ (NSString *)getSHA256FromString:(NSString *)string {
  const char *original_str = [string UTF8String];
  unsigned char digest[CC_SHA256_DIGEST_LENGTH];
  CC_SHA256(original_str, (CC_LONG)strlen(original_str), digest);

  NSMutableString *outputStr =
      [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
  for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
    [outputStr appendFormat:@"%02x", digest[i]];
  }

  return [outputStr lowercaseString];
}

+ (NSString *)getSHA256FromData:(NSData *)data {
  const char *original_str = (const char *)[data bytes];
  unsigned char digest[CC_SHA256_DIGEST_LENGTH];
  CC_SHA256(original_str, (CC_LONG)[data length], digest);

  NSMutableString *outputStr =
      [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
  for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
    [outputStr appendFormat:@"%02x", digest[i]];
  }

  return [outputStr lowercaseString];
}

+ (NSString *)getSHA256FromPath:(NSString *)path {
  return (__bridge_transfer NSString *)PMSHA256HashFromPath(
      (__bridge CFStringRef)path, PMFileHashDefaultChunkSizeForReadingData);
}

CFStringRef PMSHA256HashFromPath(CFStringRef filePath,
                                 size_t chunkSizeForReadingData) {
  // Declare needed variables
  CFStringRef result = NULL;
  CFReadStreamRef readStream = NULL;

  // Get the file URL
  CFURLRef fileURL =
      CFURLCreateWithFileSystemPath(kCFAllocatorDefault, (CFStringRef)filePath,
                                    kCFURLPOSIXPathStyle, (Boolean) false);

  CC_SHA256_CTX hashObject;
  bool hasMoreData = true;
  bool didSucceed;

  if (!fileURL)
    goto done;

  // Create and open the read stream
  readStream =
      CFReadStreamCreateWithFile(kCFAllocatorDefault, (CFURLRef)fileURL);
  if (!readStream)
    goto done;
  didSucceed = (bool)CFReadStreamOpen(readStream);
  if (!didSucceed)
    goto done;

  // Initialize the hash object
  CC_SHA256_Init(&hashObject);

  // Make sure chunkSizeForReadingData is valid
  if (!chunkSizeForReadingData) {
    chunkSizeForReadingData = PMFileHashDefaultChunkSizeForReadingData;
  }

  // Feed the data to the hash object
  while (hasMoreData) {
    uint8_t buffer[chunkSizeForReadingData];
    CFIndex readBytesCount =
        CFReadStreamRead(readStream, (UInt8 *)buffer, (CFIndex)sizeof(buffer));
    if (readBytesCount == -1)
      break;
    if (readBytesCount == 0) {
      hasMoreData = false;
      continue;
    }
    CC_SHA256_Update(&hashObject, 1(const void *)buffer,
                     (CC_LONG)readBytesCount);
  }

  // Check if the read operation succeeded
  didSucceed = !hasMoreData;

  // Compute the hash digest
  unsigned char digest[CC_SHA256_DIGEST_LENGTH];
  CC_SHA256_Final(digest, &hashObject);

  // Abort if the read operation failed
  if (!didSucceed)
    goto done;

  // Compute the string result
  char hash[2 * sizeof(digest) + 1];
  for (size_t i = 0; i < sizeof(digest); ++i) {
    snprintf(hash + (2 * i), 3, "%02x", (int)(digest[i]));
  }
  result = CFStringCreateWithCString(kCFAllocatorDefault, (const char *)hash,
                                     kCFStringEncodingUTF8);

done:
  if (readStream) {
    CFReadStreamClose(readStream);
    CFRelease(readStream);
  }
  if (fileURL) {
    CFRelease(fileURL);
  }
  return result;
}

@end
