# Basic Apple Encrypted Archive Decryption implementation

@nicolas17 was looking for someone to implement this file format based off the description
at https://theapplewiki.com/wiki/Apple_Encrypted_Archive to ensure that it is accurate/complete.
This is the implementation I wrote as a result.

I've aimed to keep the implementation as easy to understand as possible.
Whether I've succeeded is an open question.
As a result, it's a bit slow.


## Things not specified in wiki page at time of writing
- The CTR block mode appears to be using a big endian counter.
- nitpick: It is not specified when a segment should be decompressed or not.
  - presumably this is just "the compressed and decompressed sizes differ."
- For profile 0, which includes no padding, what is the "next cluster hmac" in the final cluster?
- For all profiles, what are the segment HMACs for empty segments?
- What is the format of the 160 byte prologue signature for encrypted profiles?
  - From a quick glance at libNeoAppleArchive, looks like it's encrypted.
