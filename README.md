# JdCrypt::Blowfish

**Important Advice**: you should probably use the OpenSSL extension instead.

This is a from-scratch implementation of the Blowfish encryption cipher as a C
Ruby extension (as well as a pure-Ruby counterpart).

## Usage

```ruby
require "jdcrypt/blowfish"

# For a single block
cipher = JdCrypt::Blowfish.new(my_key)
block_ciphertext = blowcypher.encrypt(my_plaintext_block)

# For a stream, using CBC (not provided here)

require "jdcrypt/cbc"
cbc = JdCrypt::CBC.new(cipher)

long_ciphertext = cbc.encrypt(iv, long_plaintext)
```

# COMPATIBILITY AND PERFORMANCE

Ruby 2.6: binary: roughly 11MB/s; pure Ruby: roughly 400KB/s.

# COPYRIGHT

This files in this distribution (with the exception of bwulf10.txt) are
copyright 2005-2023 Jim Driscoll <jim.a.driscoll@gmail.com>; please see the included file COPYING for details.
