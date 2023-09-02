# frozen_string_literal: true

require "jdcrypt/blowfish/core" unless defined? JdCrypt::Blowfish::Core

class JdCrypt
  # Provides Blowfish encryption support
  class Blowfish
    # Provides a list of block sizes (bytes) which are supported
    def self.block_sizes_supported
      [64 / 8]
    end

    def initialize(key)
      p "Debugging" if $DEBUG
      throw :too_few_digits if PiDigits.length < Core.needed_pi_digits
      @derivedkey = Core.new(PiDigits)
      @derivedkey.update_from_key(key)
      if $DEBUG
        p @derivedkey.sboxes
        p @derivedkey.subkeys
      end
    end

    def block_sizes_supported
      Blowfish.block_sizes_supported
    end

    def encrypt(string)
      p "Enc" if $DEBUG
      @derivedkey.crypt(string, :encrypt)
    end

    def decrypt(string)
      p "Dec" if $DEBUG
      @derivedkey.crypt(string, :decrypt)
    end
  end
end
