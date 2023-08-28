# frozen_string_literal: true

require "jdcrypt/bytestream" unless defined? JdCrypt::ByteStream

class JdCrypt
  class Blowfish
    Rounds = 16
    SubkeyCount = Rounds + 2
    SubkeySize = 4
    SboxCount = 4
    SboxSize = 256
    SboxEntrySize = 4

    # Lightweight copyable array
    class SubkeyArray < Array
      def initialize_copy(old)
        old.size.times do |i|
          self[i] = old[i].dup
        end
      end
    end

    # It's a blowfish sbox
    class Sbox < Array
      def initialize_copy(old)
        old.size.times do |i|
          self[i] = old[i].dup
        end
      end
    end

    # Provides the core of the Blowfish encryption.
    class Core
      def subkeys
        @subkeys.join("")
      end

      def sboxes
        @sboxes.collect { |sb| sb.join("") }.join("")
      end

      def self.needed_pi_digits
        (SubkeyCount * SubkeySize) + (SboxCount * SboxSize * SboxEntrySize)
      end

      def initialize(pi_digits_string)
        @subkeys = SubkeyArray.new(SubkeyCount)
        SubkeyCount.times do |i|
          @subkeys[i] = pi_digits_string[i * SubkeySize, SubkeySize]
        end
        offset = SubkeyCount * SubkeySize
        @sboxes = (0..SboxCount - 1).map do |i|
          sbox_data = pi_digits_string[offset + (i * SboxSize * SboxEntrySize), SboxSize * SboxEntrySize]
          sbox = Sbox.new
          SboxSize.times do |j|
            sbox[j] = JdCrypt::ByteStream.new(sbox_data[j * SboxEntrySize, SboxEntrySize])
          end
          sbox
        end
      end

      def core_function(half_block)
        # These are no-overflow 32-bit pluses below.
        ((@sboxes[0][half_block.byte_at(0)] + @sboxes[1][half_block.byte_at(1)]) ^ @sboxes[2][half_block.byte_at(2)]) +
          @sboxes[3][half_block.byte_at(3)]
      end

      def crypt(string, mode = :encrypt)
        raise unless string.length == 8

        if mode == :encrypt
          parray = @subkeys
        elsif mode == :decrypt
          parray = @subkeys.reverse
        else
          raise
        end
        x_left = JdCrypt::ByteStream.new(string[0, 4])
        x_right = JdCrypt::ByteStream.new(string[4, 4])
        puts "I #{x_left.unpack("I")} #{x_right.unpack("I")}" if $DEBUG
        0.upto(15) do |i|
          x_left ^= parray[i]
          puts "Q #{parray[i].unpack("I")} #{core_function(x_left).unpack("I")}" if $DEBUG
          x_right ^= core_function(x_left)
          puts "R #{x_left.unpack("I")} #{x_right.unpack("I")}" if $DEBUG
          x_left, x_right = x_right, x_left
        end
        x_left, x_right = x_right, x_left

        x_right ^= parray[Rounds]
        x_left ^= parray[Rounds + 1]
        JdCrypt::ByteStream.new(x_left.to_str + x_right.to_str)
      end

      def update_from_key(key)
        key_chunk_count = key.length / SubkeySize
        # For each chunk of the key, XOR it into @subkeys[i], repeating as necessary.
        SubkeyCount.times do |i|
          key_i = i.modulo(key_chunk_count)
          @subkeys[i] = JdCrypt::ByteStream.new(key[key_i * SubkeySize, SubkeySize]) ^ @subkeys[i]
        end
        if $DEBUG
          sks = @subkeys.map { |k| k.unpack("I") }
          puts "sk #{sks.join(" ")} #{key[0, SubkeySize].unpack("I")} #{key[SubkeySize, SubkeySize].unpack("I")} \
            #{key[2 * SubkeySize, SubkeySize].unpack("I")} (#{key.length})"
        end

        keygen_magic = "\x00\x00\x00\x00\x00\x00\x00\x00"
        # For all the subkeys, then the s-boxes, replace the contents
        # with the results of an encryption of the current magic value
        # (replacing the magic value also)
        (0..(SubkeyCount / 2) - 1).each do |i|
          keygen_magic = crypt(keygen_magic, :encrypt)
          @subkeys[i * 2] = JdCrypt::ByteStream.new(keygen_magic[0, 4])
          @subkeys[(i * 2) + 1] = JdCrypt::ByteStream.new(keygen_magic[4, 4])
        end
        puts "Subkeys done #{@subkeys[0].unpack("I")}" if $DEBUG
        (0..SboxCount - 1).each do |i|
          (0..(SboxSize / 2) - 1).each do |j|
            keygen_magic = crypt(keygen_magic, :decrypt)
            @sboxes[i][j * 2] = JdCrypt::ByteStream.new(keygen_magic[0, 4])
            @sboxes[i][(j * 2) + 1] = JdCrypt::ByteStream.new(keygen_magic[4, 4])
          end
        end
        puts "S-boxes done #{@sboxes[0][0].unpack("I")}" if $DEBUG
      end
    end
  end
end
