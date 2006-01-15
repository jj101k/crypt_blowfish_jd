#require 'profile'
require 'bytestream'
class Crypt
	class Blowfish
		Rounds=16
		SubkeyCount=Rounds+2
		SubkeySize=4
		SboxCount=4
		SboxSize=256
		SboxEntrySize=4

		class Pi
			def Pi.fraction_bytes(count=1)
				digits=""
				hexdigits=%w{0 1 2 3 4 5 6 7 8 9 a b c d e f}
				remainder_b = nil
				remainder_t = nil
				(0 .. 2*count.to_i).each do
					|k|
					a=8*k+1
					b=8*k+4
					c=8*k+5
					d=8*k+6
					e=16**k

					top=(4*d*c*b - 2*d*c*a - 1*d*b*a - 1*c*b*a)
					bottom=(a*b*c*d)
					if(remainder_b)
						top=(top*remainder_b + remainder_t*16*bottom)
						bottom=(remainder_b*bottom)
					end
					pi_digit = top/bottom
					if(remainder_b)
						digits+=hexdigits[pi_digit]
					end
					remainder_t=top-(pi_digit*bottom)
					remainder_b=bottom
					#remainder_t, remainder_b=*(reduce_fraction(remainder_t, remainder_b))
				end
				[digits].pack("H*")
			end
		end
		class SubkeyArray < Array
			def initialize_copy(old)
				old.size.times do
					|i|
					self[i]=old[i].dup
				end
			end
		end
		class Sbox < Array
			def initialize_copy(old)
				old.size.times do
					|i|
					self[i]=old[i].dup
				end
			end
		end
		class DerivedKey
			attr_reader :subkeys, :sboxes
			def initialize_copy(old)
				@sboxes=[]
				old.sboxes.size.times do
					|i|
					@sboxes[i]=old.sboxes[i].dup
				end
				@subkeys=old.subkeys.dup
			end
			def initialize
				@subkeys=SubkeyArray.new(SubkeyCount)
				@sboxes=[]
				subkey_chunk=Crypt::Blowfish::Pi::fraction_bytes(SubkeyCount*SubkeySize+SboxCount*SboxSize*SboxEntrySize)
				SubkeyCount.times do
					|i|
					@subkeys[i]=subkey_chunk[(i*SubkeySize), SubkeySize]
				end
				offset=SubkeyCount*SubkeySize
				SboxCount.times do
					|i|
					sbox_data = subkey_chunk[offset+(i*SboxSize*SboxEntrySize), SboxSize*SboxEntrySize]
					@sboxes[i]=Sbox.new
					SboxSize.times do
						|j|
						@sboxes[i][j] = ByteStream.new(sbox_data[j*SboxEntrySize, SboxEntrySize])
					end
				end
			end
			def core_function(half_block)
					# These are no-overflow 32-bit pluses below.
					( ( @sboxes[0][half_block[0]] + @sboxes[1][half_block[1]] ) ^ @sboxes[2][half_block[2]] ) + @sboxes[3][half_block[3]]
			end
			def crypt(string, mode=:encrypt)
				raise unless string.length==8
				if(mode==:encrypt)	
					parray=@subkeys
				elsif(mode==:decrypt)
					parray=@subkeys.reverse
				else
					raise
				end
				x_left=ByteStream.new(string[0, 4])
				x_right=ByteStream.new(string[4, 4])
				(0 .. 15).each do
					|i|
					x_left^=parray[i]
					x_right^=core_function(x_left)
					x_left, x_right = x_right, x_left
				end
				x_left, x_right = x_right, x_left

				x_right^=parray[Rounds]
				x_left^=parray[Rounds+1]
				ByteStream.new(x_left.to_str + x_right.to_str)
			end
			def update_from_key(key)
				key_chunk_count=key.length/SubkeySize
				# For each chunk of the key, XOR it into @subkeys[i], repeating as necessary.
				SubkeyCount.times do
					|i|
					key_i=i.modulo(key_chunk_count)
					@subkeys[i]=ByteStream.new(key[(key_i*SubkeySize), SubkeySize])^@subkeys[i]
				end

				keygen_magic="\x00\x00\x00\x00\x00\x00\x00\x00"
				# For all the subkeys, then the s-boxes, replace the contents
				# with the results of an encryption of the current magic value
				# (replacing the magic value also)
				(0 .. (SubkeyCount/2)-1).each do
					|i|
					keygen_magic=crypt(keygen_magic, :encrypt)
					@subkeys[i*2]=ByteStream.new(keygen_magic[0, 4])
					@subkeys[(i*2)+1]=ByteStream.new(keygen_magic[4, 4])
				end
				(0 .. SboxCount-1).each do
					|i|
					(0 .. (SboxSize/2)-1).each do
						|j|
						keygen_magic=crypt(keygen_magic, :encrypt)
						@sboxes[i][(j*2)]=ByteStream.new(keygen_magic[0, 4])
						@sboxes[i][(j*2)+1]=ByteStream.new(keygen_magic[4, 4])
					end
				end
			end
		end
		def initialize(key)
			@derived_key=
				if(defined? DerivedKeyInitial) then
					DerivedKeyInitial
				else
					p "gen"
					DerivedKey.new
				end
			@derivedkey=DerivedKeyInitial.dup
			@derivedkey.update_from_key(key)
		end
		def encrypt(string)
			@derivedkey.crypt(string, :encrypt)
		end
		def decrypt(string)
			@derivedkey.crypt(string, :decrypt)
		end
	end
end
