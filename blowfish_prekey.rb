#require 'profile'
unless(defined? Crypt::Blowfish::Core)
	require "crypt/blowfish/core"
end
class Crypt
	class Blowfish
		def initialize(key)
			if($DEBUG)
				p "Debugging"
			end
			if(PiDigits.length < Core.needed_pi_digits)
				throw :too_few_digits
			end
			@derivedkey=Core.new(PiDigits)
			@derivedkey.update_from_key(key)
			if($DEBUG)
				p @derivedkey.sboxes
				p @derivedkey.subkeys
			end
		end
		def encrypt(string)
			p "Enc" if $DEBUG
			@derivedkey.crypt(string, 'e')
		end
		def decrypt(string)
			p "Dec" if $DEBUG
			@derivedkey.crypt(string, 'd')
		end
	end
end
