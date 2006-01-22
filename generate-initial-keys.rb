require './core'
require './pi-digits'
require "fileutils"
puts "Generating initial keys for cache..."
FileUtils.cp("blowfish_prekey.rb", "blowfish.rb")
pi_digits = Pi.fraction_bytes(Crypt::Blowfish::Core.needed_pi_digits)
DigitsPerLine=64
def hex_digits_encode(hex_string)
	hex_string.gsub(/../) {|hbyte| "\\x"+hbyte}
end
File.open("blowfish.rb", "a") do
	|file|
	file.write "class Crypt\n\tclass Blowfish\n\t\tPiDigits = \n"
	full_line_count = pi_digits.length/DigitsPerLine
	(0 .. full_line_count-1).each do
		|i|
		file.write("\t\t\t\"" + hex_digits_encode(pi_digits[i*DigitsPerLine .. ((i+1)*DigitsPerLine)-1]) + "\" + \n")
	end
	file.write("\t\t\t\"" + hex_digits_encode(pi_digits[full_line_count*DigitsPerLine .. pi_digits.length-1]) + "\"\n\tend\nend\n")
end
puts "Done"
