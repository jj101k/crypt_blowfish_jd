class JdCrypt
    ByteStream = "not loaded"
end
require "./pr-core"
require "./pi-digits"
require "fileutils"

puts "Generating initial keys for cache..."
FileUtils.cp("blowfish_prekey.rb", "blowfish.rb")
pi_digits = Pi.fraction_bytes(JdCrypt::Blowfish::Core.needed_pi_digits)
DigitsPerLine = 64
def hex_digits_encode(hex_string)
    hex_string.gsub(/../) { |hbyte| "\\x" + hbyte }
end
File.open("blowfish.rb", "a") do
    |file|
    file.write "class JdCrypt\n\tclass Blowfish\n\t\tPiDigits = [\n"
    full_line_count = pi_digits.length / DigitsPerLine
    (0 .. full_line_count - 1).each do
        |i|
        digits = pi_digits[i * DigitsPerLine .. ((i + 1) * DigitsPerLine) - 1]
        file.write("\t\t\t\"" + digits + "\" + \n")
    end
    digits = pi_digits[full_line_count * DigitsPerLine .. pi_digits.length - 1]
    file.write("\t\t\t\"" + digits + "\"\n\t\t].pack(\"H*\")\n\tend\nend\n")
end
puts "Done"
