require './blowfish_prekey'
require "fileutils"
puts "Generating initial keys for cache..."
FileUtils.cp("blowfish_prekey.rb", "blowfish.rb")
derived_key_initial=Crypt::Blowfish::DerivedKey.new
File.open("blowfish.rb", "a") do
	|file|
	file.write "class Crypt\n\tclass Blowfish\n\t\tDerivedKeyInitial = Marshal.load \""
	file.write Marshal.dump(derived_key_initial).gsub(/([\x00-\x09\x0b-\x1f\x7f-\xff"#\$\\])/) {|m| '\\x' +sprintf("%02X", m[0])}
	file.write "\"\n\tend\nend\n"
end
puts "Done"
