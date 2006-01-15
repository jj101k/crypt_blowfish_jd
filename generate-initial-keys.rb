require './blowfish_prekey'
p "Generating initial keys for cache"
File.copy("blowfish_prekey.rb", "blowfish.rb")
derived_key_initial=Crypt::Blowfish::DerivedKey.new
File.open("blowfish.rb", "a") do
	|file|
	file.puts "__END__"
	Marshal.dump(derived_key_initial, file)
end
p "Done"
