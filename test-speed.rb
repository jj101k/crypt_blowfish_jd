#!/usr/bin/ruby -w
require "./core"
require "./blowfish"
require "crypt/cbc"

SampleKey="1"*8
SampleIV="2"*8

puts "Testing time-to-encrypt a big block of data (keeping it in core)...\n";
huge_ptext=IO.readlines("bwulf10.txt", nil)[0]

crypt=Crypt::Blowfish.new(SampleKey)
crypt_cbc = Crypt::CBC.new(crypt)

before=Time.new
huge_ctext=crypt_cbc.encrypt(SampleIV, huge_ptext)
after=Time.new

diff=after-before
size=huge_ptext.length/1024
puts sprintf("#{diff} seconds to encrypt a %.1fKiB file (%.1fKiB/s).\n", size, size/diff)

before=Time.new
new_huge_ptext=crypt_cbc.decrypt(SampleIV, huge_ctext)
after=Time.new

diff=after-before
puts sprintf("#{diff} seconds to decrypt (%.1fKiB/s).\n", size/diff)
if(new_huge_ptext == huge_ptext)
	puts "All seemed to work.\n"
else
	puts "Argh! Something went pear-shaped!\n"
	if(new_huge_ptext.length!=huge_ptext.length)
		puts "Length mismatch: was #{huge_ptext.length}, is #{new_huge_ptext.length}"
	else
		(0 .. 1024).each do
			|offset|
			if(new_huge_ptext[offset]!=huge_ptext[offset])
				if(offset>5)
					p "Mismatch at #{offset}: '#{new_huge_ptext[offset-5,10]}' != '#{huge_ptext[offset-5,10]}'" 
				else
					p "Mismatch at #{offset}: '#{new_huge_ptext[0,10]}' != '#{huge_ptext[0,10]}'" 
				end
			end
		end
	end
end

puts "Here's (a snippet of) the result of the decryption:\n"
puts "\n..."+new_huge_ptext[40960, 256]+"...\n"
