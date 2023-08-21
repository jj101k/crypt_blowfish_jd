#!/usr/bin/ruby -w

require ARGV[0] || "./core"
require "./blowfish"
# From Eric Young's test vectors <http://www.schneier.com/code/vectors.txt>
#   key bytes               clear bytes             cipher bytes
test_ecb_data = [
%w{0000000000000000        0000000000000000        4EF997456198DD78},
%w{FFFFFFFFFFFFFFFF        FFFFFFFFFFFFFFFF        51866FD5B85ECB8A},
%w{3000000000000000        1000000000000001        7D856F9A613063F2},
%w{1111111111111111        1111111111111111        2466DD878B963C9D},
%w{0123456789ABCDEF        1111111111111111        61F9C3802281B096},
%w{1111111111111111        0123456789ABCDEF        7D0CC630AFDA1EC7},
%w{0000000000000000        0000000000000000        4EF997456198DD78},
%w{FEDCBA9876543210        0123456789ABCDEF        0ACEAB0FC6A0A28D},
%w{7CA110454A1A6E57        01A1D6D039776742        59C68245EB05282B},
%w{0131D9619DC1376E        5CD54CA83DEF57DA        B1B8CC0B250F09A0},
%w{07A1133E4A0B2686        0248D43806F67172        1730E5778BEA1DA4},
%w{3849674C2602319E        51454B582DDF440A        A25E7856CF2651EB},
%w{04B915BA43FEB5B6        42FD443059577FA2        353882B109CE8F1A},
%w{0113B970FD34F2CE        059B5E0851CF143A        48F4D0884C379918},
%w{0170F175468FB5E6        0756D8E0774761D2        432193B78951FC98},
%w{43297FAD38E373FE        762514B829BF486A        13F04154D69D1AE5},
%w{07A7137045DA2A16        3BDD119049372802        2EEDDA93FFD39C79},
%w{04689104C2FD3B2F        26955F6835AF609A        D887E0393C2DA6E3},
%w{37D06BB516CB7546        164D5E404F275232        5F99D04F5B163969},
%w{1F08260D1AC2465E        6B056E18759F5CCA        4A057A3B24D3977B},
%w{584023641ABA6176        004BD6EF09176062        452031C1E4FADA8E},
%w{025816164629B007        480D39006EE762F2        7555AE39F59B87BD},
%w{49793EBC79B3258F        437540C8698F3CFA        53C55F9CB49FC019},
%w{4FB05E1515AB73A7        072D43A077075292        7A8E7BFA937E89A3},
%w{49E95D6D4CA229BF        02FE55778117F12A        CF9C5D7A4986ADB5},
%w{018310DC409B26D6        1D9D5C5018F728C2        D1ABB290658BC778},
%w{1C587F1C13924FEF        305532286D6F295A        55CB3774D13EF201},
%w{0101010101010101        0123456789ABCDEF        FA34EC4847B268B2},
%w{1F1F1F1F0E0E0E0E        0123456789ABCDEF        A790795108EA3CAE},
%w{E0FEE0FEF1FEF1FE        0123456789ABCDEF        C39E072D9FAC631D},
%w{0000000000000000        FFFFFFFFFFFFFFFF        014933E0CDAFF6E4},
%w{FFFFFFFFFFFFFFFF        0000000000000000        F21E9A77B71C49BC},
%w{0123456789ABCDEF        0000000000000000        245946885754369A},
%w{FEDCBA9876543210        FFFFFFFFFFFFFFFF        6B5C5A9C5D9E0A5A}
]

cbc_key       = ["0123456789ABCDEFF0E1D2C3B4A59687"].pack("H*")
iv            = ["FEDCBA9876543210"].pack("H*")
cbc_plaintext = "7654321 Now is the time for \x00"

cbc_expected_cyphertext =
# This assumes zero-padding... but we do PKCS#5 padding, so...
#   ["6B77B4D63006DEE605B156E27403979358DEB9E7154616D959F1652BD5FF92CC"].pack("H*"))
# ...this is how it should actually look.
    ["6B77B4D63006DEE605B156E27403979358DEB9E7154616D9749decbec05d264b"].pack("H*")

die_please = (ENV["die_please"] || "100000").to_i
# Test straight encryption
i = 0
test_ecb_data.each do
    |test_item|
    blowcypher = Crypt::Blowfish.new([test_item[0]].pack("H*"))
    cyphertext = blowcypher.encrypt([test_item[1]].pack("H*"))
    if(cyphertext != [test_item[2]].pack("H*") or die_please == i) then
        p "#{i} key=#{test_item[0]}, ptext=#{test_item[1]}: #{test_item[2]} != #{cyphertext.unpack("H*")[0]}"
        $DEBUG = 1
        Crypt::Blowfish.new([test_item[0]].pack("H*")).encrypt([test_item[1]].pack("H*"))
        raise
    end
    i += 1
end

# Test CBC
have_cbc = nil
begin
    require "jdcrypt/cbc"
    have_cbc = 1
rescue LoadError
    puts "No JdCrypt::CBC, skipping CBC tests"
end
if(have_cbc)
    blowcypher = Crypt::Blowfish.new(cbc_key)
    cbc = JdCrypt::CBC.new(blowcypher)

    p(cbc.encrypt(iv, cbc_plaintext) == cbc_expected_cyphertext)
else
    puts "Ok"
end

puts "All encryption tests complete. Begin decryption tests."
# Test straight decryption
test_ecb_data.each do
    |test_item|
    blowcypher = Crypt::Blowfish.new([test_item[0]].pack("H*"))
    plaintext = blowcypher.decrypt([test_item[2]].pack("H*"))
    if(plaintext != [test_item[1]].pack("H*") or die_please == i) then
        p "#{i} key=#{test_item[0]}, ctext=#{test_item[2]}: #{test_item[1]} != #{plaintext.unpack("H*")[0]}"
        $DEBUG = 1
        Crypt::Blowfish.new([test_item[0]].pack("H*")).decrypt([test_item[1]].pack("H*"))
        raise
    end
    i += 1
end

if(have_cbc)
    # Test CBC decryption
    blowcypher = Crypt::Blowfish.new(cbc_key)
    cbc = JdCrypt::CBC.new(blowcypher)

    p(cbc.decrypt(iv, cbc_expected_cyphertext) == cbc_plaintext)
else
    puts "Ok"
end
