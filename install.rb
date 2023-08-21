require "rbconfig.rb"
include Config
require "fileutils"
include FileUtils::Verbose

mkdir_p(CONFIG["sitelibdir"] + "/jdcrypt")
install("blowfish.rb", CONFIG["sitelibdir"] + "/jdcrypt", :mode => 0644)
if(File.exists? "Makefile")
    system((ENV["MAKE"] || "make") + ' install')
else
    mkdir_p(CONFIG["sitelibdir"] + "/jdcrypt/blowfish")
    install("core.rb", CONFIG["sitelibdir"] + "/jdcrypt/blowfish/", :mode => 0644)
end
