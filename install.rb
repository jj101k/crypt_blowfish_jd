require "rbconfig.rb"
include Config
require "fileutils"
include FileUtils::Verbose

mkdir_p(CONFIG["sitelibdir"]+"/crypt")
install("blowfish.rb", CONFIG["sitelibdir"]+"/crypt")
if(File.exists? "Makefile")
	system((ENV["MAKE"]||"make")+' install')
else
	mkdir_p(CONFIG["sitelibdir"]+"/crypt/blowfish")
	install("core.rb", CONFIG["sitelibdir"]+"/crypt/blowfish/")
end
