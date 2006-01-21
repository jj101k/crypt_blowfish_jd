require "rbconfig.rb"
include Config
require "fileutils"
include FileUtils::Verbose

mkdir_p(CONFIG["sitelibdir"]+"/crypt")
install("blowfish.rb", CONFIG["sitelibdir"]+"/crypt")
