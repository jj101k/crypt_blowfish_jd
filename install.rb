# frozen_string_literal: true

require "rbconfig"
include RbConfig
require "fileutils"
include FileUtils::Verbose

mkdir_p("#{CONFIG["sitelibdir"]}/jdcrypt")
install("blowfish.rb", "#{CONFIG["sitelibdir"]}/jdcrypt", mode: 0o644)
if File.exist? "Makefile"
  system("#{ENV["MAKE"] || "make"} install")
else
  mkdir_p("#{CONFIG["sitelibdir"]}/jdcrypt/blowfish")
  install("core.rb", "#{CONFIG["sitelibdir"]}/jdcrypt/blowfish/", mode: 0o644)
end
