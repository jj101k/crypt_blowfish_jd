# frozen_string_literal: true

require "rbconfig"
include RbConfig
require "fileutils"
include FileUtils::Verbose

require "./generate-initial-keys" unless File.exist? "blowfish.rb"

loop do
  puts "Do you want to install the binary (b) or pure-ruby (r) core? (b/r)?"

  answer = $stdin.gets
  if answer =~ /^b/i
    begin
      File.unlink("core.rb")
    rescue Errno::ENOENT
      # Fine
    end
    require "./extconf"
    exit system(ENV["MAKE"] || "make")
  elsif answer =~ /^r/i
    begin
      File.unlink("Makefile")
    rescue Errno::ENOENT
      # Fine
    end
    FileUtils.cp("pr-core.rb", "core.rb")
    exit
  end
end
