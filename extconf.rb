# frozen_string_literal: true

require "mkmf"
have_header("stdint.h")
create_makefile("jdcrypt/blowfish/core")
