# frozen_string_literal: true

require_relative "lib/krypto/version"

Gem::Specification.new do |s|
  s.name = "krypto"
  s.version = Krypto::VERSION
  s.summary = "Cross Platform Cryptographic Tools"
  s.description = ""
  s.authors = ["Kolide Inc."]
  s.email = ["engineering@kolide.com"]
  s.homepage = "https://github.com/kolide/krypto"
  s.license = "Copyright Kolide 2022 All Rights Reserved"

  s.files = Dir["{lib}/**/*"] + ["LICENSE", "README.md"]
  s.files += Dir["ext/**/*.{rb,rs,toml}"]
  s.require_paths = ["lib"]
  s.extensions = ["ext/krypto_hpke/extconf.rb"]

  s.required_ruby_version = "~> 3.1"

  s.add_runtime_dependency "openssl"
  s.add_runtime_dependency "msgpack", "~> 1.5"
  s.add_runtime_dependency "chunky_png", "~> 1.4"
  s.add_runtime_dependency "rb_sys", "~> 0.9"
  s.metadata["rubygems_mfa_required"] = "true"
end
