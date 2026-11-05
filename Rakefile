# frozen_string_literal: true

require "bundler/gem_tasks"
require "rake/testtask"
require "rake/extensiontask"

Rake::ExtensionTask.new("krypto_hpke", Gem::Specification.load("krypto.gemspec")) do |ext|
  ext.lib_dir = "lib/krypto"
end

Rake::TestTask.new do |t|
  t.libs << "test"
  t.libs << "lib"
  t.test_files = FileList["test/**/*_test.rb"]
  t.verbose = true
end

task test: :compile

require "standard/rake"

task default: %i[test standard]
