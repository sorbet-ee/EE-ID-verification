# frozen_string_literal: true

require "bundler/gem_tasks"

desc "Run tests"
task :test do
  sh "ruby -Ilib:test test/ee_id_verification_test.rb"
end

require "rubocop/rake_task"
RuboCop::RakeTask.new

task default: %i[test rubocop]
