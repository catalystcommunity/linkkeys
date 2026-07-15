# frozen_string_literal: true

# Loads and runs every test file in this directory under a single minitest
# process. Usage: `ruby -Ilib -Itest test/run_all.rb`.
Dir[File.join(__dir__, 'test_*.rb')].sort.each { |f| require f }
