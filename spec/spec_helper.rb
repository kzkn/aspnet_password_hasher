# frozen_string_literal: true

require "simplecov"
require "simplecov-erb"

SimpleCov.start do
  enable_coverage :branch
  formatter SimpleCov::Formatter::ERBFormatter
end

SimpleCov.minimum_coverage 100

require "rspec-parameterized"
require "aspnet_password_hasher"

RSpec.configure do |config|
  # Enable flags like --only-failures and --next-failure
  config.example_status_persistence_file_path = ".rspec_status"

  # Disable RSpec exposing methods globally on `Module` and `main`
  config.disable_monkey_patching!

  config.expect_with :rspec do |c|
    c.syntax = :expect
  end
end
