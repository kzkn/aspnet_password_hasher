# frozen_string_literal: true

require_relative "lib/aspnet_password_hasher/version"

Gem::Specification.new do |spec|
  spec.name          = "aspnet_password_hasher"
  spec.version       = AspnetPasswordHasher::VERSION
  spec.authors       = ["Kazuki Nishikawa"]
  spec.email         = ["kzkn@users.noreply.github.com"]

  spec.summary       = "An implementation of password hashing compatible with ASP.NET Identity"
  spec.description   = "An implementation of password hashing compatible with ASP.NET Identity"
  spec.homepage      = "https://github.com/kzkn/aspnet_password_hasher"
  spec.license       = "MIT"
  spec.required_ruby_version = Gem::Requirement.new(">= 2.4.0")

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = "https://github.com/kzkn/aspnet_password_hasher"
  spec.metadata["changelog_uri"] = "https://github.com/kzkn/aspnet_password_hasher/blob/master/CHANGELOG.md"

  spec.files = Dir.chdir(File.expand_path(__dir__)) do
    `git ls-files -z`.split("\x0").reject { |f| f.match(%r{\A(?:test|spec|features)/}) }
  end
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]
end
