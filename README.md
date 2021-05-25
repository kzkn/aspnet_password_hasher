![](https://github.com/kzkn/aspnet_password_hasher/workflows/CI/badge.svg)

# AspnetPasswordHasher

An implementation of password hashing compatible with [ASP.NET Identity PasswordHasher](https://github.com/dotnet/aspnetcore/blob/main/src/Identity/Extensions.Core/src/PasswordHasher.cs).

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'aspnet_password_hasher'
```

And then execute:

    $ bundle install

Or install it yourself as:

    $ gem install aspnet_password_hasher

## Usage

Password hashing:

```ruby
hasher = AspnetPasswordHasher::PasswordHasher.new
raw_password = 'my password'
hashed_password = hasher.hash_password(raw_password)
```

Verify password:

```ruby
hasher = AspnetPasswordHasher::PasswordHasher.new
raw_password = 'my password'
hashed_password = hasher.hash_password(raw_password)
hasher.verify_hashed_password(hashed_password, raw_password) # => :success
hasher.verify_hashed_password(hashed_password, 'bad password') # => :failed
```

If a hashed string with a weaker algorithm is given, report it:
```ruby
hasher = AspnetPasswordHasher::PasswordHasher.new
raw_password = 'my password'
hashed_password = hasher.hash_password(raw_password)

hasher_v2 = AspnetPasswordHasher::PasswordHasher.new(mode: :v2)
hasher_v2.verify_hashed_password(hashed_password, raw_password) # => :success_rehash_needed

hasher_fewer_iters = AspnetPasswordHasher::PasswordHasher.new(iter_count: 100)
hasher_fewer_iters.verify_hashed_password(hashed_password, raw_password) # => :success_rehash_needed
```

You can pass parameters similar to PasswordHasher:

```ruby
# compatibility mode, version 2
hasher = AspnetPasswordHasher::PasswordHasher.new(mode: :v2)

# compatibility mode, version 3 (default)
hasher = AspnetPasswordHasher::PasswordHasher.new(mode: :v3)

# custom iteration count (default is 10000)
hasher = AspnetPasswordHasher::PasswordHasher.new(iter_count: 99999)

# custom random number generator (default is SecureRandom)
hasher = AspnetPasswordHasher::PasswordHasher.new(random_number_generator: Random.new)
```

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and the created tag, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/kzkn/aspnet_password_hasher.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
