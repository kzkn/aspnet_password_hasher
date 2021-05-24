require 'spec_helper'

class SeqGen
  def initialize
    @n = 0
  end

  def bytes(n)
    arr = Array.new(n)
    n.times do |i|
      arr[i] = @n
      @n += 1
    end
    arr.pack('C*')
  end
end

RSpec.describe AspnetPasswordHasher::PasswordHasher do
  describe '.new' do
    it 'raises error if invalid compat mode' do
      expect { AspnetPasswordHasher::PasswordHasher.new(mode: :v1) }.to raise_error ArgumentError
    end

    it 'raised error if invalid iter count' do
      expect { AspnetPasswordHasher::PasswordHasher.new(iter_count: 0) }.to raise_error ArgumentError
      expect { AspnetPasswordHasher::PasswordHasher.new(iter_count: -1) }.to raise_error ArgumentError
    end
  end

  describe 'full round trip' do
    where(:mode) do
      [
        [:v2],
        [:v3],
      ]
    end

    with_them do
      example do
        hasher = AspnetPasswordHasher::PasswordHasher.new(mode: mode)

        hashed_password = hasher.hash_password("password 1")
        success_result = hasher.verify_hashed_password(hashed_password, "password 1")
        expect(success_result).to eq :success

        failed_result = hasher.verify_hashed_password(hashed_password, "password 2")
        expect(failed_result).to eq :failed
      end
    end
  end

  describe '#hash_password' do
    it 'defaults to version 3' do
      hasher = AspnetPasswordHasher::PasswordHasher.new(mode: nil, random_number_generator: SeqGen.new)
      ret_val = hasher.hash_password("my password")
      expect(ret_val).to eq "AQAAAAEAACcQAAAAEAABAgMEBQYHCAkKCwwNDg+yWU7rLgUwPZb1Itsmra7cbxw2EFpwpVFIEtP+JIuUEw=="
    end

    it 'supports version 2' do
      hasher = AspnetPasswordHasher::PasswordHasher.new(mode: :v2, random_number_generator: SeqGen.new)
      ret_val = hasher.hash_password("my password")
      expect(ret_val).to eq "AAABAgMEBQYHCAkKCwwNDg+ukCEMDf0yyQ29NYubggHIVY0sdEUfdyeM+E1LtH1uJg=="
    end

    it 'supports version 3' do
      hasher = AspnetPasswordHasher::PasswordHasher.new(mode: :v3, random_number_generator: SeqGen.new)
      ret_val = hasher.hash_password("my password")
      expect(ret_val).to eq "AQAAAAEAACcQAAAAEAABAgMEBQYHCAkKCwwNDg+yWU7rLgUwPZb1Itsmra7cbxw2EFpwpVFIEtP+JIuUEw=="
    end
  end

  describe '#verify_hashed_password failure cases' do
    where(:hashed_password) do
      [
        # version 2 payloads
        ["AAABAgMEBQYHCAkKCwwNDg+uAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALtH1uJg=="], # incorrect password
        ["AAABAgMEBQYHCAkKCwwNDg+ukCEMDf0yyQ29NYubggE="], # too short
        ["AAABAgMEBQYHCAkKCwwNDg+ukCEMDf0yyQ29NYubggHIVY0sdEUfdyeM+E1LtH1uJgAAAAAAAAAAAAA="], # extra data at end
        # version 3 payloads
        ["AQAAAAAAAAD6AAAAEAhftMyfTJyAAAAAAAAAAAAAAAAAAAih5WsjXaR3PA9M"], # incorrect password
        ["AQAAAAIAAAAyAAAAEOMwvh3+FZxqkdMBz2ekgGhwQ4A="], # too short
        ["AQAAAAIAAAAyAAAAEOMwvh3+FZxqkdMBz2ekgGhwQ4B6pZWND6zgESBuWiHwAAAAAAAAAAAA"], # extra data at end
      ]
    end

    with_them do
      example do
        hasher = AspnetPasswordHasher::PasswordHasher.new
        result = hasher.verify_hashed_password(hashed_password, "my password")
        expect(result).to eq :failed
      end
    end
  end

  describe '#verify_hashed_password version 2 success cases' do
    where(:hashed_password) do
      [
        # Version 2 payloads
        ["ANXrDknc7fGPpigibZXXZFMX4aoqz44JveK6jQuwY3eH/UyPhvr5xTPeGYEckLxz9A=="], # SHA1, 1000 iterations, 128-bit salt, 256-bit subkey
        # Version 3 payloads
        ["AQAAAAIAAAAyAAAAEOMwvh3+FZxqkdMBz2ekgGhwQ4B6pZWND6zgESBuWiHw"], # SHA512, 50 iterations, 128-bit salt, 128-bit subkey
        ["AQAAAAIAAAD6AAAAIJbVi5wbMR+htSfFp8fTw8N8GOS/Sje+S/4YZcgBfU7EQuqv4OkVYmc4VJl9AGZzmRTxSkP7LtVi9IWyUxX8IAAfZ8v+ZfhjCcudtC1YERSqE1OEdXLW9VukPuJWBBjLuw=="], # SHA512, 250 iterations, 256-bit salt, 512-bit subkey
        ["AQAAAAAAAAD6AAAAEAhftMyfTJylOlZT+eEotFXd1elee8ih5WsjXaR3PA9M"], # SHA1, 250 iterations, 128-bit salt, 128-bit subkey
        ["AQAAAAEAA9CQAAAAIESkQuj2Du8Y+kbc5lcN/W/3NiAZFEm11P27nrSN5/tId+bR1SwV8CO1Jd72r4C08OLvplNlCDc3oQZ8efcW+jQ="], # SHA256, 250000 iterations, 256-bit salt, 256-bit subkey
      ]
    end

    with_them do
      example do
        hasher = AspnetPasswordHasher::PasswordHasher.new(mode: :v2)
        result = hasher.verify_hashed_password(hashed_password, "my password")
        expect(result).to eq :success
      end
    end
  end

  describe '#verify_hashed_password version 3 success cases' do
    where(:hashed_password, :expected_result) do
      [
        # Version 2 payloads
        ["ANXrDknc7fGPpigibZXXZFMX4aoqz44JveK6jQuwY3eH/UyPhvr5xTPeGYEckLxz9A==", :success_rehash_needed], # SHA1, 1000 iterations, 128-bit salt, 256-bit subkey
        # Version 3 payloads
        ["AQAAAAIAAAAyAAAAEOMwvh3+FZxqkdMBz2ekgGhwQ4B6pZWND6zgESBuWiHw", :success_rehash_needed], # SHA512, 50 iterations, 128-bit salt, 128-bit subkey
        ["AQAAAAIAAAD6AAAAIJbVi5wbMR+htSfFp8fTw8N8GOS/Sje+S/4YZcgBfU7EQuqv4OkVYmc4VJl9AGZzmRTxSkP7LtVi9IWyUxX8IAAfZ8v+ZfhjCcudtC1YERSqE1OEdXLW9VukPuJWBBjLuw==", :success_rehash_needed], # SHA512, 250 iterations, 256-bit salt, 512-bit subkey
        ["AQAAAAAAAAD6AAAAEAhftMyfTJylOlZT+eEotFXd1elee8ih5WsjXaR3PA9M", :success_rehash_needed], # SHA1, 250 iterations, 128-bit salt, 128-bit subkey
        ["AQAAAAEAA9CQAAAAIESkQuj2Du8Y+kbc5lcN/W/3NiAZFEm11P27nrSN5/tId+bR1SwV8CO1Jd72r4C08OLvplNlCDc3oQZ8efcW+jQ=", :success], # SHA256, 250000 iterations, 256-bit salt, 256-bit subkey
      ]
    end

    with_them do
      example do
        hasher = AspnetPasswordHasher::PasswordHasher.new
        result = hasher.verify_hashed_password(hashed_password, "my password")
        expect(result).to eq expected_result
      end
    end
  end
end
