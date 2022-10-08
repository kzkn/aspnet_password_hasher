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
  PLAINTEXT_PASSWORD = "my password"
  V2_SHA1_1000ITER_128SALT_256SUBKEY = "AAABAgMEBQYHCAkKCwwNDg+ukCEMDf0yyQ29NYubggHIVY0sdEUfdyeM+E1LtH1uJg==";
  V3_SHA1_250ITER_128SALT_128SUBKEY = "AQAAAAAAAAD6AAAAEAhftMyfTJylOlZT+eEotFXd1elee8ih5WsjXaR3PA9M";
  V3_SHA256_250000ITER_256SALT_256SUBKEY = "AQAAAAEAA9CQAAAAIESkQuj2Du8Y+kbc5lcN/W/3NiAZFEm11P27nrSN5/tId+bR1SwV8CO1Jd72r4C08OLvplNlCDc3oQZ8efcW+jQ=";
  V3_SHA512_50ITER_128SALT_128SUBKEY = "AQAAAAIAAAAyAAAAEOMwvh3+FZxqkdMBz2ekgGhwQ4B6pZWND6zgESBuWiHw";
  V3_SHA512_250ITER_256SALT_512SUBKEY = "AQAAAAIAAAD6AAAAIJbVi5wbMR+htSfFp8fTw8N8GOS/Sje+S/4YZcgBfU7EQuqv4OkVYmc4VJl9AGZzmRTxSkP7LtVi9IWyUxX8IAAfZ8v+ZfhjCcudtC1YERSqE1OEdXLW9VukPuJWBBjLuw==";
  V3_SHA512_10000ITER_128SALT_256SUBKEY = "AQAAAAIAACcQAAAAEAABAgMEBQYHCAkKCwwNDg9B0Oxwty+PGIDSp95gcCfzeDvA4sGapUIUov8usXfD6A==";
  V3_SHA512_100000ITER_128SALT_256SUBKEY = "AQAAAAIAAYagAAAAEAABAgMEBQYHCAkKCwwNDg/Q8A0WMKbtHQJQ2DHCdoEeeFBrgNlldq6vH4qX/CGqGQ==";

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
      ret_val = hasher.hash_password(PLAINTEXT_PASSWORD)
      expect(ret_val).to eq V3_SHA512_100000ITER_128SALT_256SUBKEY
    end

    it 'supports version 2' do
      hasher = AspnetPasswordHasher::PasswordHasher.new(mode: :v2, random_number_generator: SeqGen.new)
      ret_val = hasher.hash_password(PLAINTEXT_PASSWORD)
      expect(ret_val).to eq V2_SHA1_1000ITER_128SALT_256SUBKEY
    end

    it 'supports version 3' do
      hasher = AspnetPasswordHasher::PasswordHasher.new(mode: :v3, random_number_generator: SeqGen.new)
      ret_val = hasher.hash_password(PLAINTEXT_PASSWORD)
      expect(ret_val).to eq V3_SHA512_100000ITER_128SALT_256SUBKEY
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
        # irregular case
        ["BQAAAAIAAAAyAAAAEOMwvh3+FZxqkdMBz2ekgGhwQ4B6pZWND6zgESBuWiHwAAAAAAAAAAAA"], # unknown version (0x05)
        ["AQAAAAEAACcQAAAADwgXTwPfMz/1hZrAcmJdRM04f0nJxC4vzsW82I71yiX07QCuttE2Sg3ly9yPUoYM"], # too small salt size (120 bits)
        ["AQAAAAMAACcQAAAAEB98ik4rMnThQzVdtfVfStpq0EpSA4tnEhciZTU8kznWADk4TOPsjRjqrA7PGIfxlQ=="], # unknown digest algorithm (prf = 3)
      ]
    end

    with_them do
      example do
        hasher = AspnetPasswordHasher::PasswordHasher.new
        result = hasher.verify_hashed_password(hashed_password, PLAINTEXT_PASSWORD)
        expect(result).to eq :failed
      end
    end
  end

  describe '#verify_hashed_password version 2 success cases' do
    where(:hashed_password) do
      [
        # Version 2 payloads
        [V2_SHA1_1000ITER_128SALT_256SUBKEY],
        # Version 3 payloads
        [V3_SHA512_50ITER_128SALT_128SUBKEY],
        [V3_SHA512_250ITER_256SALT_512SUBKEY],
        [V3_SHA512_100000ITER_128SALT_256SUBKEY],
      ]
    end

    with_them do
      example do
        hasher = AspnetPasswordHasher::PasswordHasher.new(mode: :v2)
        result = hasher.verify_hashed_password(hashed_password, PLAINTEXT_PASSWORD)
        expect(result).to eq :success
      end
    end
  end

  describe '#verify_hashed_password version 3 success cases' do
    where(:hashed_password, :expected_result) do
      [
        # Version 2 payloads
        [V2_SHA1_1000ITER_128SALT_256SUBKEY, :success_rehash_needed],
        # Version 3 payloads
        [V3_SHA1_250ITER_128SALT_128SUBKEY, :success_rehash_needed],
        [V3_SHA256_250000ITER_256SALT_256SUBKEY, :success_rehash_needed],
        [V3_SHA512_50ITER_128SALT_128SUBKEY, :success_rehash_needed],
        [V3_SHA512_250ITER_256SALT_512SUBKEY, :success_rehash_needed],
        [V3_SHA512_10000ITER_128SALT_256SUBKEY, :success_rehash_needed],
        [V3_SHA512_100000ITER_128SALT_256SUBKEY, :success],
      ]
    end

    with_them do
      example do
        hasher = AspnetPasswordHasher::PasswordHasher.new
        result = hasher.verify_hashed_password(hashed_password, PLAINTEXT_PASSWORD)
        expect(result).to eq expected_result
      end
    end
  end
end
