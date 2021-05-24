# frozen_string_literal: true

require 'openssl'
require 'securerandom'
require 'base64'

module AspnetPasswordHasher
  class PasswordHasher
    def initialize(options = {})
      @mode = options[:mode] || :v3
      case @mode
      when :v2
        # nop
      when :v3
        @iter_count = options[:iter_count] || 10000
        if @iter_count < 1
          raise ArgumentError, "Invalid password hasher iteration count"
        end
      else
        raise ArgumentError, "Invalid password hasher compatibility mode"
      end
      @rng = options[:random_number_generator] || SecureRandom
    end

    def hash_password(password)
      bytes = case @mode
              when :v2
                hash_password_v2(password)
              when :v3
                hash_password_v3(password)
              end
      Base64.strict_encode64(bytes)
    end

    def verify_hashed_password(hashed_password, provided_password)
      decoded_hashed_password = Base64.strict_decode64(hashed_password)
      case decoded_hashed_password[0]
      when "\x00"
        # v2
        verify_hashed_password_v2(decoded_hashed_password, provided_password)
      when "\x01"
        # v3
        verify_hashed_password_v3(decoded_hashed_password, provided_password)
      else
        false
      end
    end

    private

    def hash_password_v2(password)
      iter_count = 1000 # default for Rfc2898DeriveBytes
      subkey_len = 256 / 8 # 256 bits
      salt_size = 128 / 8 # 128 bits

      salt = @rng.bytes(salt_size)
      digest = OpenSSL::Digest::SHA1.new
      subkey = OpenSSL::PKCS5.pbkdf2_hmac(password, salt, iter_count, subkey_len, digest)

      output_bytes = String.new
      [0].pack('c', buffer: output_bytes)
      output_bytes << salt
      output_bytes << subkey
      output_bytes
    end

    def hash_password_v3(password)
      prf = 1 # HMACSHA256
      salt_size = 128 / 8
      num_bytes_requested = 256 / 8

      salt = @rng.bytes(salt_size)
      digest = OpenSSL::Digest::SHA256.new
      subkey = OpenSSL::PKCS5.pbkdf2_hmac(password, salt, @iter_count, num_bytes_requested, digest)

      output_bytes = String.new
      [1].pack('c', buffer: output_bytes) # format marker
      [prf].pack('N', buffer: output_bytes)
      [@iter_count].pack('N', buffer: output_bytes)
      [salt_size].pack('N', buffer: output_bytes)
      output_bytes << salt
      output_bytes << subkey
      output_bytes
    end

    def verify_hashed_password_v2(hashed_password, password)
      iter_count = 1000 # default for Rfc2898DeriveBytes
      subkey_len = 256 / 8 # 256 bits
      salt_size = 128 / 8 # 128 bits

      if hashed_password.length != 1 + subkey_len + salt_size
        return false # bad size
      end

      salt = hashed_password[1..salt_size]
      expected_subkey = hashed_password[(salt_size + 1)...hashed_password.length]

      digest = OpenSSL::Digest::SHA1.new
      actual_subkey = OpenSSL::PKCS5.pbkdf2_hmac(password, salt, iter_count, subkey_len, digest)
      expected_subkey == actual_subkey
    end

    def verify_hashed_password_v3(hashed_password, password)
      prf = hashed_password[1..4].unpack('N')[0]
      iter_count = hashed_password[5..8].unpack('N')[0]
      salt_len = hashed_password[9..12].unpack('N')[0]
      # salt must be >= 128 bits
      if salt_len < 128 / 8
        return false
      end

      salt = hashed_password[13...(13 + salt_len)]
      subkey_len = hashed_password.length - 13 - salt_len
      # subkey must by >= 128 bits
      if subkey_len < 128 / 8
        return false
      end

      expected_subkey = hashed_password[(13 + salt_len)...hashed_password.length]

      digest = case prf
               when 0
                 OpenSSL::Digest::SHA1.new
               when 1
                 OpenSSL::Digest::SHA256.new
               when 2
                 OpenSSL::Digest::SHA512.new
               end
      actual_subkey = OpenSSL::PKCS5.pbkdf2_hmac(password, salt, iter_count, subkey_len, digest)

      expected_subkey == actual_subkey
    rescue StandardError
      false
    end
  end
end
