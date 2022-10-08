# frozen_string_literal: true

require 'openssl'
require 'securerandom'
require 'base64'

module AspnetPasswordHasher
  class PasswordHasher
    KEY_DERIVATION_PRF_HMACSHA1 = 0
    KEY_DERIVATION_PRF_HMACSHA256 = 1
    KEY_DERIVATION_PRF_HMACSHA512 = 2

    def initialize(options = {})
      @mode = options[:mode] || :v3
      @rng = options[:random_number_generator] || SecureRandom

      case @mode
      when :v2
        @iter_count = 0
      when :v3
        @iter_count = options[:iter_count] || 100000
        if @iter_count < 1
          raise ArgumentError, "Invalid password hasher iteration count"
        end
      else
        raise ArgumentError, "Invalid password hasher compatibility mode"
      end
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
        if verify_hashed_password_v2(decoded_hashed_password, provided_password)
          @mode == :v3 ? :success_rehash_needed : :success
        else
          :failed
        end
      when "\x01"
        # v3
        result, embed_iter_count, prf = verify_hashed_password_v3(decoded_hashed_password, provided_password)
        if result
          if embed_iter_count < @iter_count
            :success_rehash_needed
          elsif prf == KEY_DERIVATION_PRF_HMACSHA1 || prf == KEY_DERIVATION_PRF_HMACSHA256
            :success_rehash_needed
          else
            :success
          end
        else
          :failed
        end
      else
        :failed
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
      output_bytes << "\x00" # format marker
      output_bytes << salt
      output_bytes << subkey
      output_bytes
    end

    def hash_password_v3(password)
      prf = KEY_DERIVATION_PRF_HMACSHA512
      salt_size = 128 / 8
      num_bytes_requested = 256 / 8

      salt = @rng.bytes(salt_size)
      digest = OpenSSL::Digest::SHA512.new
      subkey = OpenSSL::PKCS5.pbkdf2_hmac(password, salt, @iter_count, num_bytes_requested, digest)

      output_bytes = String.new
      output_bytes << "\x01" # format marker
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
        return [false, nil, nil]
      end

      salt = hashed_password[13...(13 + salt_len)]
      subkey_len = hashed_password.length - 13 - salt_len
      # subkey must by >= 128 bits
      if subkey_len < 128 / 8
        return [false, nil, nil]
      end

      expected_subkey = hashed_password[(13 + salt_len)...hashed_password.length]

      digest = case prf
               when KEY_DERIVATION_PRF_HMACSHA1
                 OpenSSL::Digest::SHA1.new
               when KEY_DERIVATION_PRF_HMACSHA256
                 OpenSSL::Digest::SHA256.new
               when KEY_DERIVATION_PRF_HMACSHA512
                 OpenSSL::Digest::SHA512.new
               end
      actual_subkey = OpenSSL::PKCS5.pbkdf2_hmac(password, salt, iter_count, subkey_len, digest)

      [expected_subkey == actual_subkey, iter_count, prf]
    rescue StandardError
      [false, nil, nil]
    end
  end
end
