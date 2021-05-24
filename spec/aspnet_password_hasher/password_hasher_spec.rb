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
  it 'v3' do
    hasher = AspnetPasswordHasher::PasswordHasher.new(random_number_generator: SeqGen.new)
    ret = hasher.hash_password('my password')
    expect(ret).to eq "AQAAAAEAACcQAAAAEAABAgMEBQYHCAkKCwwNDg+yWU7rLgUwPZb1Itsmra7cbxw2EFpwpVFIEtP+JIuUEw=="
    expect(hasher.verify_hashed_password(ret, 'my password')).to be_truthy
    expect(hasher.verify_hashed_password(ret, 'my password!')).to be_falsy
  end
end
