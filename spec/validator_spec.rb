require './validator.rb'
require './client'

describe Validator do
  before do
    @user_token = Client.new('foo').token
    @checking_out_token = Validator.new(@user_token).send:data, {name: 'bar'}
  end

  it 'tokens: different data/the same rsa keys' do
    expect(@user_token).not_to eql @checking_out_token
  end
end