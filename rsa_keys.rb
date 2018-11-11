module OpenSSL

  require 'openssl'

  PRIVATE_KEY_PATH = 'rsa_keys/private_key.pem'
  PUBLIC_KEY_PATH  = 'rsa_keys/public_key.pem'

  def create_rsa_keys
    key = OpenSSL::PKey::RSA.new 2048

    write PRIVATE_KEY_PATH, key
    write PUBLIC_KEY_PATH, key
  end

  def rsa_private
    key PRIVATE_KEY_PATH
  end

  def rsa_public
    key PUBLIC_KEY_PATH
  end

  private

  def write path, key
    open path, 'w' do |io| io.write (path =~ /priv/i ? key : key.public_key).to_pem end
  end

  def key path
    OpenSSL::PKey::RSA.new File.read path
  end

end