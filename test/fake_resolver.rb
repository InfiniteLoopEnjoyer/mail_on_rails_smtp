# Hash-backed stand-in for MailOnRails::SenderAuth::Dns, so verifier tests
# never touch the network. Records look like:
#
#   FakeResolver.new(
#     txt: { "example.com" => ["v=spf1 ip4:1.2.3.4 -all"] },
#     a:   { "mail.example.com" => ["1.2.3.4"] },
#     ptr: { "1.2.3.4" => ["mail.example.com"] }
#   )
#
# A value of :temperror raises Dns::TempError for that lookup.
class FakeResolver
  def initialize(records = {})
    @records = records
  end

  %i[txt a aaaa mx].each do |type|
    define_method(type) { |name| fetch(type, name.to_s.downcase) }
  end

  def ptr(ip)
    fetch(:ptr, ip.to_s)
  end

  private

  def fetch(type, key)
    value = @records.dig(type, key)
    raise MailOnRails::Smtp::SenderAuth::Dns::TempError, "#{type} #{key}" if value == :temperror

    Array(value)
  end
end
