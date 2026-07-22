# frozen_string_literal: true

require "test_helper"
require "mail_on_rails/smtp/conn_limiter"

class ConnLimiterTest < Minitest::Test
  Limiter = MailOnRails::Smtp::ConnLimiter

  test "process-wide cap acquires and releases" do
    limiter = Limiter.new(2)

    assert limiter.acquire
    assert limiter.acquire
    refute limiter.acquire
    limiter.release
    assert limiter.acquire
  end

  test "per-ip cap refuses one ip while others still connect" do
    limiter = Limiter.new(10, per_ip: 2)

    assert limiter.acquire("192.0.2.1")
    assert limiter.acquire("192.0.2.1")
    refute limiter.acquire("192.0.2.1"), "third connection from the same IP must be refused"
    assert limiter.acquire("192.0.2.2"), "other IPs must be unaffected"
  end

  test "release frees the per-ip slot" do
    limiter = Limiter.new(10, per_ip: 1)

    assert limiter.acquire("192.0.2.1")
    refute limiter.acquire("192.0.2.1")
    limiter.release("192.0.2.1")
    assert limiter.acquire("192.0.2.1")
  end

  test "nil ip counts only against the process-wide cap" do
    limiter = Limiter.new(2, per_ip: 1)

    assert limiter.acquire(nil)
    assert limiter.acquire(nil)
    refute limiter.acquire(nil), "the global cap must still bind"
  end

  test "per_ip nil or zero disables the per-ip cap" do
    [ nil, 0 ].each do |setting|
      limiter = Limiter.new(10, per_ip: setting)
      5.times { assert limiter.acquire("192.0.2.1") }
    end
  end

  test "the per-ip table does not accumulate released peers" do
    limiter = Limiter.new(200, per_ip: 2)
    100.times do |i|
      ip = "10.0.0.#{i}"
      limiter.acquire(ip)
      limiter.release(ip)
    end

    assert_empty limiter.instance_variable_get(:@per_ip)
  end
end
