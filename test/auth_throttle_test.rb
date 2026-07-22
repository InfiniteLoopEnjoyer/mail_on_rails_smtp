# frozen_string_literal: true

require "test_helper"
require "mail_on_rails/smtp/auth_throttle"

class AuthThrottleTest < Minitest::Test
  Throttle = MailOnRails::Smtp::AuthThrottle
  IP = "192.0.2.1"

  def setup
    @now = 1000.0
    @throttle = Throttle.new(limit: 3, window: 60, clock: -> { @now })
  end

  test "locks after the limit and reports the transition exactly once" do
    assert_nil @throttle.record(IP)
    assert_nil @throttle.record(IP)
    refute @throttle.locked?(IP), "below the limit must not lock"
    assert_equal :locked, @throttle.record(IP)
    assert @throttle.locked?(IP)
    assert_nil @throttle.record(IP), "the lock transition must be reported only once"
  end

  test "the lockout expires after the window" do
    3.times { @throttle.record(IP) }
    @now += 61

    refute @throttle.locked?(IP)
  end

  test "a quiet period forgives the failure count" do
    2.times { @throttle.record(IP) }
    @now += 61
    @throttle.record(IP) # would be the 3rd without decay

    refute @throttle.locked?(IP), "decayed failures must not count toward the lockout"
  end

  test "failures while locked extend the lockout" do
    3.times { @throttle.record(IP) }
    @now += 30
    @throttle.record(IP) # an in-flight session failing again
    @now += 45           # 75s past the original lock, 45s past the extension

    assert @throttle.locked?(IP)
  end

  test "ips are tracked independently" do
    3.times { @throttle.record(IP) }

    refute @throttle.locked?("192.0.2.2")
  end

  test "nil or zero limit disables the throttle" do
    [ nil, 0 ].each do |limit|
      throttle = Throttle.new(limit: limit, window: 60, clock: -> { @now })
      5.times { assert_nil throttle.record(IP) }

      refute throttle.locked?(IP)
    end
  end

  test "nil ip is ignored" do
    assert_nil @throttle.record(nil)
    refute @throttle.locked?(nil)
  end

  test "expired entries are swept once the table grows large" do
    threshold = Throttle::SWEEP_THRESHOLD
    (threshold + 1).times { |i| @throttle.record("10.#{i / 65_536}.#{(i / 256) % 256}.#{i % 256}") }
    @now += 61
    @throttle.record("192.0.2.99") # first record past the threshold sweeps

    assert_operator @throttle.instance_variable_get(:@entries).size, :<=, 2,
                    "expired entries must be purged, not retained forever"
  end
end
