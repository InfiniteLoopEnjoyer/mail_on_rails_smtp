# frozen_string_literal: true

require "test_helper"
require "mail_on_rails/smtp/clamav_client"
require_relative "fake_clamd"

# The client's whole contract: a three-way verdict, never an exception.
# Anything that isn't a definite OK or FOUND from clamd - garbage, silence,
# a dead port - must come back :unavailable so the session can 451.
class ClamavClientTest < Minitest::Test
  RAW = "From: a@b.test\r\nSubject: hi\r\n\r\nbody\r\n"

  def scan(addr, timeout: 5)
    MailOnRails::Smtp::ClamavClient.new(addr: addr, timeout: timeout).scan(RAW)
  end

  def test_clean_reply
    FakeClamd.serving(:clean) do |addr|
      result = scan(addr)
      assert result.clean?
      assert_nil result.virus
    end
  end

  def test_infected_reply_carries_the_signature_name
    FakeClamd.serving(:infected) do |addr|
      result = scan(addr)
      assert result.infected?
      assert_equal "Eicar-Test-Signature", result.virus
    end
  end

  def test_unparseable_reply_is_unavailable_not_clean
    FakeClamd.serving(:garbage) do |addr|
      assert scan(addr).unavailable?
    end
  end

  def test_refused_connection_is_unavailable
    closed = TCPServer.new("127.0.0.1", 0)
    port = closed.addr[1]
    closed.close

    assert scan("127.0.0.1:#{port}").unavailable?
  end

  def test_silent_clamd_is_unavailable_bounded_by_the_timeout
    FakeClamd.serving(:hang) do |addr|
      started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      result = scan(addr, timeout: 1)
      elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started

      assert result.unavailable?
      assert_operator elapsed, :<, 5, "the timeout must bound a silent clamd"
    end
  end

  def test_addr_without_port_defaults_to_3310
    client = MailOnRails::Smtp::ClamavClient.new(addr: "clamd.internal", timeout: 1)
    assert_equal 3310, client.instance_variable_get(:@port)
  end
end
