# frozen_string_literal: true

require_relative "scram_smtp_test"

# A SCRAM exchange is adjudicated here, not in the store, so the store's
# count-before-the-verdict (a reservation, Store::Base#scram_credentials
# with reserve: true) only works if the session plays its part: ask for
# the reservation, hand it back when the proof verifies, report it as
# already counted when the proof does not, and leave it standing when the
# client walks away. Without that, parallel exchanges all pass the
# throttle check before any failure lands.
class ScramReservationTest < ScramSmtpTest
  # Drop the inherited cases: this file adds its own on the same helpers.
  ScramSmtpTest.instance_methods(false).grep(/\Atest_/).each { |name| undef_method(name) }

  # The memory store plus the optional reservation methods, recording
  # how the session used them.
  class ReservingStore < MailOnRails::Smtp::Store::Memory
    attr_reader :calls

    def initialize(...)
      super
      @calls = []
    end

    def scram_credentials(email, ip: nil, reserve: false)
      @calls << [ :lookup, reserve ]
      material = super(email, ip: ip)
      reserve ? material.merge(reservation: [ :hold, email ]) : material
    end

    def record_auth_failure(email, ip: nil, source: nil, reservation: nil)
      @calls << [ :failure, reservation ]
      {}
    end

    def record_auth_success(email, reservation: nil)
      @calls << [ :success, email, reservation ]
      {}
    end
  end

  def setup
    @store = ReservingStore.new
    @store.add_account(email: EMAIL, password: PASSWORD)
  end

  test "a verified proof gives the reservation back" do
    with_session do |client|
      assert_match(/\A235 /, auth_scram(client))
    end

    assert_equal [ [ :lookup, true ], [ :success, EMAIL, [ :hold, EMAIL ] ] ], @store.calls
  end

  test "a bad proof is reported with its reservation, so the store does not count it twice" do
    with_session do |client|
      assert_match(/\A535 /, auth_scram(client, password: "wrong-password"))
    end

    assert_equal [ [ :lookup, true ], [ :failure, [ :hold, EMAIL ] ] ], @store.calls
  end

  test "an exchange abandoned after the challenge stays counted" do
    with_session do |client|
      server_first, = begin_exchange(client)
      assert server_first
      assert_match(/\A501 /, command(client, "*"))
      assert_match(/\A250 /, command(client, "NOOP"))
    end

    assert_equal [ [ :lookup, true ] ], @store.calls, "neither refunded nor reported: the reservation stands"
  end

  test "a store without record_auth_success is asked the old way" do
    @store = MailOnRails::Smtp::Store::Memory.new
    @store.add_account(email: EMAIL, password: PASSWORD)

    with_session do |client|
      assert_match(/\A235 /, auth_scram(client))
    end
  end
end
