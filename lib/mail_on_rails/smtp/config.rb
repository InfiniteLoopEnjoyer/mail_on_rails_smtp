# frozen_string_literal: true

module MailOnRails
  module Smtp
    # Typed ENV reads with actionable failure messages. Misconfiguration is
    # a top cause of deployment outages: a bad value must name itself and
    # fail the boot (or `bin/server --check-config`), not surface as a bare
    # ArgumentError backtrace or - worse - misbehave quietly at runtime.
    module Config
      class Error < StandardError; end

      module_function

      # Integer env var with inclusive bounds; the default is trusted.
      def int(name, default, min: 0, max: nil)
        raw = ENV.fetch(name) { return default }
        value = begin
          Integer(raw)
        rescue ArgumentError
          raise Error, "#{name} must be an integer, got #{raw.inspect}"
        end
        if value < min || (max && value > max)
          range = max ? "between #{min} and #{max}" : ">= #{min}"
          raise Error, "#{name} must be #{range}, got #{value}"
        end
        value
      end

      def port(name, default)
        int(name, default, min: 1, max: 65_535)
      end
    end
  end
end
