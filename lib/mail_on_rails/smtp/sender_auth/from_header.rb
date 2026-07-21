# frozen_string_literal: true

module MailOnRails
  module Smtp
    module SenderAuth
      # Extracts the visible From: header domain - DMARC's subject - from raw
      # message data. Replaces the mail gem's parser for this one job: the
      # gem is not Ractor-safe (class variables in Mail::Message), and
      # sessions run inside worker Ractors.
      #
      # The contract matches the previous implementation: nil whenever the
      # header is absent, unparseable, or holds anything other than exactly
      # one mailbox (DMARC has no defined verdict there, and nil makes the
      # DMARC evaluator return permerror). This is deliberately a small
      # RFC 5322 subset - quoted strings, comments, one angle-addr, an
      # obsolete route - that bails to nil on anything exotic rather than
      # guessing.
      module FromHeader
        module_function

        # => lowercased domain String, or nil.
        def domain(data)
          fields = unfolded_headers(data)
          from = fields.select { |f| f.match?(/\Afrom[ \t]*:/i) }
          return nil unless from.size == 1

          mailboxes = split_mailboxes(from.first.sub(/\Afrom[ \t]*:/i, ""))
          return nil unless mailboxes&.size == 1

          mailbox_domain(mailboxes.first)
        end

        # Header block cut at the first empty line, tolerating bare-LF input
        # the same way the previous implementation did, unfolded into one
        # string per field.
        def unfolded_headers(data)
          block = data.to_s.gsub(/(?<!\r)\n/, "\r\n").partition("\r\n\r\n").first
          block.split(/\r\n(?![ \t])/).map { |field| field.gsub("\r\n", "") }
        end

        # Splits a mailbox-list on top-level commas, tracking quoted
        # strings, nested comments, and angle brackets. Returns nil on
        # unbalanced input or group syntax (a top-level colon/semicolon -
        # groups are not valid in From, and DMARC has no verdict for them).
        def split_mailboxes(body)
          parts = [ +"" ]
          quoted = false
          escaped = false
          comment = 0
          angle = 0

          body.each_char do |ch|
            if escaped
              escaped = false
            elsif quoted
              case ch
              when "\\" then escaped = true
              when '"' then quoted = false
              end
            else
              case ch
              when '"' then quoted = true unless comment.positive?
              when "(" then comment += 1
              when ")"
                comment -= 1
                return nil if comment.negative?
              when "<" then angle += 1 if comment.zero?
              when ">"
                if comment.zero?
                  angle -= 1
                  return nil if angle.negative?
                end
              when ","
                if comment.zero? && angle.zero?
                  parts << +""
                  next
                end
              when ":", ";"
                return nil if comment.zero? && angle.zero?
              end
            end
            parts.last << ch
          end
          return nil if quoted || comment.positive? || angle.positive?

          parts.map(&:strip).reject(&:empty?)
        end

        def mailbox_domain(mailbox)
          spec = addr_spec(mailbox)
          return nil unless spec

          domain = domain_part(spec)
          return nil unless domain&.match?(/\A[^\s@\[\]<>:;,"]+\z/)

          domain.downcase
        end

        # The addr-spec: the content of the single top-level angle-addr if
        # present (minus any obsolete route), otherwise the mailbox with
        # comments stripped.
        def addr_spec(mailbox)
          content = angle_contents(mailbox)
          return nil if content == :invalid

          spec = (content || strip_comments(mailbox)).strip
          spec = strip_route(spec)
          spec&.empty? ? nil : spec
        end

        # nil when no angle-addr; :invalid when more than one.
        def angle_contents(mailbox)
          contents = []
          quoted = false
          escaped = false
          comment = 0
          depth = 0

          mailbox.each_char do |ch|
            if escaped
              escaped = false
            elsif quoted
              case ch
              when "\\" then escaped = true
              when '"' then quoted = false
              end
            else
              case ch
              when '"' then quoted = true unless comment.positive?
              when "(" then comment += 1
              when ")" then comment -= 1
              when "<"
                if comment.zero?
                  return :invalid if depth.positive? # nested angles

                  depth = 1
                  contents << +""
                  next
                end
              when ">"
                if comment.zero?
                  depth = 0
                  next
                end
              end
            end
            contents.last << ch if depth.positive? && contents.any?
          end
          return :invalid if contents.size > 1

          contents.first
        end

        # RFC 5322 obs-route: "<@relay1,@relay2:user@example.com>". A colon
        # is only valid as a route terminator (or inside a quoted local
        # part), so a route-less spec containing one is malformed.
        def strip_route(spec)
          return spec unless spec.start_with?("@")

          route, found, rest = spec.partition(":")
          found.empty? || route.include?('"') ? nil : rest.strip
        end

        def strip_comments(str)
          out = +""
          quoted = false
          escaped = false
          comment = 0

          str.each_char do |ch|
            if escaped
              escaped = false
            elsif quoted
              case ch
              when "\\" then escaped = true
              when '"' then quoted = false
              end
            else
              case ch
              when '"' then quoted = true unless comment.positive?
              when "("
                comment += 1
                next
              when ")"
                comment -= 1
                next
              end
            end
            out << ch if comment.zero?
          end
          out
        end

        # The text after the last @ that is outside the (possibly quoted)
        # local part.
        def domain_part(spec)
          at = nil
          quoted = false
          escaped = false
          spec.each_char.with_index do |ch, i|
            if escaped
              escaped = false
            elsif quoted
              case ch
              when "\\" then escaped = true
              when '"' then quoted = false
              end
            else
              case ch
              when '"' then quoted = true
              when "@" then at = i
              end
            end
          end
          at && spec[(at + 1)..]
        end
      end
    end
  end
end
