# frozen_string_literal: true

require "openssl"
require_relative "dns"

module MailOnRails
  module Smtp
    module SenderAuth
      # DKIM verifier (RFC 6376, plus RFC 8463 ed25519): checks each
      # DKIM-Signature header against the signer's public key in DNS.
      # Returns one result per signature:
      #
      #   { result:, domain:, selector:, detail: }
      #
      #   :pass      - signature and body hash verify against the DNS key
      #   :fail      - crypto mismatch (altered message) or expired signature
      #   :permerror - unusable signature or key (malformed, revoked, ...)
      #   :temperror - DNS lookup failed transiently
      class Dkim
        MAX_SIGNATURES = 5 # bound work a hostile message can demand

        class Unusable < StandardError; end

        def initialize(resolver)
          @resolver = resolver
        end

        def verify(raw)
          raw = raw.to_s.gsub(/(?<!\r)\n/, "\r\n")
          header_block, _, body = raw.partition("\r\n\r\n")
          headers = header_block.split(/\r\n(?![ \t])/)

          signatures = headers.each_index.select { |i| header_name(headers[i]).casecmp?("dkim-signature") }
          signatures.first(MAX_SIGNATURES).map { |i| verify_signature(headers, i, body) }
        end

        private

        def verify_signature(headers, sig_index, body)
          tags = parse_tags(headers[sig_index].split(":", 2).last)
          result = { domain: tags["d"].to_s.downcase, selector: tags["s"].to_s.downcase }

          begin
            validate_signature_tags(tags)
            digest, key_type = algorithm(tags["a"])
            header_canon, body_canon = (tags["c"] || "simple/simple").downcase.split("/", 2)
            body_canon ||= "simple"

            canonical_body = canonicalize_body(body, body_canon)
            canonical_body = truncate_to_length(canonical_body, tags["l"])
            bh = [ digest.digest(canonical_body) ].pack("m0")
            unless bh == tags["bh"].gsub(/\s/, "")
              return result.merge(result: :fail, detail: "body hash mismatch")
            end

            data = signed_header_data(headers, sig_index, tags["h"], header_canon)
            key = public_key(tags, key_type, digest)
            signature = decode64(tags["b"], "b")

            verified =
              if key_type == "ed25519"
                key.verify(nil, signature, digest.digest(data)) # RFC 8463: Ed25519 signs the header digest
              else
                key.verify(digest.new, signature, data)
              end
            verified ? result.merge(result: :pass) : result.merge(result: :fail, detail: "signature mismatch")
          rescue Unusable => e
            result.merge(result: :permerror, detail: e.message)
          rescue Dns::TempError
            result.merge(result: :temperror, detail: "DNS failure fetching key")
          rescue OpenSSL::PKey::PKeyError, OpenSSL::OpenSSLError => e
            result.merge(result: :permerror, detail: "key error: #{e.class}")
          end
        end

        # -- tag parsing ---------------------------------------------------------

        def parse_tags(value)
          value.to_s.split(";").each_with_object({}) do |pair, tags|
            name, val = pair.split("=", 2)
            next unless val

            tags[name.strip.downcase] ||= val.gsub(/\r\n[ \t]+/, " ").strip
          end
        end

        def validate_signature_tags(tags)
          raise Unusable, "unsupported version" unless tags["v"] == "1"

          %w[a b bh d h s].each do |required|
            raise Unusable, "missing #{required}= tag" if tags[required].to_s.empty?
          end

          signed = tags["h"].downcase.split(":").map(&:strip)
          raise Unusable, "From not signed" unless signed.include?("from")

          if tags["i"]
            i_domain = tags["i"].gsub(/\s/, "").split("@").last.to_s.downcase
            d = tags["d"].downcase
            unless i_domain == d || i_domain.end_with?(".#{d}")
              raise Unusable, "i= not within d= domain"
            end
          end

          if tags["x"] && tags["x"] =~ /\A\d+\z/ && Time.now.to_i > tags["x"].to_i
            raise Unusable, "signature expired"
          end
        end

        def algorithm(a_tag)
          case a_tag.to_s.downcase
          when "rsa-sha256" then [ OpenSSL::Digest::SHA256, "rsa" ]
          when "ed25519-sha256" then [ OpenSSL::Digest::SHA256, "ed25519" ]
          else raise Unusable, "unsupported algorithm #{a_tag}" # rsa-sha1 is historic (RFC 8301)
          end
        end

        def decode64(str, tag)
          str.gsub(/\s/, "").unpack1("m0") or raise Unusable, "empty #{tag}= tag"
        rescue ArgumentError
          raise Unusable, "invalid base64 in #{tag}= tag"
        end

        # -- body canonicalization -----------------------------------------------

        def canonicalize_body(body, mode)
          case mode
          when "simple"
            body.empty? ? "\r\n" : body.sub(/(\r\n)+\z/, "") + "\r\n"
          when "relaxed"
            lines = body.split("\r\n", -1).map { |l| l.gsub(/[ \t]+/, " ").sub(/ \z/, "") }
            lines.pop while lines.any? && lines.last.empty?
            lines.empty? ? "" : lines.join("\r\n") + "\r\n"
          else
            raise Unusable, "unknown body canonicalization #{mode}"
          end
        end

        def truncate_to_length(canonical_body, l_tag)
          return canonical_body unless l_tag

          length = Integer(l_tag, exception: false)
          raise Unusable, "invalid l= tag" unless length
          raise Unusable, "l= exceeds body length" if length > canonical_body.bytesize

          canonical_body.byteslice(0, length)
        end

        # -- header canonicalization ---------------------------------------------

        # Builds the signed data: each header named in h= (selected bottom-up
        # per RFC 6376 5.4.2), then the DKIM-Signature itself with b= emptied
        # and no trailing CRLF.
        def signed_header_data(headers, sig_index, h_tag, mode)
          candidates = Hash.new do |hash, name|
            hash[name] = headers.each_index.select do |i|
              i != sig_index && header_name(headers[i]).casecmp?(name)
            end
          end
          cursors = Hash.new { |hash, name| hash[name] = candidates[name].size }

          data = +""
          h_tag.split(":").map(&:strip).each do |name|
            cursors[name] -= 1
            index = cursors[name] >= 0 ? candidates[name][cursors[name]] : nil
            data << canonicalize_header(headers[index], mode) if index
          end

          stripped_sig = headers[sig_index].sub(/(\A|;)([\s]*b[ \t]*=)[^;]*/m, '\1\2')
          data << canonicalize_header(stripped_sig, mode).chomp("\r\n")
        end

        def canonicalize_header(line, mode)
          case mode
          when "simple"
            line + "\r\n"
          when "relaxed"
            name, value = line.split(":", 2)
            value = value.to_s.gsub(/\r\n(?=[ \t])/, "").gsub(/[ \t]+/, " ").strip
            "#{name.strip.downcase}:#{value}\r\n"
          else
            raise Unusable, "unknown header canonicalization #{mode}"
          end
        end

        def header_name(line)
          line.split(":", 2).first.to_s.strip
        end

        # -- key retrieval ---------------------------------------------------------

        def public_key(tags, key_type, digest)
          records = @resolver.txt("#{tags["s"]}._domainkey.#{tags["d"]}")
          record = records.find { |r| r.include?("p=") }
          raise Unusable, "no key record" unless record

          key_tags = parse_tags(record)
          if key_tags["v"] && !key_tags["v"].casecmp?("DKIM1")
            raise Unusable, "unsupported key version"
          end
          unless (key_tags["k"] || "rsa").casecmp?(key_type)
            raise Unusable, "key type mismatch"
          end
          if key_tags["h"] && key_tags["h"].downcase.split(":").map(&:strip).none?("sha256")
            raise Unusable, "hash not acceptable to key"
          end
          if key_tags["t"].to_s.split(":").map(&:strip).include?("s") && tags["i"]
            i_domain = tags["i"].split("@").last.to_s.downcase
            raise Unusable, "strict key forbids i= subdomain" unless i_domain == tags["d"].downcase
          end

          material = key_tags["p"].to_s.gsub(/\s/, "")
          raise Unusable, "key revoked" if material.empty?

          der = decode64(material, "p")
          if key_type == "ed25519"
            OpenSSL::PKey.new_raw_public_key("ED25519", der)
          else
            OpenSSL::PKey.read(der)
          end
        end
      end
    end
  end
end
