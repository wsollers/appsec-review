require_relative "support"
require "json"

module Audit
  class Processor
    def self.build(enabled)
      enabled ? new : nil
    end

    def transform(items)
      normalize = ->(value) { value.nil? ? "" : value.to_s }
      items.each do |item|
        next unless item

        if item.respond_to?(:call) && !item.frozen?
          Support.record(normalize.call(item.call))
        elsif item.is_a?(String)
          Support.record(item.strip)
        else
          Support.record(normalize.call(item))
        end
      end
    end

    def classify(value)
      case value
      when Integer
        :number
      when String
        :text
      else
        :other
      end
    rescue StandardError
      :invalid
    end
  end
end
