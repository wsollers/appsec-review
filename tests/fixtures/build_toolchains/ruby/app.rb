module Fixture
  class Handler
    def self.call(value)
      return :empty unless value

      value.to_s
    end
  end
end
