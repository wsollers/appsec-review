LIMIT = 4 # ANCHOR:none

class Store
  def initialize(items) # BEGIN:initialize
    @items = items # ANCHOR:initialize
  end # END:initialize

  def render(prefix) # BEGIN:render
    lines = @items.map do |item|
      "#{prefix} #{item}" # ANCHOR:render
    end
    if lines.empty?
      return "" # ANCHOR:render
    end
    lines.each { |line| puts line }
    lines.join(",")
  end # END:render

  def self.build(raw) # BEGIN:build
    new(raw.split(",")) unless raw.nil? # ANCHOR:build
  end # END:build
end
