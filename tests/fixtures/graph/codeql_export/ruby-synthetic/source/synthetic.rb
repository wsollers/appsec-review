require "net/http"

class User < ActiveRecord::Base
end

class Store
  def fetch(path)
    File.read(File.basename(path))
  end
end

class CachedStore < Store
  def fetch(path)
    File.read(path)
  end
end

class UsersController < ActionController::Base
  def show
    name = params[:name]
    User.find_by_sql("SELECT * FROM users WHERE name = '" + name + "'")
  end

  def run
    cmd = params[:cmd]
    if cmd == "status"
      system(cmd)
    end
    system(cmd)
  end

  def download
    host = params[:host]
    Net::HTTP.get(host, "/status")
  end

  def restore
    blob = params[:blob]
    Marshal.load(blob)
  end

  def read_file
    store_for(params[:kind]).fetch(params[:path])
  end

  def dispatch_action
    helper = params[:helper]
    send(helper)
  end

  private

  def store_for(kind)
    kind == "cached" ? CachedStore.new : Store.new
  end
end

module Cli
  def self.query(name)
    "SELECT * FROM users WHERE name = '" + name + "'"
  end

  def self.main
    User.find_by_sql(query(ARGV[0]))
    editor = ENV["EDITOR"]
    system(editor)
  end
end