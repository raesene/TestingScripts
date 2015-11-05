#!/usr/bin/env ruby
require 'rubygems'
require 'rack'
builder = Rack::Builder.new do
  use Rack::CommonLogger
  @@grabbed = Array.new
  map '/' do
    run Proc.new {|env| [200, {"Content-Type" => "text/html"}, ["<h1> Rack Pen Test Helper</h1>"]]}
  end
 
  map '/cookiegrabber' do
    app = proc do |env|
      req = Rack::Request.new(env) 
      ip = req.ip.to_s
      cookie = req.params['cookie'] || "No Cookie Parameter passed"
      @@grabbed << [ip,cookie]
      [200, {"Content-Type" => "text/html"}, ["grabbed " + cookie + " from " + ip + "<br /> Grabbed " + @@grabbed.length.to_s + " cookies so far"]]
    end
    run app
  end
 
  map '/cookiegrabbed' do
    app = proc do |env|
      out = ""
      if @@grabbed.length > 0
        @@grabbed.each do |crumb|
          out << "Grabbed a cookie with value  " + crumb[1] + " from " + crumb[0] + "<br />"
        end
      else
        out = "Nothing Grabbed so far"
      end
      [200, {"Content-Type" => "text/html"}, [out]]
    end
    run app
  end
end
Rack::Handler::WEBrick.run builder, :Port => 9292
