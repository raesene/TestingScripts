#!/usr/bin/env ruby
  # == Synopsis  
  # This script iterates over the autocomplete view for a Drupal site and uses this to construct a list of user accounts
  # Currently just does a-z so will miss ones that start differently, but a decent starting point.
  # == Author
  # Author::  Rory McCune
  # Copyright:: Copyright (c) 2014 Rory McCune
  # License:: GPLv3
  #
  # This program is free software: you can redistribute it and/or modify
  # it under the terms of the GNU General Public License as published by
  # the Free Software Foundation, either version 3 of the License, or
  # (at your option) any later version.
  #
  # This program is distributed in the hope that it will be useful,
  # but WITHOUT ANY WARRANTY; without even the implied warranty of
  # MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  # GNU General Public License for more details.
  #
  # You should have received a copy of the GNU General Public License
  # along with this program.  If not, see <http://www.gnu.org/licenses/>.
  #
  # == Usage 
  #
  #   drupalusers.rb <hostname>

begin
  require 'httparty'
  require 'json'
  rescue LoadError => e
  puts "Failed to load one of the libraries"
  puts e.to_s
  exit
end  


if ARGV.length < 1
  puts "format is drupalusers.rb <hostname>"
  exit
end

domain = ARGV[0]
output_file = File.new('drupalusers-' + domain + '.txt','a+')
url = 'http://' + domain + '/?q=admin/views/ajax/autocomplete/user/'
all_users = Array.new

#Do a test request to make sure we can get access
begin
  response = HTTParty.get(url + 'a')
rescue SocketError => e
  puts "couldn't find the host"
  exit
rescue Errno::ETIMEDOUT
  puts "Connection to host timed out, is there a web server running there?"
  exit 
end



('a'..'z').each do |letter|
	response = HTTParty.get(url + letter)
	users = JSON.parse(response.body)
	users.each {|name, value| all_users << value}
end

all_users.uniq.each {|user| output_file.puts user}