#!/usr/bin/env ruby
# Hacky script to spider a Kubernetes API server for paths via the kubectl proxy server on 8001/HTTP
# TODO: make this less hacky

require 'httparty'

base_url = 'http://127.0.0.1:8001'
final_paths = Array.new
final_paths_and_methods = Hash.new
# There is a more elegant way to do this
final_paths_and_methods['create'] = Array.new
final_paths_and_methods['delete'] = Array.new
final_paths_and_methods['deletecollection'] = Array.new
final_paths_and_methods['get'] = Array.new
final_paths_and_methods['list'] = Array.new
final_paths_and_methods['patch'] = Array.new
final_paths_and_methods['update'] = Array.new
final_paths_and_methods['watch'] = Array.new


paths_file = File.new('k8s_server_paths.txt','w+')
paths_and_methods_file = File.new('k8s_server_paths_and_methods.txt','w+')


base = HTTParty.get(base_url)

base.parsed_response['paths'].each do |path|
  final_paths << path
  # We can always get the path so add it to that array
  final_paths_and_methods['get'] << path
  puts "getting #{path}"
  response = HTTParty.get(base_url + path)
  # We're not interested unless there's a response
  next unless response.ok?
  if response.parsed_response['resources']
    begin
      response.parsed_response['resources'].each do |subpath|
        resource = subpath['name']
        final_paths << path + '/' + resource
      end
    # We're rescuing NoMethod for cases where the resources section isn't an array (seems to happen on some openapi paths)
    rescue NoMethodError
      puts "got a fail on #{path}"
    end
    # Now lets populate the methods available for these resources
    begin
      response.parsed_response['resources'].each do |subpath|
        resource = subpath['name']
        subpath['verbs'].each do |verb|
          final_paths_and_methods[verb] << path + '/' + resource
        end
      end
    rescue NoMethodError
      puts "got a fail on #{path}"
    end
  end
end


puts final_paths.join("\n")
paths_file.puts final_paths.join("\n")
paths_file.close

puts "\n ====== \n"

final_paths_and_methods.each do |key, value|
 puts "\n#{key} paths \n=======\n"
 paths_and_methods_file.puts "\n#{key} paths \n=======\n"
 puts value.join("\n")
 paths_and_methods_file.puts value.join("\n")
end
paths_and_methods_file.close

