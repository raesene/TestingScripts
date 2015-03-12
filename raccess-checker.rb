#!/usr/bin/env ruby

# == Author
# Author::  Rory McCune
# Copyright:: Copyright (c) 2015 Rory Mccune
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
# == Synopsis
# This class is designed to take a list of URLs and automatically perform some checks on them
# As part of a web application security review
# TODO:  Need to setup initialize function properly, split out reporting, implement some more checks
# TODO: Consider re-basing on net/http/persistent if it get a bit more stable.
# TODO: Ports for SSL shouldn't be hard-coded to 443
# TODO: Change file extensions to csv 
# TODO: RubyXL with conditional formatting
# TODO: Abstract request handling



class RaccessChecker
VERSION = '0.1'
BACKUP_EXTENSIONS = ['txt','src','inc','old','bak']
SVN_EXTENSIONS = ['/.svn/entries']
#USERAGENT = 'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.0.1) Gecko/20060111 Firefox/1.5.0.1'
USERAGENT = 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0'
PROXY_SERVER = '127.0.0.1'
PROXY_PORT = '8080'

  
  


def initialize(arguments)
  
  require 'rubygems'
  require 'net/http'
  require 'net/https'
  require 'logger'
  require 'optparse'
  require 'ostruct'

  @log = Logger.new('site-access-log')
  @log.level = Logger::DEBUG
  @log.debug("Log Created at " + Time.now.to_s)

  @options = OpenStruct.new
  
  @options.input_file_name = nil
  @options.input_file = nil
  @options.unique_url_file = nil
  @options.access_report_file = nil
  @options.backup_report_file = nil
  @options.check_http = false
  @options.host = nil
  @options.port = 80
  @options.verbose = false

  opts = OptionParser.new do |opts|
    opts.banner = "Ruby Access Checker"

    opts.on("-iINPUT","--input INPUT", "File containing the URLs to be checked ") do |file|
      @log.debug("Trying to open Input File")
      @options.input_file_name = file
      begin
        @options.input_file = File.open(file).readlines
      rescue Errno::ENOENT
        @log.fatal("Input File #{file} could not be opened")
        puts "Couldn't open input file, sure it's there?"
        exit
      end
      @log.debug("Opened file ok")
      @options.input_file.each {|input| input.chomp!}
    end

    opts.on("-sSERVER","--server SERVER", "Server to be reviewed") do |server|
      @options.host = server
    end

    opts.on("-pPort","--port PORT", "Port for server") do |port|
      @options.port = port
    end

    opts.on("--check_http", "Check all URLs on port 80") do |http|
      @options.check_http = true
    end

    opts.on("--verbose", "Be verbose during testing") do |v|
      @options.verbose = true
    end

    
    opts.on("-h","--help","-?","--?", "Get Help") do |help|
      puts opts
      exit
    end
    
    opts.on("-v","--version", "Get Version") do |ver|
      puts "Ruby Website Access Checker version #{VERSION}"
      exit
    end
  end

  if arguments.length == 0
    puts opts
    exit  
  end

  begin
    opts.parse!(arguments)
  rescue OptionParser::InvalidOption => e
    puts 'Got an invalid Option'
    puts 'Try -h to get a list of valid options'
    puts 'More details'
    puts '------------'
    puts e
    exit
  end


  @http = Net::HTTP::Proxy(PROXY_SERVER,PROXY_PORT).new(@options.host,@options.port)
  @https = Net::HTTP::Proxy(PROXY_SERVER,PROXY_PORT).new(@options.host,@options.port)
  @https.use_ssl = true
  @https.verify_mode = OpenSSL::SSL::VERIFY_NONE
end


def create_unique_url_list
  @options.unique_url_file = File.new(@options.input_file_name + '.unique','a+')
  @final_urls = Array.new

  @options.input_file.each do |line|
    next if line.length < 1
    begin
      url = URI.parse(line)
    rescue URI::InvalidURIError
      @log.info("invalid URL " + line)
      if @options.verbose
        puts 'whups invalid : ' + line
      end
      next
    end
    if !url.path
      url.path = '/'
    end
    begin
      @final_urls << url.scheme + '://' + url.host + url.path
    rescue NoMethodError
      puts 'no method yikes'
    end
  end

  @final_urls.uniq!
  @final_urls.each {|url| @options.unique_url_file.puts url}
end


def access_check
  if @options.verbose
    puts ''
    puts "access check starting"
    puts "----------------------"
    puts ''
  end
  #Idempotent Checks
  @options.get_request_access_file = File.new(@options.input_file_name + '.get_request_access','a+')
  @options.head_request_access_file = File.new(@options.input_file_name + '.head_request_access','a+')


  @final_urls.each do |test|
    url = URI.parse(test)
    begin
    if url.scheme == 'http'
      get_response = @http.get(url.request_uri, {'Host' => url.host})
      head_response = @http.head(url.request_uri, {'Host' => url.host})
    elsif url.scheme == 'https'
      get_response = @https.get(url.request_uri, {'Host' => url.host})
      head_response = @https.head(url.request_uri, {'Host' => url.host})
    end
    rescue NoMethodError => e
      puts "error with url " + url.request_uri
      puts e
      next
    rescue Errno::ETIMEDOUT
      puts "timeout"
      next
    rescue Errno::ECONNRESET
      puts "Connection Reset on " + url.request_uri
      next
    rescue Timeout::Error
      puts "timeout on " + url.request_uri
      next
    rescue Errno::ECONNREFUSED
      puts "connection refused on " + url.request_uri
      next
    end
    @options.get_request_access_file.puts(url.scheme + '://' + url.host + url.path + ',' + get_response.code + ',' + get_response.body.length.to_s)
    @options.head_request_access_file.puts(url.scheme + '://' + url.host + url.path + ',' + head_response.code + ',' + '0')
    if @options.verbose
      print '.'
    end
  end

end

def dangerous_access_checks
  #This uses HTTP Methods that can affect content on the server be very sure before trying this
  @options.post_request_access_file = File.new(@options.input_file_name + '.post_request_access','a+')
  @options.put_request_access_file = File.new(@options.input_file_name + '.put_request_access','a+')
  @options.delete_request_access_file = File.new(@options.input_file_name + '.delete_request_access','a+')
  @final_urls.each do |test|
    url = URI.parse(test)
    begin
    if url.scheme == 'http'
      #post_response = @http.get(url.request_uri, {'Host' => url.host})
      #put_response = @http.head(url.request_uri, {'Host' => url.host})
      #delete_response = 
    elsif url.scheme == 'https'
      #get_response = @https.get(url.request_uri, {'Host' => url.host})
      #head_response = @https.head(url.request_uri, {'Host' => url.host})
      #delete_response = 
    end
    rescue NoMethodError => e
      puts "error with url " + url.request_uri
      puts e
      next
    rescue Errno::ETIMEDOUT
      puts "timeout"
      next
    rescue Errno::ECONNRESET
      puts "Connection Reset on " + url.request_uri
      next
    rescue Timeout::Error
      puts "timeout on " + url.request_uri
      next
    rescue Errno::ECONNREFUSED
      puts "connection refused on " + url.request_uri
      next
    end
    @options.get_request_access_file.puts(url.scheme + '://' + url.host + url.path + ',' + get_response.code + ',' + get_response.body.length.to_s)
    @options.head_request_access_file.puts(url.scheme + '://' + url.host + url.path + ',' + head_response.code + ',' + head_response.body.length.to_s)
    if @options.verbose
      print '.'
    end
  end
end

def backup_check
  @options.backup_file = File.new(@options.input_file_name + '.backup','a+')
  @options.backup_file.puts "url, base_result, txt_result, src_result, inc_result, old_result, bak_result"
  if @options.verbose
    puts ''
    puts "backup check starting"
    puts "----------------------"
    puts ''
  end


  @final_urls.each do |test|
    url = URI.parse(test)
    #next unless url.path.match(/\.[a-zA-Z0-9]+$/)
    @options.backup_file.print(url.scheme + '://' + url.host + url.path)
    base_path = url.path.sub(/\.[a-zA-Z0-9]+$/,'')
    resp, data = get_page(url)
    @options.backup_file.print ',' + resp.code
    BACKUP_EXTENSIONS.each do |ext|
      begin
      if url.scheme == 'http'
        resp, data = @http.get(base_path + '.' + ext, {'Host' => url.host})
      elsif url.scheme == 'https'
        resp, data = @https.get(base_path + '.' + ext, {'Host' => url.host})
      end
      rescue Errno::ETIMEDOUT
        puts 'timeout'
        next
      rescue Timeout::Error
        puts "timeout on " + url.request_uri
        next
      rescue EOFError
        puts "End of file error on " + url.request_uri
      end
      @options.backup_file.print ',' + resp.code
      if @options.verbose
        print '.'
      end
    end
    @options.backup_file.print "\n"
  end
end

def check_http
  #The point of this method is to automatically test for cases where you're looking at an https site but want to check whether the file is available unencrypted
  #over port 80.
  #don't run if the options not set
  @log.debug("@options.port is " + @options.port)
  exit unless @options.check_http
  @log.debug("http check was passed the relevant command line option")
  #don't run if we're not checking an SSL site
  exit unless @options.port == '443'
  @log.debug("HTTP check running")
  if @options.verbose
    puts ''
    puts 'http access check'
    puts '-----------------'
    puts ''
  end
  #Need to use a new connection hardcoded to 80
  http = Net::HTTP::Proxy(PROXY_SERVER,PROXY_PORT).new(@options.host,80)
  @options.http_request_access_file = File.new(@options.input_file_name + '.http_access','a+')    
  @final_urls.each do |test|
    url = URI.parse(test)
    begin
      get_response = http.get(url.request_uri, {'Host' => url.host})
      https_get_response = @https.get(url.request_uri, {'Host' => url.host})
    rescue NoMethodError => e
      puts "error with url " + url.request_uri
      puts e
      next
    rescue Errno::ETIMEDOUT
      puts "timeout"
      next
    rescue Errno::ECONNRESET
      puts "Connection Reset on " + url.request_uri
      next
    rescue Timeout::Error
      puts "timeout on " + url.request_uri
      next
    rescue Errno::ECONNREFUSED
      puts "connection refused on " + url.request_uri
      next
    end
    @options.http_request_access_file.puts(url.scheme + '://' + url.host + url.path + ',' + get_response.code + ',' + https_get_response.code)
    if @options.verbose
      print '.'
    end
  end
end

def svn_check
  if @options.verbose
    puts ''
    puts 'SVN Check'
    puts '---------'
    puts ''
  end
  @options.svn_file = File.new(@options.input_file_name + '.svn','a+')
  @options.svn_file.puts "url, base_result, svn_result"
  @final_urls.each do |test|
    url = URI.parse(test)
    #next unless url.path.match(/\.[a-zA-Z0-9]+$/)
    @options.svn_file.print(url.scheme + '://' + url.host + url.path)
    base_path = url.path.sub(/\/[a-zA-Z0-9]+$/,'')
    resp, data = get_page(url)
    @options.svn_file.print ',' + resp.code
    SVN_EXTENSIONS.each do |ext|
      if url.scheme == 'http'
        resp, data = @http.get(base_path + ext, {'Host' => url.host})
      elsif url.scheme == 'https'
        resp, data = @https.get(base_path + ext, {'Host' => url.host})
      end
      @options.svn_file.print ',' + resp.code
      if @options.verbose
        print '.'
      end
    end
    @options.svn_file.print "\n"
  end
end

def git_check
  if @options.verbose
    puts ''
    puts 'Git Check'
    puts '---------'
    puts ''
  end
  @options.git_file = File.new(@options.input_file_name + '.git', 'a+')
  @options.git_file.puts "url, base_result, git_result"
  @final_urls.each do |test|
    #Only test Directories.  Really we should have a diretories only file for this kind of test
    next unless test =~ /\/$/
    url = URI.parse(test)
    @options.git_file.print(url.scheme + '://' + url.host + url.path)
    resp, data = get_page(url)
    @options.git_file.print ',' + resp.code
    if url.scheme == 'http'
      resp, data = @http.get(url.path + '.git/HEAD', {'Host' => url.host})
    elsif url.scheme == 'https'
      resp, data = @https.get(url.path + '.git/HEAD', {'Host' => url.host})
    end
    @options.git_file.print ',' + resp.code
    if @options.verbose
      print '.'
    end
    @options.git_file.print "\n"
  end
end

private

def get_page(url)
  begin
    if url.scheme == 'http'
      resp, data = @http.get(url.path, {'Host' => url.host})
    elsif url.scheme == 'https'
      resp, data = @https.get(url.path, {'Host' => url.host})
    end
  rescue Errno::ETIMEDOUT
    puts 'timeout'
  rescue Timeout::Error
    puts "timeout on " + url.request_uri
  rescue Errno::ECONNREFUSED
    puts "connection refused on " + url.request_uri
  end
  return resp, data
end
end


if __FILE__ == $0
  checker = RaccessChecker.new(ARGV)
  checker.create_unique_url_list
  checker.access_check
  checker.backup_check
  checker.svn_check
  checker.git_check
  checker.check_http
end  
