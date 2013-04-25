#!/usr/bin/env ruby

# == Synopsis
# This script is designed to automate retrieval of headers from a list of web servers
#
#Input is a file with a list of HTTP servers to be reviewed
#
# == Pre-Requisites
#
#
# == ToDo
#
# * Add logging
# * Add rtf and html reports
# * Add TRACE and OPTIONS checks
#
# == Author
# Author::  Rory McCune
# Copyright:: Copyright (c) 2013 Rory Mccune
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
# == Options
#   -h, --help          	Displays help message
#   -v, --version       	Display the version, then exit
#   -f, --file            File containing servers to scan
#   --reportPrefix        Prefix for report files (Default is icmp_recon)
#   --textReport           Create a CSV report of the results
#   --hmtlReport          Create an HTML report of the results
#   --rtfReport           Create an RTF report of the results
#
#
# == Usage
#
#

class HTTPScan
  VERSION = '0.0.1'
  def initialize(hosts)
    begin
      require 'httparty'
    rescue LoadError
      puts "Requires httparty - try gem install httparty"
      exit
    end

    #require 'logger'

    #clean up the file so that it's easier to use uri
    hosts.collect! do |address|
      unless address =~ /^http/
        if address.split(':')[1] == '443'
          address = 'https://' + address
        else
          address = 'http://' + address
        end
      end
      address
    end
    @hosts = hosts
  end

  def header_scan

    @headers = Hash.new

    @hosts.each do |host|
      begin
        resp = HTTParty.options(host, {:no_follow => true})
      rescue HTTParty::RedirectionTooDeep => e
        @headers[host] = e.response.each_header
        #@headers[host]['Was Redirect'] = 'True'
        next
      rescue Timeout::Error
        puts "Timeout Error on " + host
        next
      rescue Exception => e
        puts "Error on " + host
        puts e.to_s
        next
      end

      @headers[host] = resp.headers

    end


  end

  def text_report(report_file_base)
    puts "starting report"
    header_report_file = File.new(report_file_base + '.txt' , 'a+')
    header_report_file.puts "Header Report"
    header_report_file.puts "-------------\n"

    @headers.each do |host, headers|
      header_report_file.puts host
      header_report_file.puts "----------------"
      headers.each do |key,val|
          header_report_file.puts key + " : " + val
      end
      header_report_file.puts "\n\n------------\n\n"
    end

  end

  def html_report

  end

  def rtf_report(report_file_base)
    begin
      require 'rtf'
      require 'uri'
    rescue LoadError
      puts "RTF reports need the rtf gem, gem install 'rtf' should do it"
      exit
    end
    document = RTF::Document.new(RTF::Font.new(RTF::Font::ROMAN, 'Arial'))
    document.paragraph << "Web Server Headers"
    methods = Hash.new
    @headers.each do |host, headers|
      headers.each do |key, val|
        if key.downcase == 'allow'
          methods[host] = val
        end
      end
    end

    header_table = document.table(@headers.length + 1, 2,3000,5000)
    header_table.border_width = 5
    header_table[0][0] << 'IP Address'
    header_table[0][1] << "Web Server Headers"
    row = 1
    @headers.each do |host, headers|
      header_table[row][0] << host
      headers.each do |key,val|
        header_table[row][1] << key + ' : ' + val
        header_table[row][1].line_break
      end
      row = row + 1
    end

    document.paragraph << "Web Server Methods"

    methods_table = document.table(methods.length + 1, 2,3000,5000)
    methods_table.border_width = 5
    methods_table[0][0] << 'IP Address'
    methods_table[0][1] << "Methods Supported"
    mrow = 1
    methods.each do |host, methods|
      methods_table[mrow][0] << host
      methods_table[mrow][1] << methods
      mrow = mrow + 1
    end

    rtf_report_file = File.open(report_file_base + '.rtf', 'a+') do |file|
      file.write(document.to_rtf)
    end


  end

end







if __FILE__ == $0
  require 'optparse'
  require 'ostruct'
  options = OpenStruct.new
  options.input_file = ''
  options.report_file_base = 'rep_header_scan'
  options.text_report = false
  options.html_report = false
  options.rtf_report = false

  opts = OptionParser.new do |opts|
    opts.banner = "HTTP Scanner #{HTTPScan::VERSION}"

    opts.on("-f", "--file [FILE]", "Input File with list of servers") do |file|
      options.input_file = file
    end

    opts.on("--textReport", "Create a text Report") do |textrep|
      options.text_report = true
    end

    opts.on("--htmlReport", "Create an HTML Report") do |htmlrep|
      options.html_report = true
    end

    opts.on("--rtfReport", "Create an RTF Report") do |rtfrep|
      options.rtf_report = true
    end

    opts.on("--reportPrefix [REPREF]", "Prefix for report files") do |repref|
      options.report_file_base = repref
    end

    opts.on("-h", "--help", "-?", "--?", "Get Help") do |help|
      puts opts
      exit
    end

    opts.on("-v", "--version", "Get Version") do |ver|
      puts "ICMP Reconnaissance Tool #{HeaderScan::VERSION}"
      exit
    end

  end

  opts.parse!(ARGV)

  unless options.input_file.length > 1
    puts "You need to specify an input file name"
    puts opts
    exit
  end

  unless options.rtf_report || options.text_report || options.html_report
    puts "no reporting specified"
    puts "you need to use one of --textReport, --htmlReport or --rtfReport"
    puts opts
    exit
  end

  begin
    input_hosts = File.open(options.input_file, 'r').readlines
    input_hosts.each {|host| host.chomp!}
  rescue Exception => e
    puts "couldn't open the file supplied, check permissions/spelling?"
    puts e
    exit
  end

  scan = HTTPScan.new(input_hosts)

  scan.header_scan

  if options.text_report
    scan.text_report(options.report_file_base)
  end

  if options.html_report
    scan.html_report
  end

  if options.rtf_report
    scan.rtf_report(options.report_file_base)
  end


end
