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
# *
# *
#
# == Author
# Author::  Rory McCune
# Copyright:: Copyright (c) 2012 Rory McCune
# License:: GPLv3
#
# == Options
#   -h, --help          	Displays help message
#   -v, --version       	Display the version, then exit
#   -f, --file            File containing servers to scan
#   --reportPrefix        Prefix for report files (Default is icmp_recon)
#   --csvReport           Create a CSV report of the results
#   --hmtlReport          Create an HTML report of the results
#   --rtfReport           Create an RTF report of the results
#
#
# == Usage
#
#

class HTTPScan
  VERSION = '0.0.1'
  def initialize
    require 'logger'
  end

  def header_scan(hosts)

  end

  def csv_report

  end

  def html_report

  end

  def rtf_report

  end

end







if __FILE__ == $0
  require 'optparse'
  require 'ostruct'
  options = OpenStruct.new
  options.input_file = ''
  options.report_file_base = 'rep_header_scan'
  options.csv_report = false
  options.html_report = false
  options.rtf_report = false

  opts = OptionParser.new do |opts|
    opts.banner = "HTTP Scanner #{HTTPScan::VERSION}"

    opts.on("-f", "--file [FILE]", "Input File with list of servers") do |file|
      options.input_file = file
    end

    opts.on("--csvReport", "Create a CSV Report") do |csvrep|
      options.csv_report = true
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

  unless options.rtf_report || options.csv_report || options.html_report
    puts "no reporting specified"
    puts "you need to use one of --csvReport, --htmlReport or --rtfReport"
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

  scan = HTTPScan.new

  scan.header_scan(input_hosts)

  if options.csv_report
    scan.csv_report
  end

  if options.html_report
    scan.html_report
  end

  if options.rtf_report
    scan.rtf_report
  end


end