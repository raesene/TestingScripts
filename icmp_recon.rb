#!/usr/bin/env ruby

# == Synopsis
# This application is designed to perform ICMP reconnaissance on a range of IP addresses and output the results
# in several potential formats.
#
# It uses nmap for the underlying scanning duties so it's required that nmap will be installed.
# to do the ICMP scanning required nmap needs to run as root (on linux) so either the -s (sudo) option needs to be passed
# which produces some annoying prompts for passwords, or you could run this script as root :)
#
# Input can either be on the command line or as a series of ranges in a file.  NB at the moment RTF reporting doesn't work
# with ranges supplied in a file.
#
#
# == Pre-Requisites
#
#
# == ToDo
#
# * Get RTF report working with the file option
# *
# *
#
# == Author
# Author::  Rory McCune
# Copyright:: Copyright (c) 2013 Rory Mccune
# License:: GPLv3
#
# == Options
#   -h, --help          	Displays help message
#   -v, --version       	Display the version, then exit
#   -i, --input           Range of IP addresses to Scan
#   -f, --file            File containing ranges to scan
#   -s, --sudo            Use sudo to run nmap scans
#   --reportPrefix        Prefix for report files (Default is icmp_recon)
#   --csvReport           Create a CSV report of the results
#   --hmtlReport          Create an HTML report of the results
#   --rtfReport           Create an RTF report of the results
#
#
# == Usage
#
#
#
#
#

class IcmpRecon

  VERSION = '0.0.1'

  def initialize(arguments)
    require 'optparse'
    require 'logger'
    require 'ostruct'


    begin
      require 'nmap/parser'
      require 'ipaddress'
      require 'logger'
    rescue LoadError
      puts "icmp_recon requires two gems to run"
      puts "install nmap-parser and ipaddress and try again"
      exit
    end

    begin
      require 'nokogiri'
    rescue LoadError
      puts "Couldn't load nokogiri"
      puts "try gem install nokogiri"
      exit
    end

    @options = OpenStruct.new
    @options.input_file = ''
    @options.input_ranges = Array.new
    @options.report_file_base = 'icmp_recon'
    @options.nmap_command = 'nmap'
    @options.csv_report = false
    @options.html_report = false
    @options.rtf_report = false
    @options.bypass_root_check = false

    opts = OptionParser.new do |opts|
      opts.banner = "ICMP Reconnaissance Tool #{VERSION}"

      opts.on("-f", "--file [FILE]", "Input File with IP Address Range List") do |file|
        @options.input_file = file
      end

      opts.on("-i", "--input [INPUT]", "Input Address range to scan") do |range|
        @options.input_ranges << range
      end

      opts.on("-s", "--sudo", "Run nmap commands using sudo") do |sudo|
        @options.nmap_command = 'sudo nmap'
        @options.bypass_root_check = true
      end

      opts.on("--csvReport", "Create a CSV report") do |csvrep|
        @options.csv_report = true
      end

      opts.on("--htmlReport", "Create an HTML report") do |htmlrep|
        @options.html_report = true
      end

      opts.on("--rtfReport", "Create an RTF report") do |rtfrep|
        @options.rtf_report = true
      end

      opts.on("--reportPrefix [REPREF]", "Prefix for report files") do |reppref|
        @options.report_file_base = reppref
      end

      opts.on("-b", "Bypass root check") do |bypass|
        @options.bypass_root_check = true
      end

      opts.on("-h", "--help", "-?", "--?", "Get Help") do |help|
        puts opts
        exit
      end

      opts.on("-v", "--version", "Get Version") do |ver|
        puts "ICMP Reconnaissance Tool #{VERSION}"
        exit
      end
    end

    opts.parse!(arguments)

    unless @options.input_file.length > 0 || @options.input_ranges.length > 0
      puts "You need to either specify a range or an input file"
      puts opts
      exit
    end


    @log = Logger.new('icmp-recon-analyzer-log')
    @log.level = Logger::DEBUG

    unless Process.uid == 0 || @options.bypass_root_check
      @log.debug('errored on root check')
      puts "You need root permissions to run this properly"
      puts "Either run this script as root or use the sudo option (-s)"
      puts "or if your sure it's ok, use the -b option to bypass this check"
      exit
    end

    unless @options.rtf_report || @options.csv_report || @options.html_report
      @log.debug('errored on reporting check')
      puts "No reporting specified"
      puts " you need to use one or more of --csvReport, --rtfReport or --htmlReport"
      exit
    end

    @ip_address_ranges = Array.new

    if @options.input_file.length > 0
      begin
        @input_file = File.open(@options.input_file,'r')
      rescue Exception => e
        puts "Couldn't open the input file provided, check permissions/spelling?"
        puts e
        exit
      end
      @ip_address_ranges = File.open(@options.input_file,'r+').readlines
      @ip_address_ranges.each {|line| line.chomp!}
      #Getting rid of anything that's obviously not an IP address, really it should be 7 I think (4 digits and 3 .'s)
      @ip_address_ranges.delete_if {|ip| ip.length < 4}
      @log.debug("there are #{@ip_address_ranges.length} ranges to scan")

    end

    if @options.input_ranges.length > 0
      @ip_address_ranges = @options.input_ranges
    end



    @echo_hosts = Array.new
    @timestamp_hosts = Array.new
    @address_mask_hosts = Array.new

  end

  def run
    icmp_scan
    csv_report if @options.csv_report
    html_report if @options.html_report
    rtf_report if @options.rtf_report
  end

  def icmp_scan
    @ip_address_ranges.each do |range|
      echo_parser = Nmap::Parser.parsescan(@options.nmap_command, "-sP -PE #{range}")
      echo_parser.hosts("up") do |host|
        @echo_hosts << host.addr
      end

      timestamp_parser = Nmap::Parser.parsescan(@options.nmap_command, "-sP -PP #{range}")

      timestamp_parser.hosts("up") do |host|
        @timestamp_hosts << host.addr
      end

      address_mask_parser = Nmap::Parser.parsescan(@options.nmap_command, "-sP -PM #{range}")

      address_mask_parser.hosts("up") do |host|
        @address_mask_hosts << host.addr
      end
    end
  end

  def csv_report
    report = File.new(@options.report_file_base + '.csv','w+')
    report.puts "ICMP Reconnaissance Report"
    report.puts "-------------------------"
    report.puts "Address, Echo Response?, Timestamp Response?, Netmask Response?"
    @ip_address_ranges.each do |raw_range|
      next unless raw_range
      begin
        range = IPAddress.parse(raw_range)
      rescue ArgumentError => e
        @log.debug('had a problem trying to parse' + raw_range)
        @log.debug('the problem was ' + e)
        puts 'not so good al'
        puts e
        next
      end
      range.each do |address|
        address = address.to_s
        report.print address + ","
        @echo_hosts.include?(address) ? report.print("y,") : report.print("n,")
        @timestamp_hosts.include?(address) ? report.print("y,") : report.print("n,")
        @address_mask_hosts.include?(address) ? report.puts("y") : report.puts("n")
      end
    end
  end

  def html_report
    @builder = Nokogiri::HTML::Builder.new do |doc|
      doc.html {
        doc.head {
          doc.title "ICMP Recon Report"
          doc.style {
            doc.text "table, th, td {border: 1px solid black;}"
            doc.text "td {text-align:center;}"


          }
        }
        doc.body {
          doc.h1 "ICMP Reconnaissance Report"
          doc.table {
            doc.tr {
              doc.th "IP Address"
              doc.th "ICMP Echo Response?"
              doc.th "ICMP Timestamp Response?"
              doc.th "ICMP Netmask Response?"
            }

            @ip_address_ranges.each do |raw_range|
              range = IPAddress.parse(raw_range)
              range.each do |address|
                address = address.to_s
                doc.tr{
                  doc.td{
                    doc.b address
                  }

                  @echo_hosts.include?(address) ? doc.td("y", :bgcolor => "CC0033"):doc.td("n", :bgcolor => "33CC33")

                  @timestamp_hosts.include?(address) ? doc.td("y", :bgcolor => "CC0033"):doc.td("n", :bgcolor => "33CC33")

                  @address_mask_hosts.include?(address) ? doc.td("y", :bgcolor => "CC0033"):doc.td("n", :bgcolor => "33CC33")


                }

              end
            end
          }
        }
      }
    end
    @report_file = File.new(@options.report_file_base + '.html','w+')
    @report_file.puts @builder.to_html
  end

  def rtf_report
    require 'rtf'
    document = RTF::Document.new(RTF::Font.new(RTF::Font::ROMAN, 'Arial'))
    @ip_address_ranges.each do |raw_range|
      range = IPAddress.parse(raw_range)
      table = document.table(range.size + 1,4,2000,2000,2000,2000)
      table[0][0] << 'IP Address'
      table[0][1] << 'ICMP Echo Response?'
      table[0][2] << 'ICMP Timestamp Response?'
      table[0][3] << 'ICMP Netmask Response?'
      row = 1
      range.each do |address|
        address = address.to_s
        table[row][0] << address
        @echo_hosts.include?(address) ? table[row][1] << 'Y': table[row][1] << 'N'
        @timestamp_hosts.include?(address) ? table[row][2] << 'Y': table[row][2] << 'N'
        @address_mask_hosts.include?(address) ? table[row][3] << 'Y': table[row][3] << 'N'
        row = row + 1
      end

    end
    @report_file = File.open(@options.report_file_base + '.rtf','w+') do |file|
      file.write(document.to_rtf)
    end


  end


end


if __FILE__ == $0
  recon = IcmpRecon.new(ARGV)
  recon.run
end
