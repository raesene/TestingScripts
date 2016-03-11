#!/usr/bin/env ruby
  # !!NB!!
  # This tool isn't ready for use, so don't :)
  #
  #
  #
  # == Synopsis
  # This script is designed to co-ordinate parsing of sslyze xml files and production of a concise set findings.
  #
  # The scanner relies on the nokogiri gem for xml parsing
  #
  # There are 2 modes of operation.
  #
  # Directory mode just takes a parameter of the directory containing the xml files and goes and parses any files found there
  #
  # File mode takes a parameter of a single file and parses that
  #
  #TODO:
  # - File bug report where root CAs are getting tagged as intermediate stopping us checking SHA-1 (e.g. geotrust CA)
  #
  # == Author
  # Author::  Rory McCune
  # Copyright:: Copyright (c) 2016 Rory Mccune
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
  #   -d <dir>, --directory <dir>  Only needed in directory mode name of the directory to scan
  #   -f <file>, --file <file>     Only needed in file mode, name of the file to parse
  #   -r <file>, --report <file>        Name of file for reporting
  #   -l <file>             Log debug messages to a file.
  #   --reportDirectory <dir>   Place the report in a different directory
  #
  # == Usage
  #
  #   Directory Mode
  #   sslyzeautoanalyzer.rb -m directory -d <directoryname> -r <reportfile>
  #   File Mode
  #   sslyzeautoanalyzer.rb -m file -f <filename> -r <reportfile>



class SslyzeAutoAnalyzer
  # Version of the code
  VERSION='0.0.1'
  #attr_accessor :parsed_hosts, :low_vulns, :medium_vulns, :high_vulns, :info_vulns, :exploitable_vulns

  # Parse the arguments passed ans setup the options for scanning
  def initialize(commandlineopts)
    
    #Requiring things we need.  Most of these are in stdlib, but nokogiri ain't
    begin
      require 'rubygems'
      require 'logger'      
      require 'nokogiri'

    rescue LoadError => e
      puts "Couldn't load one of the required gems (likely to be nokogiri)"
      puts "The error message may be useful"
      puts e.to_s
      exit
    end
    
    @options = commandlineopts
    
    @base_dir = @options.report_directory
    @scan_dir = @options.scan_directory
    if !File.exists?(@base_dir)
      Dir.mkdirs(@base_dir)
    end

    if @options.logger
      @log = Logger.new(@base_dir + '/' + @options.logger)
    else
      @log = Logger.new(STDOUT)
    end
    #Change the line below to Logger::DEBUG to get debugging messages during the program run
    @log.level = Logger::DEBUG
    @log.debug("Log created at " + Time.now.to_s)
    @log.debug("Scan type is : #{@options.scan_type}")
    @log.debug("Directory being scanned is : #{@options.scan_directory}") if @options.scan_type == :directory
    @log.debug("File being scanned is : #{@options.scan_file}") if @options.scan_type == :file
    
  end

  # Sets up the process for scanning the xml files and calls the individual methods depending on the scan type
  def run
    case @options.scan_type
    when :directory
      scan_dirs
      parse_files
      excel_report
    when :file
      @scan_files = Array.new
      @scan_files << @options.scan_file
      parse_files
      excel_report
    end
  end

  #Adds all the files in the directory being scanned to the scan_files array.
  #We sort out valid files later.
  def scan_dirs
    @scan_files = Array.new
    Dir.entries(@scan_dir).each do |scan|
      next if scan =~ /^\.{1,2}$/
      @scan_files << @scan_dir + '/' + scan
    end
  end

  #Set-up the Hashes to store the results of the parse commands and pass to the correct parse command depending on version
  def parse_files
    #Hash to store our results
    @host_results = Hash.new
    @log.debug("Files to be looked at : #{@scan_files.join(', ')}")
    @scan_files.each do |file|      
      file_content = File.open(file,'r').read
      doc = Nokogiri::XML(file_content)
      if doc.root['title'] == "SSLyze Scan Results"
        @log.debug("Got a sslyze file called #{file}, processing")
        parse_file(doc)
      else
        @log.warn("Invalid format for file : #{file}, skipping")
        next
      end
    end
  end

  #Parse the sslyze format file and populate the hashes for the report
  #Remember one file can contain multiple hosts
  def parse_file(doc)
    hosts = doc.xpath('//document/results/target')
    @log.debug("Got #{hosts.length} hosts to review")
    hosts.each do |host|
      address = host['host']
      #Need to account for the poss. that this already exists?
      @host_results[address] = Hash.new
      #Check for Self-Signed Certificate
      if host.xpath('certinfo_basic/certificateValidation/pathValidation')[0]['validationResult'] == "self signed certificate"
        @host_results[address]['self_signed'] = true
      end
      #Check for untrusted root
      if host.xpath('certinfo_basic/certificateValidation/pathValidation')[0]['validationResult'] == "unable to get local issuer certificate"
        @host_results[address]['untrusted_issuer'] = true
      end
      #Check for Expired Cert
      if host.xpath('certinfo_basic/certificateValidation/pathValidation')[0]['validationResult'] == "certificate has expired"
        @host_results[address]['expired_cert'] = true
      end
      #Check for hostname mismatch
      if host.xpath('certinfo_basic/certificateValidation/hostnameValidation')[0]['certificateMatchesServerHostname'] == "False"
        @host_results[address]['hostname_mismatch'] = true
      end
      #Check Public Key Size
      @host_results[address]['public_key_size'] = host.xpath('certinfo_basic/certificateChain/certificate[@position="leaf"]')[0].xpath('subjectPublicKeyInfo/publicKeySize').inner_text


      #Check for SHA-1 Signed Certificate is fine for leafs, intermediates are trickier
      @host_results[address]['sha1_signed'] = host.xpath('certinfo_basic/certificateChain/certificate[@position="leaf"]')[0].xpath('signatureAlgorithm').inner_text
    end
  end

  def excel_report
    begin 
      require 'rubyXL'
    rescue LoadError
      puts "Excel report needs the rubyXL gem"
    end

    workbook = RubyXL::Workbook.new
    vuln_sheet = workbook.worksheets[0]
    vuln_sheet.sheet_name = "SSLyze Results"

    vuln_sheet.add_cell(1,0,"Hostname/IP Address")
    vuln_sheet.add_cell(1,1,"Self Signed Certificate?")
    vuln_sheet.add_cell(1,2,"Untrusted Issuer?")
    vuln_sheet.add_cell(1,3,"Subject Mismatch with Hostname?")
    vuln_sheet.add_cell(1,4,"Certificate without WWW?")
    vuln_sheet.add_cell(1,5,"Expired Certificate?")
    vuln_sheet.add_cell(1,6,"Certificate Expiry Imminent?")
    vuln_sheet.add_cell(1,7,"Public Key Size")
    vuln_sheet.add_cell(1,8,"Wildcard Certificate?")
    vuln_sheet.add_cell(1,9,"Certificate Revoked?")
    vuln_sheet.add_cell(1,10,"Certificate Signature Algorithm")
    row_count = 2
    @host_results.each do |host, vulns|
      vuln_sheet.add_cell(row_count,0,host)
      vuln_sheet.add_cell(row_count,1,vulns['self_signed'])
      vuln_sheet.add_cell(row_count,2,vulns['untrusted_issuer'])
      vuln_sheet.add_cell(row_count,3,vulns['hostname_mismatch'])
      vuln_sheet.add_cell(row_count,5,vulns['expired_cert'])
      vuln_sheet.add_cell(row_count,7,vulns['public_key_size'])
      vuln_sheet.add_cell(row_count,10,vulns['sha1_signed'])
      row_count = row_count + 1
    end

    workbook.write(@options.report_file + '.xlsx')
  end

end

if __FILE__ == $0
  require 'ostruct'
  require 'optparse'
  options = OpenStruct.new
  
  #Set some defaults in the options hash
  options.report_directory = Dir.pwd
  options.report_file = 'sslyze-parse-report'
  options.scan_directory = Dir.pwd
  options.scan_file = ''
  options.scan_type = :notset
  
  
  opts = OptionParser.new do |opts|
    opts.banner = "Sslyze Auto analyzer #{SslyzeAutoAnalyzer::VERSION}"
    
    opts.on("-d", "--directory [DIRECTORY]", "Directory to scan for .sslyze files") do |dir|
      options.scan_directory = dir
      options.scan_type = :directory
    end 
    
    opts.on("-f", "--file [FILE]", "File to analyze including path") do |file|
      options.scan_file = file
      options.scan_type = :file
    end
    
    opts.on("-r", "--report [REPORT]", "Base Report Name") do |rep|
      options.report_file = rep
    end
    
    opts.on("--reportDirectory [REPORTDIRECTORY]", "Directory to output reports to") do |repdir|
      options.report_directory = repdir
    end

    opts.on("-l", "--log [LOGGER]", "Log debugging messages to a file") do |logger|
      options.logger = logger
    end
    
    opts.on("-h", "--help", "-?", "--?", "Get Help") do |help|
      puts opts
      exit
    end
    
    opts.on("-v", "--version", "Get Version") do |ver|
      puts "sslyze Analyzer Version #{SslyzeAutoAnalyzer::VERSION}"
      exit
    end
    
  end
  
  opts.parse!(ARGV)
    
    #Check for missing required options
    unless (options.scan_type == :file || options.scan_type == :directory)
      puts "didn't get any arguments or missing scan type"
      puts opts
      exit
    end

  analysis = SslyzeAutoAnalyzer.new(options)
  analysis.run
end

