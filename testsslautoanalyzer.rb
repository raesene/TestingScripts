#!/usr/bin/env ruby
  # == Synopsis
  # This script is designed to co-ordinate parsing of testssl.sh JSON files and production of a concise set findings.
  #
  #
  # There are 2 modes of operation.
  #
  # Directory mode just takes a parameter of the directory containing the xml files and goes and parses any files found there
  #
  # File mode takes a parameter of a single file and parses that
  #
  #TODO:
  # - The Cert Expiring Checks will return true in both cases this needs changing
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
  #   testsslautoanalyzer.rb -m directory -d <directoryname> -r <reportfile>
  #   File Mode
  #   testsslautoanalyzer.rb -m file -f <filename> -r <reportfile>



class TestSSLAutoAnalyzer
  # Version of the code
  VERSION='0.0.1'
  #attr_accessor :parsed_hosts, :low_vulns, :medium_vulns, :high_vulns, :info_vulns, :exploitable_vulns

  # Parse the arguments passed ans setup the options for scanning
  def initialize(commandlineopts)
    
    #Requiring things we need.  Most of these are in stdlib, but nokogiri ain't
    begin
      require 'rubygems'
      require 'logger'      
      require 'json'
      require 'date'
      #require 'resolv'

    rescue LoadError => e
      puts "Couldn't load one of the required gems"
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
    @log.level = Logger::WARN
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
      next if File.directory?(@scan_dir + '/' + scan)
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
      begin
        @log.debug("File name is " + file)
        doc = JSON.parse(file_content)
      rescue JSON::ParserError => e
        @log.warn("We got an error parsing #{file}")
        next
      end
      #Make sure that the file is actually XML
      begin
        @log.debug("Got a sslyze file called #{file}, processing")
        parse_file(doc)
      rescue Exception => e
        @log.warn("We got an error parsing #{file}")
        @log.warn(e)
      end
    end
  end

  #Parse the testssl.sh format file and populate the hashes for the report
  #Remember one file only ever contains one host
  def parse_file(doc)
    address = doc[0]['ip']
    @host_results[address] = Hash.new


    #testSSL JSON files are an array of elements, it's nicer for this to be able to key off a hash of the id
    results = Hash.new
    doc.each {|element| results[element['id']] = element}

    #Get a list of the valid hostnames for the Certificat
    sans = results['san']['finding']
    sans.slice!('subjectAltName (SAN) : ')
    host_names = Array.new
    host_names << sans.split(' ')
    host_names << address.split('/')[0]


    #Self Signed Certificate Checks
    if results['trust']['finding'].downcase =~ /self signed/
      @host_results[address]['self_signed'] = true
    else
      @host_results[address]['self_signed'] = false
    end

    #Untrusted Issuer
    if results['trust']['finding'].downcase =~ /chain incomplete/
      @host_results[address]['untrusted_issuer'] = true
    else
      @host_results[address]['untrusted_issuer'] = false
    end

    #Hostname Mismatch
    if results['cn']['finding'].downcase =~ /(?=.{1,255}$)[0-9A-Za-z](?:(?:[0-9A-Za-z]|-){0,61}[0-9A-Za-z])?(?:\.[0-9A-Za-z](?:(?:[0-9A-Za-z]|-){0,61}[0-9A-Za-z])?)*\.?/
      hostname = results['cn']['finding'].slice(/(?=.{1,255}$)[0-9A-Za-z](?:(?:[0-9A-Za-z]|-){0,61}[0-9A-Za-z])?(?:\.[0-9A-Za-z](?:(?:[0-9A-Za-z]|-){0,61}[0-9A-Za-z])?)*\.?/)
      unless host_names.eql?(hostname)
        @host_results[address]['hostname_mismatch'] = true
      else
        @host_results[address]['hostname_mismatch'] = false
      end
    end

    #Cert No WWW
    if results['trust']['finding'].downcase =~ //
      @host_results[address]['cert_no_www'] = true
    else
      @host_results[address]['cert_no_www'] = false
    end

    #Expiration
    if results['expiration']['severity'] != "OK"
      @host_results[address]['expired_cert'] = true
    else
      @host_results[address]['expired_cert'] = false
    end

    #About to expire    
    if results['expiration']['severity'] != "OK"
      @host_results[address]['cert_expiring_soon'] = true
    else
      @host_results[address]['cert_expiring_soon'] = false
    end

    #Wildcard Cert
    if results['cn']['finding'].downcase =~ /wildcard/
      @host_results[address]['wildcard_cert'] = true
    else
      @host_results[address]['wildcard_cert'] = false
    end


    #Public Key Size
    if results['key_size']['severity'] == "OK" || results['key_size']['severity'] == "WARN"
      @host_results[address]['public_key_size'] = false
    else
      @host_results[address]['public_key_size'] = true
    end

    #SHA-1 Signed
    if results['algorithm']['finding'].downcase =~ /sha1/
      @host_results[address]['sha1_signed'] = true
    else
      @host_results[address]['sha1_signed'] = false
    end

    #Anonymous Ciphers
    if results['std_aNULL']['severity'] == "OK" && 
       results['std_ADH']['severity'] == "OK"
      @host_results[address]['anonymous_ciphers'] = false
    else
      @host_results[address]['anonymous_ciphers'] = true
    end

    #Weak Ciphers
    if results['std_LOW']['severity'] == "OK" &&
     results['std_DES']['severity'] == "OK" && 
     results['std_MEDIUM']['severity'] == "OK" && 
     results['std_3DES']['severity'] == "OK"
       @host_results[address]['weak_ciphers'] = false
    else
      @host_results[address]['weak_ciphers'] = true
    end

    #RC4 Ciphers
    if results['rc4']['severity'] == "OK"
      @host_results[address]['rc4_ciphers'] = false
    else
      @host_results[address]['rc4_ciphers'] = true
    end

    #SSLv2
    if results['sslv2']['severity'] == "OK"
      @host_results[address]['sslv2_supported'] = false
    else
      @host_results[address]['sslv2_supported'] = true
    end

    #SSLv3
    if results['sslv3']['severity'] == "OK"
      @host_results[address]['sslv3_supported'] = false
    else
      @host_results[address]['sslv3_supported'] = true
    end

    #TLSv1 (there should be a better way to check this)
    if results['tls1']['severity'] == "OK" &&
      (results['tls1_1']['severity'] != "INFO" &&
      results['tls1_2']['severity'] !="INFO")
      @host_results[address]['no_tls_v1_1_2'] = true
    else
      @host_results[address]['no_tls_v1_1_2'] = false
    end

    #Client Renegotation
    if results['sec_client_renego']['severity'] == "OK"
      @host_results[address]['client_renegotiation'] = false
    else
      @host_results[address]['client_renegotiation'] = true
    end

    if results['secure_renego']['severity'] == "OK"
      @host_results[address]['insecure_renegotiation'] = false
    else
      @host_results[address]['insecure_renegotiation'] = true
    end

    if results['breach']['severity'] == "OK"
      @host_results[address]['compression'] = false
    else
      @host_results[address]['compression'] = true
    end

    if results['ccs']['severity'] == "OK"
      @host_results[address]['ccs_vuln'] = false
    else
      @host_results[address]['ccs_vuln'] = true
    end

    if results['beast']['severity'] == "OK"
      @host_results[address]['beast'] = false
    else
      @host_results[address]['beast'] = false
    end

  end

  def excel_report
    begin 
      require 'rubyXL'
    rescue LoadError
      puts "Excel report needs the rubyXL gem"
      exit
    end

    workbook = RubyXL::Workbook.new
    cert_sheet = workbook.worksheets[0]
    cert_sheet.sheet_name = "Certificate Issues"
    cert_sheet.add_cell(0,0,"IP Address")
    cert_sheet.add_cell(0,1,"Hostname")
    cert_sheet.add_cell(0,2,"Self Signed Certificate?")
    cert_sheet.add_cell(0,3,"Untrusted Issuer?")
    cert_sheet.add_cell(0,4,"Subject Mismatch with Hostname?")
    cert_sheet.add_cell(0,5,"Certificate without WWW?")
    cert_sheet.add_cell(0,6,"Expired Certificate?")
    cert_sheet.add_cell(0,7,"Certificate Expiry Imminent?")
    cert_sheet.add_cell(0,8,"Wildcard Certificate?")
    cert_sheet.add_cell(0,9,"Small Public Key")
    #cert_sheet.add_cell(0,9,"Certificate Revoked?")
    cert_sheet.add_cell(0,10,"Certificate Signature SHA-1")

    cipher_sheet = workbook.add_worksheet('Cipher Issues')
    cipher_sheet.add_cell(0,0,"IP Address")
    cipher_sheet.add_cell(0,1,"Hostname")
    cipher_sheet.add_cell(0,2,"Anonymous Ciphers Supported")
    cipher_sheet.add_cell(0,3,"Weak Ciphers Supported")
    cipher_sheet.add_cell(0,4,"RC4 Ciphers Supported")
    #cipher_sheet.add_cell(0,4,"Weak Diffie-hellman")
    #cipher_sheet.add_cell(0,5,"Weak RSA Key Exchange")
    #cipher_sheet.add_cell(0,6,"Forward Secrecy Unsupported")

    protocol_sheet = workbook.add_worksheet('Protocol Issues')
    protocol_sheet.add_cell(0,0,"IP Address")
    protocol_sheet.add_cell(0,1,"Hostname")
    protocol_sheet.add_cell(0,2,"SSLv2 Supported")
    protocol_sheet.add_cell(0,3,"SSLv3 Supported")
    #protocol_sheet.add_cell(0,3,"Poodle over TLS")
    protocol_sheet.add_cell(0,4,"No support for TLS above 1.0")
    protocol_sheet.add_cell(0,5,"Client-Initiated Renogotiation DoS")
    protocol_sheet.add_cell(0,6,"Insecure Renogotiation")
    protocol_sheet.add_cell(0,7,"Compression Supported")
    protocol_sheet.add_cell(0,8,"OpenSSL ChangeCipherSpec (CCS) Vulnerability")
    protocol_sheet.add_cell(0,9,"BEAST")

    row_count = 1
    @host_results.each do |host, vulns|
      host_name = host.split(':')[0]
      cert_sheet.add_cell(row_count,0,host.split('/')[1])
      cert_sheet.add_cell(row_count,1,host.split('/')[0])
      cert_sheet.add_cell(row_count,2,vulns['self_signed'])
      cert_sheet.add_cell(row_count,3,vulns['untrusted_issuer'])
      cert_sheet.add_cell(row_count,4,vulns['hostname_mismatch'])
      cert_sheet.add_cell(row_count,5,vulns['cert_no_www'])
      cert_sheet.add_cell(row_count,6,vulns['expired_cert'])
      cert_sheet.add_cell(row_count,7,vulns['cert_expiring_soon'])
      cert_sheet.add_cell(row_count,8,vulns['wildcard_cert'])
      cert_sheet.add_cell(row_count,9,vulns['public_key_size'])
      #cert_sheet.add_cell(row_count,9,"Not Tested")
      cert_sheet.add_cell(row_count,10,vulns['sha1_signed'])
      #Apply Colours
      col = 2
      #number of cols to colour in
      7.times do |i|
        if cert_sheet.sheet_data[row_count][col + i].value == true
          cert_sheet.sheet_data[row_count][col + i].change_fill('d4004b')
        else
          cert_sheet.sheet_data[row_count][col + i].change_fill('27ae60')
        end
      end

      cipher_sheet.add_cell(row_count,0,host.split('/')[1])
      cipher_sheet.add_cell(row_count,1,host.split('/')[0])
      cipher_sheet.add_cell(row_count,2,vulns['anonymous_ciphers'])
      cipher_sheet.add_cell(row_count,3,vulns['weak_ciphers'])
      cipher_sheet.add_cell(row_count,4,vulns['rc4_ciphers'])
      #cipher_sheet.add_cell(row_count,4,"Not Tested")
      #cipher_sheet.add_cell(row_count,5,"Not Tested")
      #cipher_sheet.add_cell(row_count,6,"Not Tested")

      protocol_sheet.add_cell(row_count,0,host.split('/')[1])
      protocol_sheet.add_cell(row_count,1,host.split('/')[0])
      protocol_sheet.add_cell(row_count,2,vulns['sslv2_supported'])
      protocol_sheet.add_cell(row_count,3,vulns['sslv3_supported'])
      #POODLE over TLS , probably not worth specifically sorting this unless sslyze does
      #protocol_sheet.add_cell(row_count,3,"Not Tested")
      protocol_sheet.add_cell(row_count,4,vulns['no_tls_v1_1_2'])
      protocol_sheet.add_cell(row_count,5,vulns['client_renegotiation'])
      protocol_sheet.add_cell(row_count,6,vulns['insecure_renegotiation'])
      protocol_sheet.add_cell(row_count,7,vulns['compression'])
      protocol_sheet.add_cell(row_count,8,vulns['ccs_vuln'])
      protocol_sheet.add_cell(row_count,9,vulns['beast'])
      #Add the colours
      7.times do |i|
        if protocol_sheet.sheet_data[row_count][col + i].value == true
          protocol_sheet.sheet_data[row_count][col + i].change_fill('d4004b')
        else
          protocol_sheet.sheet_data[row_count][col + i].change_fill('27ae60')
        end
      end


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
  options.report_file = 'testssl-parse-report'
  options.scan_directory = Dir.pwd
  options.scan_file = ''
  options.scan_type = :notset
  
  
  opts = OptionParser.new do |opts|
    opts.banner = "TestSSL Auto analyzer #{TestSSLAutoAnalyzer::VERSION}"
    
    opts.on("-d", "--directory [DIRECTORY]", "Directory to scan for TestSSL.sh json files") do |dir|
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
      puts "TestSSL.sh Analyzer Version #{TestSSLAutoAnalyzer::VERSION}"
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

  analysis = TestSSLAutoAnalyzer.new(options)
  analysis.run
end

