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
  # - Figure out missing checks :- TLS POODLE
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
      begin
        doc.root['title'] == "SSLyze Scan Results"
        @log.debug("Got a sslyze file called #{file}, processing")
        parse_file(doc)
      rescue Exception => e
        @log.warn("Invalid format for file : #{file}, skipping")
        @log.warn(e)
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
      ##Certificate Issues
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

      if host.xpath('certinfo_basic/certificateChain/certificate[@position="leaf"]')[0].xpath('subject/commonName').inner_text =~ /\*/
        @host_results[address]['wildcard_cert'] = true
      end
      #Check for SHA-1 Signed Certificate is fine for leafs, intermediates are trickier
      @host_results[address]['sha1_signed'] = host.xpath('certinfo_basic/certificateChain/certificate[@position="leaf"]')[0].xpath('signatureAlgorithm').inner_text


      ## Protocol Issues
      @host_results[address]['sslv2_supported'] = host.xpath('sslv2')[0]['isProtocolSupported']
      @host_results[address]['sslv3_supported'] = host.xpath('sslv3')[0]['isProtocolSupported']
      
      @host_results[address]['tlsv1_1_supported'] = host.xpath('tlsv1_1')[0]['isProtocolSupported']
      @host_results[address]['tlsv1_2_supported'] = host.xpath('tlsv1_2')[0]['isProtocolSupported']
      if (host.xpath('tlsv1_1')[0]['isProtocolSupported'] == "False" && host.xpath('tlsv1_2')[0]['isProtocolSupported'] == "False")
        @host_results[address]['no_tls_v1_1_2'] = "True"
      else 
        @host_results[address]['no_tls_v1_1_2'] = "False"
      end

      @host_results[address]['client_renegotiation'] = host.xpath('reneg/sessionRenegotiation')[0]['canBeClientInitiated']
      unless host.xpath('reneg/sessionRenegotiation')[0]['isSecure'] == "True"
        @host_results[address]['insecure_renegotiation'] = "True"
      else
        @host_results[address]['insecure_renegotiation'] = "False"
      end

      @host_results[address]['ccs_vuln'] = host.xpath('openssl_ccs/openSslCcsInjection')[0]['isVulnerable']

      ##Cipher Vulns
      protocols = ['sslv2','sslv3','tlsv1','tlsv1_1','tlsv1_2']
      @host_results[address]['anonymous_ciphers'] = Array.new
      @host_results[address]['weak_ciphers'] = Array.new
      @host_results[address]['rc4_ciphers'] = Array.new
      @host_results[address]['weak_dh_ciphers'] = Array.new
      @host_results[address]['weak_key_exchange'] = Array.new
      @host_results[address]['forward_secrecy_unsupported'] = Array.new
      @host_results[address]['cbc_ciphers'] = Array.new

      protocols.each do |protocol|
        ciphers = host.xpath(protocol+'/acceptedCipherSuites/cipherSuite')
        @log.debug("got " + ciphers.length.to_s + " ciphers to do")
        ciphers.each do |cipher|
          if cipher['anonymous'] == true
            @host_results[address]['anonymous_ciphers'] << protocol + ', ' + cipher['name']
          end

          if cipher['keySize'].to_i < 128
            @host_results[address]['weak_ciphers'] << protocol + ', ' + cipher['name']
          end

          if cipher['name'] =~ /RC4/
            @host_results[address]['rc4_ciphers'] << protocpl + ', ' + cipher['name']
          end

          if (protocol == 'sslv3' || protocol == 'tlsv1') && cipher['name'] =~ /CBC/
            @host_results[address]['cbc_ciphers'] << protocol + ', ' + cipher['name']
          end
        end
      end
    end
  end

  def excel_report
    begin 
      require 'rubyXL'
    rescue LoadError
      puts "Excel report needs the rubyXL gem"
    end

    workbook = RubyXL::Workbook.new
    cert_sheet = workbook.worksheets[0]
    cert_sheet.sheet_name = "Certificate Issues"

    cert_sheet.add_cell(0,0,"Hostname/IP Address")
    cert_sheet.add_cell(0,1,"Self Signed Certificate?")
    cert_sheet.add_cell(0,2,"Untrusted Issuer?")
    cert_sheet.add_cell(0,3,"Subject Mismatch with Hostname?")
    cert_sheet.add_cell(0,4,"Certificate without WWW?")
    cert_sheet.add_cell(0,5,"Expired Certificate?")
    cert_sheet.add_cell(0,6,"Certificate Expiry Imminent?")
    cert_sheet.add_cell(0,7,"Public Key Size")
    cert_sheet.add_cell(0,8,"Wildcard Certificate?")
    cert_sheet.add_cell(0,9,"Certificate Revoked?")
    cert_sheet.add_cell(0,10,"Certificate Signature Algorithm")

    cipher_sheet = workbook.add_worksheet('Cipher Issues')
    cipher_sheet.add_cell(0,0,"Hostname/IP Address")
    cipher_sheet.add_cell(0,1,"Anonymous Ciphers Supported")
    cipher_sheet.add_cell(0,2,"Weak Ciphers Supported")
    cipher_sheet.add_cell(0,3,"RC4 Ciphers Supported")
    cipher_sheet.add_cell(0,4,"Weak Diffie-hellman")
    cipher_sheet.add_cell(0,5,"Weak RSA Key Exchange")
    cipher_sheet.add_cell(0,6,"Forward Secrecy Unsupported")

    protocol_sheet = workbook.add_worksheet('Protocol Issues')
    protocol_sheet.add_cell(0,0,"Hostname/IP Address")
    protocol_sheet.add_cell(0,1,"SSLv2 Supported")
    protocol_sheet.add_cell(0,2,"SSLv3 Supported")
    protocol_sheet.add_cell(0,3,"Poodle over TLS")
    protocol_sheet.add_cell(0,4,"No support for TLS above 1.0")
    protocol_sheet.add_cell(0,5,"Client-Initiated Renogotiation DoS")
    protocol_sheet.add_cell(0,6,"Insecure Renogotiation")
    protocol_sheet.add_cell(0,7,"Compression Supported")
    protocol_sheet.add_cell(0,8,"OpenSSL ChangeCipherSpec (CCS) Vulnerability")
    protocol_sheet.add_cell(0,9,"BEAST")

    row_count = 1
    @host_results.each do |host, vulns|
      cert_sheet.add_cell(row_count,0,host)
      cert_sheet.add_cell(row_count,1,vulns['self_signed'])
      cert_sheet.add_cell(row_count,2,vulns['untrusted_issuer'])
      cert_sheet.add_cell(row_count,3,vulns['hostname_mismatch'])
      cert_sheet.add_cell(row_count,4,"Not Tested")
      cert_sheet.add_cell(row_count,5,vulns['expired_cert'])
      cert_sheet.add_cell(row_count,6,"Not Tested")
      cert_sheet.add_cell(row_count,7,vulns['public_key_size'])
      cert_sheet.add_cell(row_count,8,vulns['wildcard_cert'])
      cert_sheet.add_cell(row_count,9,"Not Tested")
      cert_sheet.add_cell(row_count,10,vulns['sha1_signed'])
      cipher_sheet.add_cell(row_count,0,host)
      cipher_sheet.add_cell(row_count,1,vulns['anonymous_ciphers'].join("\n"))
      cipher_sheet.add_cell(row_count,2,vulns['weak_ciphers'].join("\n"))
      cipher_sheet.add_cell(row_count,3,vulns['rc4_ciphers'].join("\n"))
      cipher_sheet.add_cell(row_count,4,"Not Tested")
      cipher_sheet.add_cell(row_count,5,"Not Tested")
      cipher_sheet.add_cell(row_count,6,"Not Tested")
      protocol_sheet.add_cell(row_count,0,host)
      protocol_sheet.add_cell(row_count,1,vulns['sslv2_supported'])
      protocol_sheet.add_cell(row_count,2,vulns['sslv3_supported'])
      #POODLE over TLS , probably not worth specifically sorting this unless sslyze does
      protocol_sheet.add_cell(row_count,3,"Not Tested")
      protocol_sheet.add_cell(row_count,4,vulns['no_tls_v1_1_2'])
      protocol_sheet.add_cell(row_count,5,vulns['client_renegotiation'])
      protocol_sheet.add_cell(row_count,6,vulns['insecure_renegotiation'])
      protocol_sheet.add_cell(row_count,7,vulns['compression'])
      protocol_sheet.add_cell(row_count,8,vulns['ccs_vuln'])
      protocol_sheet.add_cell(row_count,9,vulns['cbc_ciphers'].join("\n"))


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

