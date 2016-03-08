#!/usr/bin/env ruby
  # == Synopsis  
  # This script is designed to co-ordinate parsing of nmap xml files and production of a concise report, just listing ports that are open on hosts, with whatever supplementary information nmap provide about them (service, product name, reason nmap thinks the port is open).  
  # 
  # The scanner relies on the nmap/parser library (http://rubyforge.org/projects/rubynmap)
  # either being in the same directory (parser.rb) or installed as a gem 
  #
  # The HTML reports option relies on the kramdown gem being installed.
  #
  # There are 2 modes of operation.  
  #
  # Directory mode just takes a parameter of the directory containing the xml files and goes and parses any files found there
  # 
  # File mode takes a parameter of a single file and parses that
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
  #   -m, --mode       		One of two modes to run the script in 'directory','file'
  #   -i, ignoreChatty      Bypasses hosts with more than 900 open TCP ports.  Reason for this switches existance is that some hosts (e.g. Proxy servers)
  #                         will show all ports as open, which makes quite a mess of the output.
  #   -d <dir>, --directory <dir>  Only needed in directory mode name of the directory to scan
  #   -f <file>, --file <file>     Only needed in file mode, name of the file to parse
  #   -r <file>, --report <file>        Name of file for reporting
  #   --html-report         Generates an HTML report in addition to the txt one (uses the kramdown gem)
  #   --reportDirectory <dir>   Place the report in a different directory
  #
  # == Usage 
  #
  #   Directory Mode
  #   nmapautoanalyzer.rb -d <directoryname> -r <reportfile>
  #   File Mode
  #   nmapautoanalyzer.rb -f <filename> -r <reportfile>


class NmapautoAnalyzer

  VERSION = '0.2.4'
  attr_accessor :valid_entries, :scan_files, :parsed_hosts, :scanned_files, :options

  def initialize(commandlineopts)

    @options = commandlineopts
    
    require 'rubygems'
    require 'logger'
      
    #this is needed to tack on to file checks in 1.9.2 as the current directory is no longer on the lib path
    script_dir = File.expand_path( File.dirname(__FILE__) )

    begin

      if File.exists?(script_dir + '/parser.rb')
        require script_dir + '/parser'
      else
        require 'nmap/parser'
      end
    rescue LoadError
      puts "Couldn't find or load the nmap parser library.  'gem install nmap-parser' should work"
      exit
    end
    
    @base_dir = @options.report_directory
    @scan_dir = @options.scan_directory
    if !File.exists?(@base_dir)
      Dir.mkdirs(@base_dir)
    end

    @log = Logger.new(@base_dir + '/nmap-analyzer-log')
    @log.level = Logger::DEBUG
    @log.debug("Log created at " + Time.now.to_s)
    @log.debug("Scan type is : #{@options.scan_type}")
    @log.debug("Directory being scanned is : #{@options.scan_directory}") if @options.scan_type == :directory 
    @log.debug("File being scanned is : #{@options.scan_file}") if @options.scan_type == :file 
    
    @report_file_name = @base_dir + '/' + @options.report_file
    @report_file = File.new(@report_file_name + '.txt','w+')
    @html_report_file = File.new(@report_file_name + '.html','w+')
    @excel_report_file_name = @report_file_name + '.xlsx'
    @log.info("New report file created #{@report_file_name}")
  end


  # Sets up the process for scanning the xml files and calls the individual methods depending on the scan type
  def run
    
    case @options.scan_type
    #Directory Mode
    when :directory
      @valid_entries = Array.new
      @valid_entries << ''
      scan_dirs
      parse_files
      report
      excel_report
      if @options.html_report
        html_report
      end
    #File Mode     
    when :file
      @scan_files = Array.new
      @scan_files << @options.scan_file
      parse_files
      report
      excel_report
      if @options.html_report
        html_report
      end
    end
  end

  #Adds all the xml files in the directory being scanned to the scan_files array
  def scan_dirs
    @scan_files = Array.new
    @valid_entries.each do |dir|
      Dir.entries(@scan_dir + dir).each do |scan|
        if scan =~ /xml$/
          @scan_files << @scan_dir + dir + '/' + scan
        end
      end
    end
  end

  #Parses the nmap xml files and populates the arrays needed by the report
  def parse_files
    #Hash to put the information for each host into
    @parsed_hosts = Hash.new
    @scanned_files = Hash.new
    @closed_ports = Array.new
    #Ports is an array to contain a list of the unique ports encountered for later feeding to Nessus
    @ports = Array.new
    #port_hash is a hash to contain a list of ports and what hosts have them open
    @port_hash = Hash.new
    @traceroute_hash = Hash.new
    @os_hash = Hash.new
    @web_headers_hash = Hash.new
    @scan_files.each do |file|
      begin
        parser = Nmap::Parser.parsefile(file)
      rescue IOError => e
        @log.warn("Warning couldn't parse file #{file}")
        puts "Couldn't parse file #{file}, check to make sure it wasn't critical!!"
        next
      rescue REXML::ParseException
        @log.warn("Warning, couldn't parse file #{file} due to an XML parse error")
        puts "Warning, couldn't parse file #{file} due to an XML parse error"
        next
      end
      @scanned_files[file] = Hash.new unless @scanned_files[file]
      @scanned_files[file][:scan_args] = parser.session.scan_args if parser.session.scan_args
      @scanned_files[file][:scan_time] = parser.session.scan_time if parser.session.scan_time
      parser.hosts("up") do |host|
        #TODO: we should add UDP here too, but watch for no-response otherwise we'll get false positive centraled.
        next if host.tcp_ports("open").length > 100
        @parsed_hosts[host.addr] = Hash.new unless @parsed_hosts[host.addr]
        host.extraports.each do |portstate|
          if portstate.state == "closed" && portstate.count > 1
            @closed_ports << host.addr
          end
        end

        #Add Traceroute information and grab the last hop before the host
        #It's either the last hop or the one before it
        #So it looks to me that nmaps traceroute isn't quite right for this
        #produces different results to traceroute...
        #if host.traceroute
        #  @log.debug("host address is " + host.addr +  "Last traceroute is" + host.traceroute.hops[-1].addr)
        #  if host.traceroute.hops[-1].addr != host.addr || host.traceroute.hops.length == 1
        #    last_hop = host.traceroute.hops[-1].addr.to_s
        #  else
        #    last_hop = host.traceroute.hops[-2].addr.to_s
        #  end
        #  @traceroute_hash[host.addr] = last_hop
        #end

        #Add OS guess information
        if host.os.name
          @os_hash[host.addr] = host.os.name + ', ' + host.os.name_accuracy.to_s
        end

        host.tcp_ports("open") do |port|
          #Add the port to the ports array
          @ports << port.num.to_s
          #Add the port to the port hash
          if @port_hash[port.num.to_s + '-TCP']
            @port_hash[port.num.to_s + '-TCP'] << host.addr
          else
            @port_hash[port.num.to_s + '-TCP'] = Array.new
            @port_hash[port.num.to_s + '-TCP'] << host.addr
          end
          @parsed_hosts[host.addr][port.num.to_s + ' - TCP'] = Hash.new 
          @parsed_hosts[host.addr][port.num.to_s + ' - TCP'][:service] = port.service.name if port.service.name
          @parsed_hosts[host.addr][port.num.to_s + ' - TCP'][:reason] = port.reason if port.reason
          @parsed_hosts[host.addr][port.num.to_s + ' - TCP'][:product] = port.service.product if port.service.product
          if host.tcp_script(port.num.to_s, 'http-methods')
            @web_headers_hash[host.addr + ':' + port.num.to_s] = host.tcp_script(port.num.to_s, 'http-methods').output.split("\n")[0]
          end
        end
  
        host.udp_ports("open") do |port|
          next if port.reason == "no-response"
          #Add the port to the ports array
          @ports << port.num.to_s
          #Add the port to the port hash
          if @port_hash[port.num.to_s + '-UDP']
            @port_hash[port.num.to_s + '-UDP'] << host.addr
          else
            @port_hash[port.num.to_s + '-UDP'] = Array.new
            @port_hash[port.num.to_s + '-UDP'] << host.addr
          end
          @parsed_hosts[host.addr][port.num.to_s + ' - UDP'] = Hash.new
          @parsed_hosts[host.addr][port.num.to_s + ' - UDP'][:service] = port.service.name if port.service.name
          @parsed_hosts[host.addr][port.num.to_s + ' - UDP'][:reason] = port.reason if port.reason
          @parsed_hosts[host.addr][port.num.to_s + ' - UDP'][:product] = port.service.product if port.service.product  	
        end  
      end
    end
  #Once we're done with the files clean up the ports array
  @ports.uniq!
  end

  #Generates a kramdown compatible report that we can use to generate an HTML report
  def report
    @report_file.puts "NMAP AUTO analysis"
    @report_file.puts "===================\n\n"
    @report_file.puts "Unique ports open"
    @report_file.puts "-------------------\n\n"
    @report_file.puts @ports.join(', ')
    @report_file.puts "\n\n"
    @report_file.puts "NMAP Host Analysis"
    @report_file.puts "-------------------"
    @report_file.puts ""
    @report_file.puts "Active Host List"
    @report_file.puts "---------"
    active_ipaddresses = Array.new
    inactive_ipaddresses = Array.new
    @parsed_hosts.each do |entry|
      host, ports = entry[0], entry[1]
      if ports.length > 0
        active_ipaddresses << host
      else
        inactive_ipaddresses << host
      end
    end
	  @report_file.puts active_ipaddresses.uniq.join(', ')
    @report_file.puts ""
    @report_file.puts ""
    @report_file.puts "Inactive Host List"
    @report_file.puts "---------"
    @report_file.puts inactive_ipaddresses.uniq.join(', ')
    @report_file.puts ""
    @report_file.puts ""
    if @traceroute_hash.length > 0
      @report_file.puts "Traceroute Information"
      @report_file.puts "---------"
      @report_file.puts "Target Address, Last Hop"
      @traceroute_hash.each do |addr, last_hop|
        @report_file.puts addr + ", " + last_hop
      end
      @report_file.puts ""
      @report_file.puts ""
    end
    if @os_hash.length > 0
      @report_file.puts "Operating System Information"
      @report_file.puts "---------"
      @report_file.puts "Target Address, OS Guess, OS Accuracy"
      @os_hash.each do |addr, os|
        @report_file.puts addr + ", " + os
      end
      @report_file.puts ""
      @report_file.puts ""
    end

    if @web_headers_hash.length > 0
      @report_file.puts "Operating System Information"
      @report_file.puts "---------"
      @report_file.puts "Target Web Server, Supported Methods"
      @web_headers_hash.each do |addr, methods|
        @report_file.puts addr + ", " + methods
      end
      @report_file.puts ""
      @report_file.puts ""
    end

    #sorted_hosts = @parsed_hosts.sort {|a,b| b[1].length <=> a[1].length}
    sorted_hosts = @parsed_hosts.sort_by {|address,find| address.split('.').map{ |digits| digits.to_i}}

    sorted_hosts.each do |entry|
      host, ports = entry[0], entry[1]
      #This omits any hosts that were deemed up but had no open ports
      #TODO: Make this an option in reporting (verbose against concise)
      next if ports.length == 0
      @report_file.puts "Host address: #{host} was detected as up by nmap"
      @report_file.puts "------------------------------------------------"
      @report_file.puts ""
      if ports.length == 0
        @report_file.puts "No Ports detected as open on this host"
      end
      ports.each do |port, data|
        
        @report_file.print "Port #{port} is open "
        @report_file.print ", Service name is #{data[:service]}" if data[:service]
        @report_file.print ", Service Product name is #{data[:product]}" if data[:product]
        @report_file.print ", Up reason is #{data[:reason]}" if data[:reason]
        @report_file.puts ""
        
      end
      @report_file.puts ""
      @report_file.puts "-------------------"
      @report_file.puts ""
    end

    @report_file.puts "\n\nReport of hosts with a given port open"
    @report_file.puts "--------------------\n\n"
    @port_hash.each do |port,hosts|
      @report_file.puts port + ' - ' + hosts.uniq.length.to_s + ' hosts have this port open'
      @report_file.puts "-----------------"
      @report_file.puts hosts.uniq.join(', ')
      @report_file.puts "\n\n"
    end

    @report_file.puts "\n\nActive Hosts with Closed Ports"
    @report_file.puts "--------------------\n\n"
    @report_file.puts @closed_ports.uniq.join(', ')
    @report_file.puts "--------------------\n\n"
    active_ipaddresses.each do |add|
      result = "n"
      result = "y" if @closed_ports.include?(add)
      @report_file.puts add + ', ' + result
    end

    #TODO: Make this an option in terms of reporting volume
    @report_file.puts "\n\nNMAP runs analysed"
    @scanned_files.each do |file, data|
      @report_file.puts "\n-------------------"
      @report_file.puts file
      @report_file.puts "Scan arguments were #{data[:scan_args]}"
      @report_file.puts "Scan Time was #{data[:scan_time]}"
    end
    @report_file.close
  end

  #Generates an HTML report with the results
  def html_report
    begin
      require 'kramdown'
    rescue LoadError
      puts "Couldn't load kramdown, try gem install kramdown"
      exit
    end
    
    
    base_report = File.open(@report_file_name + '.txt','r').read
    
    report = Kramdown::Document.new(base_report)
    
      
    @html_report_file.puts report.to_html
  end
  
  def excel_report
    begin
      require 'rubyXL'
    rescue LoadError
      puts "Couldn't load rubyXL, try gem install rubyXL"
      exit
    end
    
    workbook = RubyXL::Workbook.new
    sheet = workbook.worksheets[0]
    
    sheet.add_cell(0,0,"IP Address")
    sheet.add_cell(0,1,"TCP Ports")
    sheet.add_cell(0,2,"UDP Ports")
    curr_row = 1
    sorted_hosts = @parsed_hosts.sort_by {|address,find| address.split('.').map{ |digits| digits.to_i}}
    sorted_hosts.each do |entry|
      host, ports = entry[0], entry[1]
      next if ports.length == 0
      tcp_ports = Array.new
      udp_ports = Array.new
      ports.each do |port,data|
        portnum, protocol = port.split(' - ')
        if protocol == 'TCP'
          tcp_ports << portnum
        elsif protocol == 'UDP'
          udp_ports << portnum
        end

      end
      sheet.add_cell(curr_row,0,host)
      sheet.add_cell(curr_row,1,tcp_ports.join(', '))
      sheet.add_cell(curr_row,2,udp_ports.join(', '))
      curr_row = curr_row + 1
    end

    workbook.write(@excel_report_file_name)
  end
  
end

if __FILE__ == $0
  require 'ostruct'
  require 'optparse'
  options = OpenStruct.new

  options.report_directory = Dir.pwd
  options.report_file = 'nmap-parse-report'
  options.scan_directory = '/tmp/nmapscans/'
  options.scan_file = ''
  options.scan_type = :notset
  options.html_report = false
  options.ignore_chatty = false

  opts = OptionParser.new do |opts|
    opts.banner = "Nmap Auto Analyzer #{NmapautoAnalyzer::VERSION}"
      
    opts.on("-d", "--directory [DIRECTORY]", "Directory to scan for xml files") do |dir|
      options.scan_directory = dir
      options.scan_type = :directory
    end
    opts.on("-f", "--file [FILE]", "File to scan including path") do |file|
      options.scan_file = file
      options.scan_type = :file
    end
      
    opts.on("-r", "--report [REPORT]", "Report name") do |rep|
      options.report_file = 'nmap_' + rep
    end

    opts.on("--reportDirectory [REPORTDIRECTORY]", "Report Directory") do |rep|
      options.report_directory = rep
    end

    opts.on("--html-report", "Generate an HTML report as well as the txt one") do |html|
      options.html_report = true
    end

    opts.on("-i", "--ignoreChatty", "Ignore Chatty Hosts (over 900 open tcp ports)") do |ignore|
      options.ignore_chatty = true
    end

    opts.on("-h", "--help", "-?", "--?", "Get Help") do |help|
      puts opts
      exit
    end
      
    opts.on("-v", "--version", "get Version") do |ver|
      puts "Nmapauto Analyzer Version #{NmapautoAnalyzer::VERSION}"
      exit
    end
  end

  opts.parse!(ARGV)

  unless (options.scan_type == :file || options.scan_type == :directory)
    puts "didn't get any arguments or invalid scantype"
    puts opts
    exit
  end

  analysis = NmapautoAnalyzer.new(options)
  analysis.run
end
