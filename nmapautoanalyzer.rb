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
  #   Rory McCune
  #
  # == Options
  #   -h, --help          	Displays help message
  #   -v, --version       	Display the version, then exit
  #   -m, --mode       		One of two modes to run the script in 'directory','file'
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

  def initialize(arguments)
    
    require 'rubygems'
    require 'logger'
    require 'optparse'
    require 'ostruct'

    if arguments.length > 0
      arguments_flag = :true
    end
    
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
    
   
    @options = OpenStruct.new

    @options.report_directory = Dir.pwd
    @options.report_file = 'nmap-parse-report'
    @options.scan_directory = '/tmp/nmapscans/'
    @options.scan_file = ''
    @options.scan_type = :notset
    @options.html_report = false

    opts = OptionParser.new do |opts|
      opts.banner = "Nmap Auto Analyzer #{VERSION}"
      
      opts.on("-d", "--directory [DIRECTORY]", "Directory to scan for xml files") do |dir|
        @options.scan_directory = dir
        @options.scan_type = :directory
      end

      opts.on("-f", "--file [FILE]", "File to scan including path") do |file|
        @options.scan_file = file
        @options.scan_type = :file
      end
      
      opts.on("-r", "--report [REPORT]", "Report name") do |rep|
        @options.report_file = rep
      end

      opts.on("--reportDirectory [REPORTDIRECTORY]", "Report Directory") do |rep|
        @options.report_directory = rep
      end

      opts.on("--html-report", "Generate an HTML report as well as the txt one") do |html|
        @options.html_report = true
      end

      opts.on("-h", "--help", "-?", "--?", "Get Help") do |help|
        puts opts
        exit
      end
      
      opts.on("-v", "--version", "get Version") do |ver|
        puts "Nmapauto Analyzer Version #{VERSION}"
        exit
      end
    end

    opts.parse!(arguments)

    #Catch cases where we don't get required information
    unless arguments_flag && (@options.scan_type == :file || @options.scan_type == :directory)
      puts "didn't get any arguments or invalid scantype"
      puts opts
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
      if @options.html_report
        html_report
      end
    #File Mode     
    when :file
      @scan_files = Array.new
      @scan_files << @options.scan_file
      parse_files
      report
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
    #Ports is an array to contain a list of the unique ports encountered for later feeding to Nessus
    @ports = Array.new
    #port_hash is a hash to contain a list of ports and what hosts have them open
    @port_hash = Hash.new
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
        @parsed_hosts[host.addr] = Hash.new unless @parsed_hosts[host.addr]
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
    @report_file.puts "Host List"
    @report_file.puts "---------"
    @report_file.puts ""
    ipaddresses = Array.new
    @parsed_hosts.each_key do |host|
      ipaddresses << host
    end
	@report_file.puts ipaddresses.uniq.join(', ')
    @report_file.puts ""
    @report_file.puts ""
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
        @report_file.puts ""
      end
      @report_file.puts "-------------------"
      @report_file.puts ""
    end

    @report_file.puts "\n\nReport of hosts with a given port open"
    @report_file.puts "--------------------\n\n"
    @port_hash.each do |port,hosts|
      @report_file.puts port
      @report_file.puts "-----------------"
      @report_file.puts hosts.uniq.join(', ')
      @report_file.puts "\n\n"
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
  
  


end

if __FILE__ == $0
  analysis = NmapautoAnalyzer.new(ARGV)
  analysis.run
end
