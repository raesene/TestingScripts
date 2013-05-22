#!/usr/bin/env ruby
  # == Synopsis  
  #   
  # This class just wraps snmpwalk and iterates over a series of IP addresses and usernames
  # Designed to brute-force a snmpv3 username
  # for it to work on ubuntu you need to have the snmp programs and MIBs installed
  # sudo apt-get install snmp snmp-mibs-downloader
  # sudo download-mibs
  # == Author
  #   Rory McCune
  #
  # == Options
  #   -h, --help          	Displays help message
  #   -v, --version       	Display the version, then exit
  #   -s, --snmpwalk		The location of snmpwalk if not specified assumed to be on the path 
  #   -i, --ipaddress		IP address to scan
  #   -u, --usernames		File name with usernames to try in it, specified one per line
  #   -f, --ipaddressfile		File name with ip addresses to try in it, specified one per line
  #   -r, --report		Report file name
  #
  # == Usage 
  #  snmpv3enum.rb -i <ip_address> -u <username_file>
  #  




class Snmpv3Enum
  VERSION = '0.1'

def initialize(arguments)

  require 'optparse'
  require 'ostruct'
  require 'logger'
  
  
  if arguments.length > 0
    arguments_flag = :true
  end

  @snmp_log = Logger.new('snmpv3enum.log')
  @snmp_log.level = Logger::DEBUG

  @options = OpenStruct.new

  @options.snmpwalk = %x[which snmpwalk].chomp
  @options.ip_address = Array.new
  @options.usernames = 'usernames'
  @options.report = 'snmp-report'

  opts = OptionParser.new do |opts|
    opts.banner = 'SNMPV3 Username enumerator'

    opts.on("-i", "--ipaddress [IPADDRESS]", "IP address to scan") do |address|
      @options.ip_address << address
    end

    opts.on("-u", "--usernames USERNAMES", "File with usernames to scan") do |name|
      @options.usernames = name
    end

    opts.on("-s", "--snmpwalk [SNMPWALK]", "Location of the snmpwalk binary") do |snmp|
      @options.snmpwalk = snmp
    end

    opts.on("-f", "--ip_address_file [IPADDRESSFILE]","File with IP addresses to scan") do |ipfile|
      ip_file = File.open(ipfile,'r').readlines
      ip_file.each do |ip|
        ip.chomp!
        @options.ip_address << ip
      end 
    end

    opts.on("-r", "--report [REPORT]","Report File") do |report|
      @options.report = report
    end
  
    opts.on("-h", "--help", "-?", "--?", "Get Help") do |help|
      puts opts
      exit
    end
      
    opts.on("-v", "--version", "get Version") do |ver|
      puts "SNMPV3 User name enumerator Version #{VERSION}"
      exit
    end
  end

  opts.parse!(arguments)

  unless arguments_flag
    puts "didn't get any arguments"
    puts opts
    exit
  end


  if @options.snmpwalk == ''
    @snmp_log.fatal("Couldn't find snmpwalk")
    abort "Couldn't find snmpwalk on Ubuntu try sudo apt-get install snmp"
  end

  unless @usernames = File.open(@options.usernames,'r').readlines
    @snmp_log.fatal("Couldn't open the usernames file")
    abort "Couldn't open the usernames file"
  end

  @usernames.each {|name| name.chomp!}

  @report = File.new(@options.report, "a+")

  @ip_addresses = @options.ip_address

  @snmpwalk = @options.snmpwalk
  @snmp_log.debug("snmpwalk set to" + @snmpwalk)

end

def scan
  @report.puts "SNMP SCAN V3 run at #{Time.now.to_s}"
  @report.puts "-------------------------------------"

  #Iterate over each ip address to be tested
  @ip_addresses.each do |ip|
    @snmp_log.debug("run for IP address of #{ip} started")
    @report.puts ''
    @report.puts "Results for : #{ip}"

    #This is an initial check to see if the host responds at all
    up_responses = %x[#{@snmpwalk} -v 3 -l noAuthNoPriv #{ip} RFC1213-MIB::sysUpTime.0 2>&1]
    if up_responses =~ /Timeout/
      @report.puts "No snmp server found on host"
      @snmp_log.warn("No SNMP server found on host : #{ip}")
      next
    end
    #Now for this host iterate over each of the names to try
    @usernames.each do |name|
      @snmp_log.debug("Run for name of #{name} with IP of #{ip} started")
      result = ''
      #This is the main request to snmpwalk
      response = %x[#{@snmpwalk} -v 3 -l noAuthNoPriv -u #{name} #{ip} RFC1213-MIB::sysUpTime.0 2>&1]
      if response =~ /Unknown user name/
        result = 'Unknown User'
      elsif response =~ /authorizationError/
        result = 'Known User'
        puts "valid username : #{name} on host : #{ip}"
      else
        result = 'unknown response.  See debug log for details'
      end
      @report.puts "Username : #{name} had response of #{result}"
      @snmp_log.debug("#{ip.to_s},#{name}, #{response}")
    end
  end
end



end

if __FILE__ == $0
  analysis = Snmpv3Enum.new(ARGV)
  analysis.scan
end
