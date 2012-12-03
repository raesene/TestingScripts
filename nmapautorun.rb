#!/usr/bin/env ruby



class NmapautoRun

  VERSION = '0.0.1'

  def initialize(input_filename, input_range, report_file_base)
    begin
      require 'nmap/program'
    rescue LoadError
      puts 'could not load the ruby-nmap library'
      puts 'Try gem install ruby-nmap'
      exit
    end

    @input_filename = input_filename


    @input_range = input_range
    @report_file_base = report_file_base

  end

  def init_scan
    Nmap::Program.scan do |nmap|
      nmap.syn_scan = true
      nmap.service_scan = true
      nmap.default_script = true
      nmap.os_fingerprint = true
      nmap.verbose = true
      nmap.top_ports = 1000
      nmap.xml = @report_file_base + '_init.xml'
      if @input_range.length > 1
        nmap.targets = @input_range
      elsif @input_filename.length > 1
        nmap.target_file = @input_filename
      end
    end
  end

  def full_tcp_scan
    Nmap::Program.scan do |nmap|
      nmap.syn_scan = true
      nmap.verbose = true
      nmap.ports = '1-65535'
      nmap.xml = @report_file_base + '_full_tcp.xml'
      if @input_range.length > 1
        nmap.targets = @input_range
      elsif @input_filename.length > 1
        nmap.target_file = @input_filename
      end
    end
  end

  def full_tcp_scan_noping
    Nmap::Program.scan do |nmap|
      nmap.syn_scan = true
      nmap.verbose = true
      nmap.skip_discovery
      nmap.ports = '1-65535'
      nmap.xml = @report_file_base + '_full_tcp_noping.xml'
      if @input_range.length > 1
        nmap.targets = @input_range
      elsif @input_filename.length > 1
        nmap.target_file = @input_filename
      end
    end
  end


  def mod_udp_scan
    Nmap::Program.scan do |nmap|
      nmap.udp_scan = true
      nmap.service_scan = true
      nmap.version_intensity = 0
      nmap.verbose = true
      nmap.top_ports = 1000
      nmap.xml = @report_file_base + '_mod_udp.xml'
      if @input_range.length > 1
        nmap.targets = @input_range
      elsif @input_filename.length > 1
        nmap.target_file = @input_filename
      end
    end
  end

end



if __FILE__ == $0
  require 'optparse'
  require 'ostruct'

  options = OpenStruct.new
  options.input_file = ''
  options.input_range = ''
  options.no_ping = false
  #creates a unique base file name in case the user doesn't specify one
  options.report_file_base = 'nmap_auto' + Time.now.gmtime.to_s.gsub(/\W/,'')


  opts = OptionParser.new do |opts|
    opts.banner = "NMAP Auto Runner #{NmapautoRun::VERSION}"

    opts.on("-f", "--file [FILE]", "Input File with list of IPs") do |file|
      options.input_file = file
    end

    opts.on("-r", "--range [RANGE]", "Range to Scan") do |range|
      options.input_range = range
    end

    opts.on("-o", "--output [OUTPUT]", "Output File Name Base") do |output|
      options.report_file_base = output
    end

    opts.on("-n", "--noping", "Run the full TCP scan with no ping") do |noping|
      options.no_ping = true
    end

    opts.on("-h", "--help", "-?", "--?", "Get Help") do |help|
      puts opts
      exit
    end

    opts.on("-v", "--version", "Get Version") do |ver|
      puts "NMAP Auto Runner #{NmapautoRun::VERSION}"
      exit
    end

  end

  opts.parse!(ARGV)

  unless options.input_file.length > 1 || options.input_range.length > 1
    puts "You need either a file to read IPs from or specify a range with -r"
    puts opts
    exit
  end



  scan = NmapautoRun.new(options.input_file, options.input_range, options.report_file_base)

  scan.init_scan
  scan.mod_udp_scan
  if options.no_ping
    scan.full_tcp_scan_noping
  else
    scan.full_tcp_scan
  end



end


