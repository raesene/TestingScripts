#!/usr/bin/env ruby
# TODO: Include parser Directive options (e.g. changing comment characters) https://docs.docker.com/engine/reference/builder/#parser-directives



class DockerfileAnalyzer
  VERSION='0.0.1'

  def initialize(commandlineopts)
    require 'logger'

    @options = commandlineopts
    @base_dir = @options.report_directory
    @scan_dir = @options.scan_directory
    if !File.exists?(@base_dir)
      Dir.mkdir(@base_dir)
    end

    if @options.logger
      @log = Logger.new(@base_dir + '/' + @options.logger)
    else
      @log = Logger.new(STDOUT)
    end
    #Change before release
    @log.level = Logger::DEBUG

    @log.debug("Log created at " + Time.now.to_s)
    @log.debug("Scan type is : " + @options.scan_type.to_s)
    @log.debug("Directory being scanned is : " + @options.scan_directory) if @options.scan_type == :directory
    puts @options.report_file
    @log.debug("File being scanned is : " + @options.scan_file) if @options.scan_type == :file
  end

  def run
    case @options.scan_type
    when :directory
      scan_dirs
      parse_files
      analyze_files
      report
    when :file
      @scan_files = Array.new
      @scan_files << @options.scan_file
      parse_files
      analyze_files
      report
    end
  end

  def scan_dirs
  end

  def parse_files
    @parsed_dockerfiles = Array.new
    @log.debug("Files to be looked at : " + @scan_files.join(', '))
    @scan_files.each do |file|
      results = Hash.new
      file_contents = File.open(file,'r').readlines
      #Get rid of the line endings
      file_contents.each {|line| line.chomp!}
      #Remove Blank Lines
      file_contents.delete_if {|line| line.length==0}
      #Get all the continued lines onto a single line
      file_contents.each_index do |i|
        while file_contents[i] =~ /\\$/
          file_contents[i].sub!(/\\$/,'')
          file_contents[i] = file_contents[i] + file_contents[i+1].lstrip
          file_contents.delete_at(i+1)
        end
      end
      
      #Not gathering all the commands here just the ones we want to analyse
      #CMD or ENTRYPOINT
      results[:command] = Array.new
      results[:from] = Array.new
      results[:run] = Array.new
      results[:add] = Array.new
      results[:copy] = Array.new
      results[:env] = Array.new
      results[:user] = Array.new
      file_contents.each do |line|
        cmd = line.split(' ')[0]
        @log.debug ("Working on a #{cmd}")
        case cmd
        when "CMD" || "ENTRYPOINT"
          results[:command] << line
        when "ENV" || "ARG"
          results[:env] << line
        when "RUN"
          results[:run] << line
        when "USER"
          results[:user] << line
        when "FROM"
          results[:from] << line
        when "ADD"
          results[:add] << line
        when "COPY"
          results[:copy] << line
        end


      end
      @parsed_dockerfiles << results
    end
  end

  def analyze_files
  end

  def report
  end
end

if __FILE__ == $0
  require 'ostruct'
  require 'optparse'
  options = OpenStruct.new

  options.report_directory = Dir.pwd
  options.report_file = "docker-analysis-report"
  options.scan_directory = Dir.pwd
  options.scan_file = 'Lorem'
  
  options.scan_type = :notset
  options.recursive = false

  opts = OptionParser.new do |opts|
    opts.banner = "Dockerfile Analyzer #{DockerfileAnalyzer::VERSION}"
    opts.on("-d", "--directory [DIRECTORY]", "Directory to scan for Dockerfiles") do |dir|
      options.scan_directory = dir
      options.scan_type = :directory
    end

    opts.on("--recursive", "scan for Dockerfiles recursively") do |recurse|
      options.recursive = true
    end

    opts.on("-f", "--file [FILE]", "File to scan for issues") do |file|
      options.scan_file = file
      options.scan_type = :file
    end

    opts.on("--reportDirectory [REPORTDIRECTORY", "Directory for the report") do |repdir|
      options.report_directory = repdir
    end

    opts.on("-l", "--logger [LOGGER]", "Log debugging messages to a file") do |logger|
      options.logger = logger
    end

    opts.on("-h", "--help", "-?", "--?", "Get Help") do |help|
      puts opts
      exit
    end

    opts.on("-v", "--version", "Get Version") do |ver|
      puts "Dockerfile Analyzer Version #{DockerfileAnalyzer::VERSION}"
    end
  end

  opts.parse!(ARGV)

  unless (options.scan_type == :file || options.scan_type == :directory)
    puts "Didn't get any arguments or missing scan type"
    puts opts
    exit
  end

  analysis = DockerfileAnalyzer.new(options)
  analysis.run
end