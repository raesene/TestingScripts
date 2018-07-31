#!/usr/bin/env ruby
  # == Synopsis
  # This script is designed to co-ordinate parsing of Clair Vulnerability scanner JSON files and production of a concise set findings.
  #
  # WARNING This isn't ready for use yet, don't do it, you'll be sorry!
  #
  # There are 2 modes of operation.
  #
  # Directory mode just takes a parameter of the directory containing the xml files and goes and parses any files found there
  #
  # File mode takes a parameter of a single file and parses that
  #
  #TODO:
  # == Author
  # Author::  Rory McCune
  # Copyright:: Copyright (c) 2018 Rory Mccune
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
  #   -h, --help            Displays help message
  #   -v, --version         Display the version, then exit
  #   -d <dir>, --directory <dir>  Only needed in directory mode name of the directory to scan
  #   -f <file>, --file <file>     Only needed in file mode, name of the file to parse
  #   -r <file>, --report <file>        Name of file for reporting
  #   -l <file>             Log debug messages to a file.
  #   --reportDirectory <dir>   Place the report in a different directory
  #
  # == Usage
  #
  #   Directory Mode
  #   clairautoanalyzer.rb -m directory -d <directoryname> -r <reportfile>
  #   File Mode
  #   clairautoanalyzer.rb -m file -f <filename> -r <reportfile>



class ClairAutoAnalyzer
  VERSION='0.0.1'

  def initialize(commandlineopts)
    #This is StdLib so shouldn't need a rescue for failed require
    require 'json'
    require 'logger'

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
    #Change this to Logger::DEBUG if you want to debug stuff
    @log.level = Logger::DEBUG

    @log.debug("Log created at " + Time.now.to_s)
    @log.debug("Scan type is : #{@options.scan_type}")
    @log.debug("Directory being scanned is : #{@options.scan_directory}") if @options.scan_type == :directory
    @log.debug("File being scanned is : #{@options.scan_file}") if @options.scan_type == :file
  end

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

  def scan_dirs
    @scan_files = Array.new
    @log.debug("Scan directory is #{@scan_dir}")
    Dir.entries(@scan_dir).each do |scan|
      next if File.directory?(@scan_dir + '/' + scan)
      @scan_files << @scan_dir + '/' + scan
    end
  end

  def parse_files
    @image_results = Hash.new
    @log.debug("Files to be looked at : #{@scan_files.join(', ')}")
    @scan_files.each do |file|
      file_content = File.open(file,'r').read
      begin
        @log.debug("File name is " + file)
        doc = JSON.parse(file_content)
      rescue JSON::ParserError => e
        @log.warn("We got a parser error on #{file}")
        next
      end

      begin
        @log.debug("Got a valid JSON file called #{file}, processing...")
        parse_file(doc)
      rescue Exception => e
        @log.warn("We got a parsing error on a valid JSON file #{file}")
        @log.warn(e)
      end
    end
  end

  def parse_file(doc)
    image = doc['image']
    @image_results[image] = Hash.new
    doc['vulnerabilities'].each do |vuln|
      @image_results[image][vuln['vulnerability']] = [vuln['severity'], vuln['featurename']]
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
    vuln_sheet = workbook.worksheets[0]
    vuln_sheet.sheet_name = "Docker Image Vulnerabilities"
    vuln_sheet.add_cell(0,0,"Image Name")
    vuln_sheet.add_cell(0,1,"CVE ID")
    vuln_sheet.add_cell(0,2,"Severity")
    vuln_sheet.add_cell(0,3,"Affected Package")
    row_count = 1
    @image_results.each do |image, results|
      results.each do |cve, data|
        vuln_sheet.add_cell(row_count,0,image)
        vuln_sheet.add_cell(row_count,1,cve)
        vuln_sheet.add_cell(row_count,2,data[0])
        vuln_sheet.add_cell(row_count,3,data[1])
        row_count = row_count + 1
      end
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
    opts.banner = "Clair Auto analyzer #{ClairAutoAnalyzer::VERSION}"
    
    opts.on("-d", "--directory [DIRECTORY]", "Directory to scan for Clair json files") do |dir|
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
      puts "Clair Analyzer Version #{ClairAutoAnalyzer::VERSION}"
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

  analysis = ClairAutoAnalyzer.new(options)
  analysis.run
end