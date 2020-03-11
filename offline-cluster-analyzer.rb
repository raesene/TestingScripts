#!/usr/bin/env ruby
# This script is designed to take the output of "kubectl get $(kubectl api-resources --verbs=list -o name | grep -v -e "secrets" -e "componentstatuses" -e "priorityclass" -e "events" | paste -sd, -) --ignore-not-found --all-namespaces -o json" 
# and analyse it for various things that can be helpful in security reviews and review scoping

class Offlinek8sAnalyzer
  VERSION='0.0.1'

  def initialize(commandlineopts)
    require 'logger'
    @options = commandlineopts
    @base_dir = @options.report_directory
    @input_file = @options.input_file

    if @options.logger
      @log = Logger.new(@base_dir + '/' + @options.logger)
    else
      @log = Logger.new(STDOUT)
    end

    @log.level = Logger::DEBUG
    @log.debug("Log created at " + Time.now.to_s)

  end

  def run
    @log.debug ("Starting Run")
    require 'json'
    @cluster_info = Hash.new

    input = File.open(@input_file,'r').read

    @data = JSON.parse(input)
  end

  def container_image_info
    @log.debug("Starting Image Info")
    pods = Array.new

    images = Array.new

    @data['items'].each do |item|
      if item['kind'] == "Pod"
        pods << item
      end
    end

    pods.each do |pod|
        pod['spec']['containers'].each do |container|
            images << container['image']
        end
    end

    images.uniq!
    
    @cluster_info['container_images'] = Array.new
    images.each {|image| @cluster_info['container_images'] << image }
  end

  def object_info
    @log.debug("Starting Object Info")
    objects = Array.new
    @data['items'].each do |item|
      objects << item['kind']
    end
    
    objects.uniq!
    @cluster_info['objects'] = Array.new
    objects.each {|object| @cluster_info['objects'] << object}
    

  end

  def report
    @log.debug("Starting Report")
    @html_report_file = File.new(@options.report_file + '.html','w+')

    @html_report_file << '
          <!DOCTYPE html>
          <head>
           <title> Kubernetes Offline Analysis Report</title>
           <meta charset="utf-8"> 
           <style>
            body {
              font: normal 14px;
              font-family: "Helvetica Neue", Helvetica, Arial, sans-serif;
              color: #C41230;
              background: #FFFFFF;
            }
            #kubernetes-analyzer {
              font-weight: bold;
              font-size: 48px;
              color: #C41230;
            }
            .master-node, .worker-node, .vuln-node {
              background: #F5F5F5;
              border: 1px solid black;
              padding-left: 6px;
            }
            #api-server-results {
              font-weight: italic;
              font-size: 36px;
              color: #C41230;
            }
            table, th, td {
              border-collapse: collapse;
              border: 1px solid black;
            }
            th {
             font: bold 11px;
             color: #C41230;
             background: #999999;
             letter-spacing: 2px;
             text-transform: uppercase;
             text-align: left;
             padding: 6px 6px 6px 12px;
            }
            td {
            background: #FFFFFF;
            padding: 6px 6px 6px 12px;
            color: #333333;
            }
            .container{
              display: flex;
            } 
            .fixed{
              width: 300px;
            }
            .flex-item{
              flex-grow: 1;
            }
        </style>
      </head>
      <body>
      
        '

    @html_report_file.puts "<br><br>"
    @html_report_file.puts "<h1>Kubernetes Offline Analysis</h1>"
    #Summary Stats
    @html_report_file.puts "<h2>Summary Statistics</h2>"
    @html_report_file.puts "<table><thead><tr><th>Check</th><th>Number</th></tr></thead>"
    @log.debug("Number of container images should be " + @cluster_info['container_images'].length.to_s)
    @html_report_file.puts "<tr><td>Unique Docker Images</td><td>#{@cluster_info['container_images'].length.to_s}</td></tr>"
    @html_report_file.puts "<tr><td>Object Types In use</td><td>#{@cluster_info['objects'].length.to_s}</td></tr>"
    @html_report_file.puts "</table>"

    # Object Info Section
    @html_report_file.puts "<h2>Kinds of Kubernetes Objects In use</h2>"
    @html_report_file.puts "<table><thead><tr><th>Object</th></tr></thead>"
    @html_report_file.puts "<tr><td>#{@cluster_info['objects'].join('<br>')}</td></tr>"
    @html_report_file.puts "</table>"

    # Container Image Section
    @html_report_file.puts "<h2>Docker Images Used In Cluster</h2>"
    @html_report_file.puts "<table><thead><tr><th>Image Name</th></tr></thead>"
    @html_report_file.puts "<tr><td>#{@cluster_info['container_images'].join('<br>')}</td></tr>"
    @html_report_file.puts "</table>"



    @html_report_file.puts "</body></html>"
  end
end


if __FILE__ == $0
  require 'ostruct'
  require 'optparse'
  options = OpenStruct.new

  options.report_directory = Dir.pwd
  options.report_file = "k8s-offline-analysis-report"
  options.input_file = ''
  
  opts = OptionParser.new do |opts|
    opts.banner = "Kubernetes Offline Analyzer #{Offlinek8sAnalyzer::VERSION}"
    opts.on("--inputfile [INPUTFILE]", "Cluster Role File to review") do |inputfile|
      options.input_file = inputfile
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
      puts "Kubernetes Offline Auditor Version #{Offlinek8sAnalyzer::VERSION}"
      exit
    end
  end

  opts.parse!(ARGV)

  unless (options.input_file.length > 1 )
    puts "Need to specify the cluster configuration to be analyzed"
    puts opts
    exit
  end

  analysis = Offlinek8sAnalyzer.new(options)
  analysis.run
  analysis.container_image_info
  analysis.object_info
  analysis.report
end

