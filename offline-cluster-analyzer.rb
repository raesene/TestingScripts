#!/usr/bin/env ruby
# This script is designed to take the output of "kubectl get $(kubectl api-resources --verbs=list -o name | grep -v -e "secrets" -e "componentstatuses" -e "priorityclass" -e "events" | paste -sd, -) --ignore-not-found --all-namespaces -o json" 
# If you don't fancy the nested command kubectl get po,svc,roles,rolebindings,clusterroles,clusterrolebindings,networkpolicies,psp,no,ns,pv,pvc,rc,crds,ds,deploy,rs,sts,ing --all-namespaces -o json , will work.
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

  def pod_info
    @log.debug("Starting Pod Info")
    @cluster_info['pods'] = Array.new
    @data['items'].each do |item|
      if item['kind'] == "Pod"
        @cluster_info['pods'] << item
      end
    end
  end

  def container_image_info
    @log.debug("Starting Image Info")

    images = Array.new

    @cluster_info['container_images'] = Array.new

    @cluster_info['pods'].each do |pod|
        pod['spec']['containers'].each do |container|
            @cluster_info['container_images'] << container['image']
        end
    end

    @cluster_info['container_images'].uniq!
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

  def crd_info
    @log.debug("Starting CRD Info")
    @cluster_info['crds'] = Array.new
    @data['items'].each do |item|
      if item['kind'] == "CustomResourceDefinition"
        @cluster_info['crds'] << item['metadata']['name']
      end
    end
    @log.debug("Found #{@cluster_info['crds'].length.to_s} CRDs")
  end

  def namespace_info
    @log.debug("Starting Namespace Info")
    @cluster_info['namespaces'] = Array.new
    @data['items'].each do |item|
      if item['kind'] == "Namespace"
        @cluster_info['namespaces'] << item['metadata']['name']
      end
    end
    @log.debug("Found #{@cluster_info['namespaces'].length.to_s } namespaces")
  end

  def node_info
    @log.debug("Starting node Info")
    @cluster_info['nodes'] = Array.new
    @data['items'].each do |item|
      if item['kind'] == "Node"
        @cluster_info['nodes'] << item['metadata']['name']
      end
    end
  end

  def rbac_info
    @log.debug("Starting RBAC Info")
    @cluster_info['clusterroles'] = Array.new
    @cluster_info['clusterrolebindings'] = Array.new
    @cluster_info['roles'] = Array.new
    @cluster_info['rolebindings'] = Array.new

    @data['items'].each do |item|
      if item['kind'] == "ClusterRole"
        @cluster_info['clusterroles'] << item['metadata']['name']
      end
    end

    @data['items'].each do |item|
      if item['kind'] == "ClusterRoleBinding"
        @cluster_info['clusterrolebindings'] << item['metadata']['name']
      end
    end

    @data['items'].each do |item|
      if item['kind'] == "Role"
        @cluster_info['roles'] << item['metadata']['name']
      end
    end

    @data['items'].each do |item|
      if item['kind'] == "RoleBinding"
        @cluster_info['rolebindings'] << item['metadata']['name']
      end
    end

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
    @html_report_file.puts "<tr><td>Namespaces</td><td>#{@cluster_info['namespaces'].length.to_s}</td></tr>"
    @html_report_file.puts "<tr><td>Nodes</td><td>#{@cluster_info['nodes'].length.to_s}</td></tr>"
    @html_report_file.puts "<tr><td>Pods running in cluster</td><td>#{@cluster_info['pods'].length.to_s}</td></tr>"
    @html_report_file.puts "<tr><td>Cluster Roles in cluster</td><td>#{@cluster_info['clusterroles'].length.to_s}</td></tr>"
    @html_report_file.puts "<tr><td>Cluster Role Bindings in cluster</td><td>#{@cluster_info['clusterrolebindings'].length.to_s}</td></tr>"
    @html_report_file.puts "<tr><td>Roles in cluster</td><td>#{@cluster_info['roles'].length.to_s}</td></tr>"
    @html_report_file.puts "<tr><td>Role Bindings in cluster</td><td>#{@cluster_info['rolebindings'].length.to_s}</td></tr>"
    @html_report_file.puts "<tr><td>Object Types In use</td><td>#{@cluster_info['objects'].length.to_s}</td></tr>"
    @html_report_file.puts "<tr><td>CRDs In use</td><td>#{@cluster_info['crds'].length.to_s}</td></tr>"
    @html_report_file.puts "<tr><td>Unique Docker Images</td><td>#{@cluster_info['container_images'].length.to_s}</td></tr>"
    @html_report_file.puts "</table>"

    # Namespace Info Section
    @html_report_file.puts "<h2>Namespaces in cluster</h2>"
    @html_report_file.puts "<table><thead><tr><th>namespace name</th><th>pods in namespace</th></tr></thead>"
    @cluster_info['namespaces'].each do |namespace|
      pods = 0
      @cluster_info['pods'].each do |pod|
        if pod['metadata']['namespace'] == namespace
          pods = pods +1
        end
      end
      @html_report_file.puts "<tr><td>#{namespace}</td><td>#{pods}</td></tr>"  
    end
    @html_report_file.puts "</table>"

    # Nodes Section
    @html_report_file.puts "<h2>Nodes In Cluster</h2>"
    @html_report_file.puts "<table><thead><tr><th>Node Name</th></tr></thead>"
    @html_report_file.puts "<tr><td>#{@cluster_info['nodes'].join('<br>')}</td></tr>"
    @html_report_file.puts "</table>"
    
    # Object Info Section
    @html_report_file.puts "<h2>Standard Kubernetes Objects In use</h2>"
    @html_report_file.puts "<table><thead><tr><th>Object</th></tr></thead>"
    @html_report_file.puts "<tr><td>#{@cluster_info['objects'].join('<br>')}</td></tr>"
    @html_report_file.puts "</table>"

    # CRD Section
    @html_report_file.puts "<h2>CRDs In Cluster</h2>"
    @html_report_file.puts "<table><thead><tr><th>CRD Name</th></tr></thead>"
    @html_report_file.puts "<tr><td>#{@cluster_info['crds'].join('<br>')}</td></tr>"
    @html_report_file.puts "</table>"

    # Container Image Section
    @html_report_file.puts "<h2>Unique Docker Images Used In Cluster</h2>"
    @html_report_file.puts "<table><thead><tr><th>Image Name</th></tr></thead>"
    @html_report_file.puts "<tr><td>#{@cluster_info['container_images'].sort.join('<br>')}</td></tr>"
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
    opts.on("-i", "--inputfile [INPUTFILE]", "Cluster Role File to review") do |inputfile|
      options.input_file = inputfile
    end

    opts.on("-f", "--reportFile [REPORTFILE]", "Report File Name") do |reportfile|
      options.report_file = reportfile
    end

    opts.on("--reportDirectory [REPORTDIRECTORY]", "Directory for the report") do |repdir|
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
  analysis.pod_info
  analysis.container_image_info
  analysis.object_info
  analysis.crd_info
  analysis.namespace_info
  analysis.node_info
  analysis.rbac_info
  analysis.report
end

