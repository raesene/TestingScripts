#!/usr/bin/env ruby
# This script take in role/role binding and clusterrole/clusterrolbinding objects in JSON
# And parses out some info, then creates a table for them to help in a review.
# To get it working you need 4 files
# clusterroles.json - produced with kubectl get clusterroles -o json
# clusterrolebindings.json - produced with kubectl get clusterrolebindings -o json
# roles.json - produced with kubectl get roles --all-namespaces -o json
# rolebindings.json - producted with kubectl get rolebindings --all-namespaces -o json
# 

class K8sRbacAnalyzer
  VERSION='0.0.1'

  def initialize(commandlineoptions)
    require 'logger'
    @options = commandlineoptions
    @base_dir = @options.report_directory
    @cr_file = @options.cr_file
    @crb_file = @options.crb_file
    @role_file = @options.role_file
    @rb_file = @options.rb_file
    if !File.exists?(@base_dir)
      Dir.mkdir(@base_dir)
    end

    if @options.logger
      @log = Logger.new(@base_dir + '/' + @options.logger)
    else
      @log = Logger.new(STDOUT)
    end

    @log.level = Logger::DEBUG
    @log.debug("Log created at " + Time.now.to_s)

  end

  def run
    require 'json'
    cr_input = File.open(@cr_file,'r').read
    crb_input = File.open(@crb_file,'r').read
    role_input = File.open(@role_file,'r').read
    rb_input = File.open(@rb_file,'r').read

    cluster_roles = JSON.parse(cr_input)
    cluster_role_bindings = JSON.parse(crb_input)
    roles = JSON.parse(role_input)
    role_bindings = JSON.parse(rb_input)

    @results = Hash.new
    @subject_results = Hash.new
    cluster_roles['items'].each do |role|
      role_output = Hash.new
      role_output[:rules] = role['rules']
      begin
        if role['metadata']['labels']['kubernetes.io/bootstrapping'] == "rbac-defaults"
          role_output[:default] = true
        else
          role_output[:default] = false
        end
      rescue NoMethodError
        role_output[:default] = false
      end

      role_output[:subjects] = Array.new
      cluster_role_bindings['items'].each do |binding|
        if binding['roleRef']['kind'] == "ClusterRole"
          if binding['roleRef']['name'] == role['metadata']['name']
            if binding['subjects']
              binding['subjects'].each do |subject|
                role_output[:subjects] << subject
                unless @subject_results[subject]
                  @subject_results[subject] = Array.new
                end
                @subject_results[subject] << role['metadata']['name']
              end
            end
          end
        end
      end
      @results[role['metadata']['name']] = role_output
    end
  end

  def report
    @html_report_file = File.new(@options.report_file + '.html','w+')

    @html_report_file << '
          <!DOCTYPE html>
          <head>
           <title> Kubernetes RBAC Audit Report</title>
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
    @html_report_file.puts "<br><br><h2>Cluster Role Information</h2>"
    @html_report_file.puts "<table><thead><tr><th>Name</th><th>Default?</th><th>Subjects</th><th>Rules</th></tr></thead>"
    @results.each do |name, info|
      subjects = ''
      info[:subjects].each do |subject|
        subjects << "#{subject['kind']}:#{subject['namespace']}:#{subject['name']}<br>"
      end
      rules = ''
      info[:rules].each do |rule|
        unless rule['verbs']
          rule['verbs'] = Array.new
        end
        unless rule['apiGroups']
          rule['apiGroups'] = Array.new
        end
        unless rule['resources']
          rule['resources'] = Array.new
        end
        unless rule['nonResourceURLs']
          rule['nonResourceURLs'] = Array.new
        end
        rules << "Verbs : #{rule['verbs'].join(', ')}<br>API Groups : #{rule['apiGroups'].join(', ')}<br>Resources : #{rule['resources'].join(', ')}<br>Non Resource URLs: #{rule['nonResourceURLs'].join(', ')}<hr>"
      end
      @html_report_file.puts "<tr><td>#{name}</td><td>#{info[:default]}</td><td>#{subjects}</td><td>#{rules}</td></tr>"
    end
    @html_report_file.puts "</table>"
    @html_report_file.puts "<br><br>"
    @html_report_file.puts "<br><br><h2>Cluster Role Subject Information</h2>"
    @html_report_file.puts "<table><thead><tr><th>Subject</th><th>Roles</th></tr></thead>"
    @subject_results.each do |subject, roles|
      @html_report_file.puts "<tr><td>#{subject}</td><td>#{roles.join('<br>')}</td></tr>"
    end
    @html_report_file.puts "</table>"
    @html_report_file.puts "<br><br>"
    @html_report_file.puts "</body></html>"
    @html_report_file.close
  end
end

if __FILE__ == $0
  require 'ostruct'
  require 'optparse'
  options = OpenStruct.new

  options.report_directory = Dir.pwd
  options.report_file = "k8s-rbac-analysis-report"
  options.cr_file = ''
  options.crb_file = ''
  options.role_file = ''
  options.rb_file = ''

  opts = OptionParser.new do |opts|
    opts.banner = "Kubernetes RBAC Auditor #{K8sRbacAnalyzer::VERSION}"
    opts.on( "--crfile [CRFILE]", "Cluster Role File to review") do |crfile|
      options.cr_file = crfile
    end

    opts.on( "--crbfile [CRBFILE]", "Cluster Role Bindings File to review") do |crbfile|
      options.crb_file = crbfile
    end

    opts.on(" --rolefile [ROLEFILE]", "File containing role information") do |rolefile|
      options.role_file = rolefile
    end

    opts.on(" --rbfile [RBFILE]", "File containing the role binding information") do |rbfile|
      options.rb_file = rbfile
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
      puts "Kubernetes RBAC Auditor Version #{K8sRbacAnalyzer::VERSION}"
      exit
    end
  end

  opts.parse!(ARGV)

  unless (options.cr_file.length > 1 && options.crb_file.length > 1 )
    puts "Need to specify the Cluster Role and Cluster Role Bindings file to be reviewed"
    puts opts
    exit
  end

  analysis = K8sRbacAnalyzer.new(options)
  analysis.run
  analysis.report
end