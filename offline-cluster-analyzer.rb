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
    @rbac_results = Hash.new
    @rbac_subject_results = Hash.new

    input = File.open(@input_file,'r').read

    @data = JSON.parse(input)
  end

  def pod_info
    @log.debug("Starting Pod Info")
    @cluster_info['pods'] = Array.new
    @data['items'].each do |item|
      if item['kind'] == "Pod" && item['apiVersion'] == "v1"
        @cluster_info['pods'] << item
      end
    end
  end

  def security_context_info
    #OK this is a dirty hack, needs cleaned up later.  security context can be at a pod or container level, but we'll check container level for now
    @cluster_info['security_contexts'] = Hash.new
    @data['items'].each do |item|
      @log.debug("about to do a pod in security context")
      if item['kind'] == "Pod" && item['apiVersion'] == "v1"
        podname = item['metadata']['name']
        namespace = item['metadata']['namespace']
        #Lets get some security context info out of the containers
        item['spec']['containers'].each do |container|
          containername = container['name']
          if container['securityContext']
            @cluster_info['security_contexts'][namespace + '|' + podname + '|' + containername] = container['securityContext']
          end
        end
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
      if item['kind'] == "Namespace" && item['apiVersion'] == "v1"
        @cluster_info['namespaces'] << item['metadata']['name']
      end
    end
    @log.debug("Found #{@cluster_info['namespaces'].length.to_s } namespaces")
  end

  def node_info
    @log.debug("Starting node Info")
    @cluster_info['nodes'] = Array.new
    @data['items'].each do |item|
      if item['kind'] == "Node" && item['apiVersion'] == "v1"
        ip_addresses = Array.new
        item['status']['addresses'].each do |add|
          if add["type"] == "InternalIP"
            ip_addresses << add["address"]
          end
        end
        @cluster_info['nodes'] << item['metadata']['name'] + ',' + ip_addresses.join(' ')
      end
    end
  end

  def rbac_info
    @log.debug("Starting RBAC Info")
    @roles = Array.new
    @rolebindings = Array.new
    @clusterroles = Array.new
    @clusterrolebindings = Array.new

    @data['items'].each do |item|
      case item['kind']
      when "ClusterRole"
        @clusterroles << item
      when "ClusterRoleBinding"
        @clusterrolebindings << item
      when "Role"
        @roles << item
      when "RoleBinding"
        @rolebindings << item
      end
    end
  
    @cluster_info['clusterroles'] = Array.new
    @cluster_info['clusterrolebindings'] = Array.new
    @cluster_info['roles'] = Array.new
    @cluster_info['rolebindings'] = Array.new
    @clusterroles.each do |item|
      if item['kind'] == "ClusterRole" && item['apiVersion'] == "rbac.authorization.k8s.io/v1"
        @cluster_info['clusterroles'] << item['metadata']['name']
      end
    end

    @clusterrolebindings.each do |item|
      if item['kind'] == "ClusterRoleBinding" && item['apiVersion'] == "rbac.authorization.k8s.io/v1"
        @cluster_info['clusterrolebindings'] << item['metadata']['name']
        @log.debug("added a clusterrolebinding")
      end
    end

    @roles.each do |item|
      if item['kind'] == "Role" && item['apiVersion'] == "rbac.authorization.k8s.io/v1"
        @cluster_info['roles'] << item['metadata']['name']
      end
    end

    @rolebindings.each do |item|
      if item['kind'] == "RoleBinding" && item['apiVersion'] == "rbac.authorization.k8s.io/v1"
        @cluster_info['rolebindings'] << item['metadata']['name']
      end
    end
  end

  def parseclusterroles
    @rbac_results['clusterroles'] = Hash.new
    @clusterroles.each do |role|
      role_name = role['metadata']['name']
      role_output = Hash.new
      # Handle the case with a role with no rules in it
      unless role['rules']
        role['rules'] = Hash.new
      end
      role_output[:rules] = role['rules']
      #Add a flag so we know if this is one of k8s default roles
      #This is brittle but ok for now.
      begin
        if role['metadata']['labels']['kubernetes.io/bootstrapping'] == "rbac-defaults"
          role_output[:default] = true
        else
          role_output[:default] = false
        end
      rescue NoMethodError
        role_output[:default] = false
      end

      role_output[:cluster_subjects] = Array.new
      @clusterrolebindings.each do |binding|
        if binding['roleRef']['name'] == role_name
          if binding['subjects']
            binding['subjects'].each do |subject|
              role_output[:cluster_subjects] << subject
              unless @rbac_subject_results[subject]
                @rbac_subject_results[subject] = Array.new
              end
              @rbac_subject_results[subject] << role_name
            end
          end
        end
      end
      role_output[:subjects] = Array.new
      @rolebindings.each do |binding|
        if binding['roleRef']['kind'] == "ClusterRole"
          if binding['roleRef']['name'] == role_name
            if binding['subjects']
              binding['subjects'].each do |subject|
                #Not 100% that this logic holds
                subject['namespace'] = binding['metadata']['namespace']
                role_output[:subjects] << subject
                @log.debug("Namespace for subject is #{subject['namespace']}")
              end
            end
          end
        end
      end
      @rbac_results['clusterroles'][role_name] = role_output
    end
  end

  def parseroles
    @roles.each do |role|
      role_namespace = role['metadata']['namespace']
      role_name = role['metadata']['name']
      role_output = Hash.new
      # Handle the case with a role with no rules in it
      unless role['rules']
        role['rules'] = Hash.new
      end
      role_output[:rules] = role['rules']
      #Add a flag so we know if this is one of k8s default roles
      #This is brittle but ok for now.
      begin
        if role['metadata']['labels']['kubernetes.io/bootstrapping'] == "rbac-defaults"
          role_output[:default] = true
        else
          role_output[:default] = false
        end
      rescue NoMethodError
        role_output[:default] = false
      end
      
      #Here we Don't need to check for cluster roles as you can't (AFAIK) do a clusterrolebinding to a role
      role_output[:subjects] = Array.new
      @rolebindings.each do |binding|
        if binding['roleRef']['kind'] == "ClusterRole"
          if binding['roleRef']['name'] == role_name
            if binding['subjects']
              binding['subjects'].each do |subject|
                #Not 100% that this logic holds
                subject['namespace'] = binding['metadata']['namespace']
                role_output[:subjects] << subject
              end
            end
          end
        end
      end
      unless @rbac_results[role_namespace]
        @rbac_results[role_namespace] = Hash.new
      end
      @log.debug("Analysed a role in #{role_namespace} called #{role_name}")
      @rbac_results[role_namespace][role_name] = role_output
    end
  end

  def rbac_security_checks
    @rbac_security_check_results = Hash.new
    @rbac_security_check_results[:get_secrets] = Hash.new
    @rbac_results.each do |namespace, results|
      @rbac_security_check_results[:get_secrets][namespace] = Hash.new
      results.each do |role_name, info|
        info[:rules].each do |rule|
          @log.debug("About to check #{role_name} for secrets")
          next unless rule['resources'] && rule['verbs']
          if rule['resources'].include?('secrets') && rule['verbs'].include?('get')
            @rbac_security_check_results[:get_secrets][namespace][role_name] = info
            @log.debug("Added a role called #{role_name}")
          end
          if rule['resources'].include?('*') && rule['verbs'].include?('*')
            @rbac_security_check_results[:get_secrets][namespace][role_name] = info
            @log.debug("Added a wildcard role called #{role_name} from namespace #{namespace}")
          end
        end
      end
    end
  end



  def service_info
    @log.debug("Starting Service Info")
    @cluster_info['services'] = Hash.new
    @data['items'].each do |item|
      if item['kind'] == "Service" && item['apiVersion'] == "v1"
        ports = Array.new
        begin
          item['spec']['ports'].each do |p|
            ports << p['port']
            @log.debug("added #{p['port']}")
          end
        rescue NoMethodError
          @log.debug("there were no ports for service #{item['metadata']['name']}")
        end
        service_data = Array.new
        service_data << item['spec']['clusterIP']
        service_data << ports.join(',')
        @log.debug("ip address is #{service_data[0]}")
        @cluster_info['services'][item['metadata']['namespace'] + ':' + item['metadata']['name']] = service_data
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
    @html_report_file.puts "<tr><td>Services in cluster</td><td>#{@cluster_info['services'].length.to_s}</td></tr>"
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
    @html_report_file.puts "<table><thead><tr><th>Node Name</th><th>IP Address(es)</th></tr></thead>"
    @cluster_info['nodes'].each do |node|
      name = node.split(',')[0]
      ip_addresses = node.split(',')[1]
      @html_report_file.puts "<tr><td>#{name}</td><td>#{ip_addresses}</tr>"  
    end
    
    @html_report_file.puts "</table>"
    
    # Services Section
    @html_report_file.puts "<h2>Services In Cluster</h2>"
    @html_report_file.puts "<table><thead><tr><th>Namespace Name</th><th>Service Name</th></tr></thead>"
    @cluster_info['services'].each do |name, value|
      @html_report_file.puts "<tr><td>#{name.split(':')[0]}</td><td>#{name.split(':')[1]}</td></tr>"
    end
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

    @html_report_file.puts "<br><br>"
    @html_report_file.puts "<h2>Privileged Roles</h2>"
    @rbac_security_check_results[:get_secrets].each do |namespace, roles|
      if namespace == 'clusterroles'
        @html_report_file.puts "<h2>Cluster Roles with Get Secrets</h2>"
        @html_report_file.puts "<table><thead><tr><th>Role Name</th><th>Default?</th><th>Cluster Subjects</th><th>Subjects</th></thead>"  
        roles.each do |role|
          subjects = ''
          cluster_subjects = ''
          role[1][:subjects].each do |subject|
            subjects << "#{subject['kind']}:#{subject['namespace']}:#{subject['name']}<br>"
          end
          if role[1][:cluster_subjects]
            role[1][:cluster_subjects].each do |subject|
              cluster_subjects << "#{subject['kind']}:#{subject['namespace']}:#{subject['name']}<br>"
            end
          end
          @html_report_file.puts "<tr><td>#{role[0]}</td><td>#{role[1][:default]}</td><td>#{cluster_subjects}</td><td>#{subjects}</tr>"
        end
        @html_report_file.puts "</table><br><br>"
      else
        @html_report_file.puts "<h2>Roles for the #{namespace} namespace with Get Secrets</h2>"
        @html_report_file.puts "<table><thead><tr><th>Role Name</th><th>Default?</th><th>Subjects</th></thead>"
        roles.each do |role|
          subjects = ''
          role[1][:subjects].each do |subject|
            subjects << "#{subject['kind']}:#{subject['namespace']}:#{subject['name']}<br>"
          end
          @html_report_file.puts "<tr><td>#{role[0]}</td><td>#{role[1][:default]}</td><td>#{subjects}</td></tr>"
        end
        @html_report_file.puts "</table><br><br>"
      end
      
    end


    @html_report_file.puts "<br><br>"
    @html_report_file.puts "<br><br><h2>Cluster Role Information</h2>"
    @html_report_file.puts "<table><thead><tr><th>Name</th><th>Default?</th><th>Cluster Subjects</th><th>Subjects</th><th>Rules</th></tr></thead>"
    @rbac_results['clusterroles'].each do |name, info|
      cluster_subjects = ''
      info[:cluster_subjects].each do |subject|
        cluster_subjects << "#{subject['kind']}:#{subject['namespace']}:#{subject['name']}<br>"
      end
      subjects = ''
      info[:subjects].each do |sus|
        @log.debug "Namespace for subject is #{sus['namespace']}"
        subjects << "#{sus['kind']}:#{sus['namespace']}:#{sus['name']}<br>"
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
      @html_report_file.puts "<tr><td>#{name}</td><td>#{info[:default]}</td><td>#{cluster_subjects}</td><td>#{subjects}</td><td>#{rules}</td></tr>"
    end
    @html_report_file.puts "</table>"
    @html_report_file.puts "<br><br>"


    @rbac_results.each do |name, info|
      next if name == 'clusterroles'
      @log.debug "printing results for namespace : #{name}"
      @html_report_file.puts "<br><h2>Information for Namespace #{name}</h2> "
      @html_report_file.puts "<table><thead><tr><th>Name</th><th>Default?</th><th>Subjects</th><th>Rules</th></tr></thead>"
      info.each do |role, output|
        subjects = ''
        output[:subjects].each do |sus|
          subjects << "#{sus['kind']}:#{sus['namespace']}:#{sus['name']}<br>"
        end
        rules = ''
        output[:rules].each do |rule|
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
        @html_report_file.puts "<tr><td>#{role}</td><td>#{output[:default]}</td><td>#{subjects}</td><td>#{rules}</td></tr>"
      end
      @html_report_file.puts "</table>"
      @html_report_file.puts "<br><br>"
    end
    @html_report_file.puts "<br><br><h2>Cluster Role Subject Information</h2>"
    @html_report_file.puts "<table><thead><tr><th>Subject</th><th>Roles</th></tr></thead>"
    @rbac_subject_results.each do |subject, roles|
      @html_report_file.puts "<tr><td>#{subject}</td><td>#{roles.join('<br>')}</td></tr>"
    end
    @html_report_file.puts "</table>"
    @html_report_file.puts "<br><br>"

    @html_report_file.puts "<br><br><h2>Security Context Information</h2>"
    @html_report_file.puts "<table><thead><tr><th>Namespace</th><th>Pod Name</th><th>Container Name</th><th>Security context</th></tr></thead>"
    @cluster_info['security_contexts'].each do |name, seccon|
      namespace, pod, container = name.split('|')
      @html_report_file.puts "<tr><td>#{namespace}</td><td>#{pod}</td><td>#{container}</td><td>#{seccon.to_s}</td></tr>"
    end
    @html_report_file.puts "</table>"

    # Service scanning Section
    @html_report_file.puts "<br><br>"
    @html_report_file.puts "<h2>NMap command for scanning services</h2>"
    @html_report_file.puts "<table><thead><tr><th>Command</th></tr></thead>"
    ports = Array.new
    ips = Array.new
    @cluster_info['services'].each do |name, value|
      if value[0] != "None"
        ips << value[0]
      end
      value[1].split(',').each do |val|
        ports << val
      end
    end
    ports.uniq!
    @html_report_file.puts "<tr><td>nmap -sT -Pn -p #{ports.join(',')} #{ips.join(' ')} </td></tr>"
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

    opts.on("-r", "--reportFile [REPORTFILE]", "Report File Name") do |reportfile|
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
  analysis.security_context_info
  analysis.container_image_info
  analysis.object_info
  analysis.crd_info
  analysis.namespace_info
  analysis.node_info
  analysis.service_info
  analysis.rbac_info
  analysis.parseclusterroles
  analysis.parseroles
  analysis.rbac_security_checks
  analysis.report
end

