#!/usr/bin/env ruby


class NessusautoRun
  VERSION = '0.0.1'

  def initialize(host, username, password)
    begin
      require 'mechanize'
    rescue LoadError
      puts "Could not load mechanize"
      puts "try gem install mechanize or bundle install"
      exit
    end

    require 'uri'


    #ToDo: fix this up to check for the presence of a port and have it add it if needed
    #At the moment it's a hack for forgetful people (e.g. me)
    #unless host =~ /8834\/*$/
    #  host = host + ':8834'
    #end
    
    host_url = URI.parse(host)

    unless host_url.class == URI::HTTPS
      abort("Sure you got the hostname right?")
    end

    #Assumption here is that Nessus runs on 8834 in future this should be an option but at the moment we'll hardcode it
    unless host_url.port == 8834
      host_url.set_port = 8834
    end






    @host = host_url.to_s

    @agent = Mechanize.new
    #Most Nessus instances won't have a trusted cert.
    @agent.verify_mode = OpenSSL::SSL::VERIFY_NONE

    #Troubleshooting stuff
    @agent.set_proxy 'localhost', 8080
    @agent.idle_timeout = 1
    @agent.keep_alive=false

    login_url = @host + 'login'

    login_response = @agent.post(login_url, {:login => username, :password => password})

    login_response_xml = Nokogiri::XML(login_response.body)

    @token = login_response_xml.xpath('//token').text

    if @token.length > 1
      puts "logged in ok with a token of " + @token
    end

    @executed_scans = Hash.new
  end

  def list_policies
    list_policy_url = @host + 'policy/list'
    list_policy_response = @agent.get(list_policy_url)
    policy_xml = Nokogiri::XML(list_policy_response.body)
    policy_names = policy_xml.xpath('//reply/contents/policies/policy/policyName').collect {|name| name.text}
    policy_ids = policy_xml.xpath('//reply/contents/policies/policy/policyID').collect {|id| id.text}
    policy_names.length.times do |line|
      puts "Policy ID : #{policy_ids[line - 1]} - Policy Name : #{policy_names[line - 1]}"
    end
  end

  def run_scan(hosts, pol_id, s_name)
    #Todo: Need validation for hostnames and policy IDs
    scan_url = @host + 'scan/new'
    scan_response = @agent.post(scan_url, {:target => hosts, :policy_id => pol_id, :scan_name => s_name})
    scan_response_xml = Nokogiri::XML(scan_response.body)
    scan_id = scan_response_xml.xpath('//reply/contents/scan/uuid').text
    puts "Scan ID : #{scan_id}"
    @executed_scans[s_name] = scan_id
  end

  def get_report(name)
    #ToDo:  Add a call to the report list to check the scan status before trying to download it
    report_url = @host + 'file/report/download'
    report_uid = @executed_scans[name]
    report_response = @agent.post(report_url, {:report => report_uid})
    puts report_response.body.size.to_s + " is the size of the report"
  end

end