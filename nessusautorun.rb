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

    #ToDo: fix this up to check for the presence of a port and have it add it if needed
    #At the moment it's a hack for forgetful people (e.g. me)
    unless host =~ /8834\/*$/
      host = host + ':8834'
    end

    agent = Mechanize.new
    #Most Nessus instances won't have a trusted cert.
    agent.verify_mode = OpenSSL::SSL::VERIFY_NONE

    #Troubleshooting stuff
    agent.set_proxy 'localhost', 8080
    agent.idle_timeout = 1
    agent.keep_alive=false

    login_url = host + '/login'

    login_response = agent.post(login_url, {:login => username, :password => password})

    login_response_xml = Nokogiri::XML(login_response.body)

    @token = login_response_xml.xpath('//token').text

    if @token.length > 1
      puts "logged in ok with a token of " + @token
    end
  end
end