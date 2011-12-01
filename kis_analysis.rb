#!/usr/bin/env ruby
#TODO: split out network numbers on the report (inf/adhoc/probe)



class KisAnalysis
  VERSION = '0.12'
  #Copyright (C) 2011  Rory McCune
  #This program is free software; you can redistribute it and/or
  #modify it under the terms of the GNU General Public License
  #as published by the Free Software Foundation; either version 2
  #of the License, or (at your option) any later version.
  #
  #This program is distributed in the hope that it will be useful,
  #but WITHOUT ANY WARRANTY; without even the implied warranty of
  #MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  #GNU General Public License for more details.
  #
  #You should have received a copy of the GNU General Public License
  #along with this program; if not, write to the Free Software
  #Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
  
  def initialize(arguments)
    begin
      require 'rubygems'
      require 'nokogiri'
      require 'logger'
      require 'optparse'
      require 'ostruct'
	  
    rescue LoadError
      abort("FATALITY: kis_analysis required the nokogiri gem to work.  Try 'gem install nokogiri'\n for linux installs 'apt-get install libxslt libxml2 libxml2-dev' is needed before installing the gem")
    end

    @log = Logger.new("kis-analysis.log")
    @log.level = Logger::DEBUG
    @log.debug("Log Created at " + Time.now.to_s)

    @options = OpenStruct.new

    #Name for the .netxml file to be parsed
    @options.input_file_name = nil
	
    #Directory name that contains the .netxml files to be parsed
    @options.input_dir_name = nil
	
    #Name for the report file.  If not specified a default is assigned
    @options.report_file = nil
	
    #Array of file names that we either assign the name above to or that we punt all the files from the specified directory into if -d has been used
    @options.file_names = Array.new
	
    #Once we've opened the files we use this array for the contents
    @options.files = Array.new
	
    #This is a flag for whether the analyse_gps method is run
    @options.gps = false
	
    #This contains the gps data if required. the hash key is the mac address of the network the contents are a hash of the lat/long position
    @options.gps_data = Hash.new
	
    #This is a reporting option for whether we want the report with a single HTML table or one per SSID
    @options.single_table = false
	
    #This options defines whether we want a google map of the networks. For it to work the gps option is needed
    @options.create_map = false

    #This option specifies whether we'll try looking up the network co-ordinates using Google Maps
    @options.google_maps_lookup = false

    opts = OptionParser.new do |opts|
      opts.banner = "Ruby Kismet Log File Analyzer"

      opts.on("-fFILE","--file FILE", "kismet netxml file to analyze") do |file|
        @log.debug("Trying to open Input File")
        @options.input_file_name = file
      end

      opts.on("-dDIR","--dir DIR","Directory with kismet netxml files to analyze") do |dir|
        @log.debug("Setting Directory")
        @options.input_dir_name = dir
        #TODO: Need to create a check for openable directory here
      end

      opts.on("-rREPORT","--report REPORT","report file") do |rep|
        @log.debug("setting report file")
        @options.report_file = rep
      end

      opts.on("-g","--gps","Enable GPS analysis") do |gps|
        @options.gps = true
      end

      opts.on("-l", "--googlelookup", "Enable GPS lookup using Google maps javascript API") do |lookup|
        @options.google_maps_lookup = true
      end

      opts.on("-m","--map","Create a Google map") do |map|
        @options.create_map = true
      end

      opts.on("-h","--help","-?","--?", "Get Help") do |help|
        puts opts
        exit
      end

      opts.on("-v","--version", "Get Version") do |ver|
        puts "Ruby Kismet Log parser #{VERSION}"
        exit
      end

    end

    opts.parse!(arguments)
    
    unless @options.input_file_name || @options.input_dir_name
      puts "ERROR: Either a file name or directory name required to work"
      puts opts
      exit
    end

    if @options.input_file_name && @options.input_dir_name
      puts "can't specify files and directories"
      puts "one or the other..."
      exit
    end

    

    if @options.input_file_name
      begin
        file = File.open(@options.input_file_name).read
        @options.files << file
        @options.file_names << @options.input_file_name
      rescue Errno::ENOENT
        @log.fatal("Input File #{file} could not be opened")
        puts "couldn't open the input file, sure it's there?"
        exit
      end
      @log.info("opened #{@options.input_file_name} successfully")
    elsif @options.input_dir_name
      begin
        Dir.chdir(@options.input_dir_name) unless Dir.pwd == @options.input_dir_name
      rescue Errno::ENOENT
        @log.fatal("can't change to #{@options.input_dir_name} sure it's there?")
        abort("Can't change to #{@options.input_dir_name} sure it's there?")
      end

      pot_files = Dir.entries(@options.input_dir_name)
      pot_files.each do |pot_file|
        if pot_file =~ /netxml$/
          begin
            tfile = File.open(pot_file).read
            @options.files << tfile
            @options.file_names << pot_file
          rescue Errno::ENOENT
            @log.fatal("Input File #{tfile} could not be opened")
            puts "couldn't open the input file, sure it's there?"
            exit
          end

        end

      end

    else
      @log.fatal("no idea how we got here!")
      puts "that was weird"
      exit
    end
   
    

  end

  def analyse
    @num_servers = 0
    @num_clients = 0
    @num_by_cipher = Hash.new
    @infrastructure_networks = Hash.new
    @probe_networks = Hash.new
    @adhoc_networks = Hash.new
    @nets_by_bssid = Hash.new

    @options.files.each do |file|
      @doc = Nokogiri::XML(file)
      if @options.gps || @options.google_maps_lookup
        analyse_gps
      end


      @num_servers = @num_servers + @doc.search('wireless-network').length
      @num_clients = @num_clients + @doc.search('wireless-client').length

      @doc.search('wireless-network').each do |net|
        if net.attribute('type').value == 'infrastructure'
          analyse_net(net,'inf')
        elsif net.attribute('type').value == 'probe'
          analyse_net(net, 'probe')
        elsif net.attribute('type').value == 'ad-hoc'
		      analyse_net(net,'adhoc')
		    else
		      @log.warn("hit an unknown Wireless network type #{net.attribute('type').value}")
        end
      end
    end
  end

  #Generate the HTML report for the Scan
  def html_report
    begin
      require 'ruport'
    rescue LoadError
      abort("Couldn't load ruport, suggest that gem install ruport should help")
    end

    unless @options.report_file
      html_report_file_name = 'Kismet-Wireless-Report-' + Time.now.to_s + '.html'
    end

    unless @options.report_file =~ /html$/
      html_report_file_name = @options.report_file + '.html'
    end

    @report = File.new(html_report_file_name,'w+')
    html_report_header
    html_report_stats
    
    if @options.create_map
      @report << '<hr /><br /><br />'
      html_report_map_body
    end
    @report << '<hr /><br /><br />'
    html_report_inf
    @report << '<hr /><br /><br />'
    html_report_adhoc
    @report << '<hr /><br /><br />'
	html_report_probe
    
    
    @report << "</body>"
    @report << "</html>"
  end

  #Sets up the HTML report header.  CSS and Javascript for the Google Maps Option
  def html_report_header
    @report << '
    <html>
      <head>
       <title> Kismet Wireless Report</title>
       <style>
        body {
	        font: normal 11px auto "Trebuchet MS", Verdana, Arial, Helvetica, sans-serif;
	        color: #4f6b72;
	        background: #E6EAE9;
        }
        #report-header {
          font-weight: bold;
          font-size: 24px;
          font-family: "Trebuchet MS", Verdana, Arial, Helvetica, sans-serif;
          color: #4f6b72;

        }

        #sub-header {
          font-weight: italic;
          font-size: 10px;
          font-family: "Trebuchet MS", Verdana, Arial, Helvetica, sans-serif;
          color: #4f6b72;

        }

        #title {
          font-weight: bold;
          font-size: 16px;
          font-family: "Trebuchet MS", Verdana, Arial, Helvetica, sans-serif;
          color: #4f6b72;
        }

         th {
	       font: bold 11px "Trebuchet MS", Verdana, Arial, Helvetica, sans-serif;
	       color: #4f6b72;
	       border-right: 1px solid #C1DAD7;
	       border-bottom: 1px solid #C1DAD7;
	       border-top: 1px solid #C1DAD7;
	       letter-spacing: 2px;
	       text-transform: uppercase;
	       text-align: left;
	       padding: 6px 6px 6px 12px;
         }

      td {
	      border-right: 1px solid #C1DAD7;
	      border-bottom: 1px solid #C1DAD7;
	      background: #fff;
	      padding: 6px 6px 6px 12px;
	      color: #4f6b72;
      }


      td.alt {
	      background: #F5FAFA;
	      color: #797268;
      }



    </style>
    '
    if @options.create_map
      @report << %Q!
       <script type="text/javascript" src="http://maps.google.com/maps/api/js?sensor=false"></script>
       <script type="text/javascript">
       function initialize() {
         var latlng = new google.maps.LatLng(#{@map_centre['lat']}, #{@map_centre['long']});
         var myOptions = {
           zoom: 14,
           center: latlng,
           mapTypeId: google.maps.MapTypeId.ROADMAP
         };
        var map = new google.maps.Map(document.getElementById("map_canvas"), myOptions);
     !

     #Yugh this is a hack
     @options.gps_data.each do |bssid,point|
        netname = bssid.gsub(':','')

        if @nets_by_bssid[bssid]
          #Next line is present to strip any single quotes from SSID's before putting them into the marker as that causes problems :)
          content_ssid = @nets_by_bssid[bssid]['ssid'].gsub(/['<>]/,'')
          @log.debug("About to add " + content_ssid) if content_ssid
          @report << %Q!
            var contentString#{netname} = '<b>SSID: </b> #{content_ssid} <br />' +
                                          '<b>BSSID: </b> #{bssid}<br />' +
                                          '<b>Channel: </b> #{@nets_by_bssid[bssid]['channel']} <br />' +
                                          '<b>Ciphers: </b> #{@nets_by_bssid[bssid]['cipher']} <br />' +
                                          '<b>Cloaked?: </b> #{@nets_by_bssid[bssid]['cloaked']} <br />';
            var infowindow#{netname} = new google.maps.InfoWindow({
              content: contentString#{netname}
            });
           !
        end
         @report << %Q!
            var latlng#{netname} = new google.maps.LatLng(#{point['lat']}, #{point['lon']});

            var marker#{netname} = new google.maps.Marker({
              position: latlng#{netname},
              map: map
            });
       !
       if @nets_by_bssid[bssid]
         @report << %Q!
            google.maps.event.addListener(marker#{netname}, 'click', function() {
              infowindow#{netname}.open(map,marker#{netname});
            });
         !
       end
     end

      @report << %Q!
      }
     </script>

    !
    end
    @report << '</head>'
    if @options.create_map
      @report << '<body onload="initialize()">'
    else
      @report << '<body>'
    end
    @report << '<div id="report-header">Kismet Wireless Report</div> <br /> <div id="sub-header"> Report Generated at ' + Time.now.to_s + '<br />'
    @report << 'Files analysed ' + @options.file_names.join(',<br />') + '<br /> <br /></div>'
  end

  #Sets up the statistics table
  def html_report_stats
    @report << '<div id="title"> General Statistics</div>'
    stat_tab = Ruport::Data::Table(%w[Stat Value])
    stat_tab << ['Number of servers Seen', @num_servers]
    stat_tab << ['Number of clients Seen', @num_clients]
    @num_by_cipher.each do |cipher, num|
      stat_tab << ['Encryption: ' + cipher, num]
    end
    @report << stat_tab.to_html
    @report << '<br /><br />'
  end

  #creates the report section for Infrastructure Networks
  def html_report_inf
    @report << '<div id="title">Infrastructure Networks</div><br /><br />'
	  @log.debug("Starting reporting Infrastructure networks there were " + @infrastructure_networks.length.to_s + " networks to list")
    @infrastructure_networks.each do |ssid,bssid|
      tab = Ruport::Data::Table(%w[bssid num_clients channel cipher cloaked? manufacturer first_seen last_seen max_signal_dbm])
      ssid = "Hidden or Blank" if ssid.length < 1
      @report << '<div id="title">SSID: ' + ssid + ' </div>'
      bssid.each do |net,info|
        if @options.gps_data[net]
          point = net
          @log.debug("attempting to add link")
          link_info = '+(' + ssid + ' | Ciphers: ' + info['cipher'] + ' | Channel: ' + info['channel'] + ')'
          url = 'http://maps.google.co.uk/maps?q=' + @options.gps_data[point]['lat'].to_s + ',' + @options.gps_data[point]['lon'].to_s + link_info
          net = '<a href="' + url + '">' + point + '</a>'
        end
        tab << [net, info['clients'].length.to_s, info['channel'], info['cipher'], info['cloaked'], info['manufacturer'], info['first_seen'], info['last_seen'], info['max_signal_dbm']]
      end
      @report << tab.to_html
      @report << "<br /> <br />"
    end
  end

  #Sets up the HTML report for AdHoc Networks
  def html_report_adhoc
    @log.debug("Starting to report ad-hoc networks, there were " + @adhoc_networks.length.to_s + "to report")
    @report << '<div id="title">Adhoc Networks</div><br /><br />'
    @adhoc_networks.each do |ssid,bssid|
      tab = Ruport::Data::Table(%w[bssid channel cipher cloaked? manufacturer first_seen last_seen max_signal_dbm])
      ssid = "Hidden or Blank" if ssid.length < 1
      @report << '<div id="title">SSID: ' + ssid + ' </div>'
      bssid.each do |net,info|
          if @options.gps_data[net]
            point = net
            @log.debug("attempting to add link")
            link_info = '+(' + ssid + ' | Ciphers: ' + info['cipher'] + ' | Channel: ' + info['channel'] + ')'
            url = 'http://maps.google.co.uk/maps?q=' + @options.gps_data[point]['lat'].to_s + ',' + @options.gps_data[point]['lon'].to_s + link_info
            net = '<a href="' + url + '">' + point + '</a>'
          end
          tab << [net, info['channel'], info['cipher'], info['cloaked'], info['manufacturer'], info['first_seen'], info['last_seen'], info['max_signal_dbm']]
      end
      @report << tab.to_html
      @report << "<br /> <br />"
    end
  end

  #Sets up the report for Probe Networks
  def html_report_probe
    @log.debug("Starting to report probe networks, there were " + @probe_networks.length.to_s + " to report")
	@report << '<div id="title">Probe Networks</div><br /><br />'
	@probe_tab = Ruport::Data::Table(%w[bssid manufacturer])
	@probe_networks.each do |probe,info|
	  if @options.gps_data[probe]
        point = probe
        @log.debug("attempting to add link")
        url = 'http://maps.google.co.uk/maps?q=' + @options.gps_data[point]['lat'].to_s + ',' + @options.gps_data[point]['lon'].to_s
      probe = '<a href="' + url + '">' + point + '</a>'
      end
	  @probe_tab << [probe, info['manufacturer']]
	end
	
	@report << @probe_tab.to_html
	@report << "<br /><br />"
  end

  def html_report_map_body
    @report << '<div id="map_canvas" style="width:50%; height:50%"></div> '
  end

  
  def analyse_net(net,type)
	  manufacturer = net.search('manuf')[0].text
    begin
      encryption_cipher = net.search('encryption')[0].text
    rescue NoMethodError
      @log.debug('no encryption method for network')
      encryption_cipher = 'unknown'
    end
    if @num_by_cipher[encryption_cipher]
      @num_by_cipher[encryption_cipher] = @num_by_cipher[encryption_cipher] + 1
    else
      @num_by_cipher[encryption_cipher] = 1
    end



	  case type
      when "inf", "adhoc"
        begin
          bssid = net.search('BSSID')[0].text
		      essid = net.search('essid')[0].text
          channel = net.search('channel')[0].text
			    #TODO: Complete Hack make this nicer we need to find the essid where there are multiple instances of it sometimes it's reporting blank.
			    if essid.length <2 && net.search('essid').length > 1
			      essid = essid + net.search('essid')[1].text
			    end
		      first_seen = net.attribute('first-time').value
		      last_seen = net.attribute('last-time').value
          cloaked = net.search('essid')[0].attribute('cloaked').text
          #This has is needed for the Google Maps Setup
          @nets_by_bssid[bssid] = Hash.new
          @nets_by_bssid[bssid]['ssid'] = essid
          @nets_by_bssid[bssid]['channel'] = channel
          @nets_by_bssid[bssid]['cipher'] = encryption_cipher
          @nets_by_bssid[bssid]['cloaked'] = cloaked

		    rescue NoMethodError
          @log.warn("Can't find the key data for this network skipping")
          return
        end
      when "probe"
        begin
  	      bssid = net.search('BSSID')[0].text
  		    essid = 'probe'
  	    rescue NoMethodError
          @log.warn("Can't find the key data for this network skipping")
          return
        end
  	end

    begin
  	  max_signal_dbm = net.search('max_signal_dbm')[0].text
   	rescue NoMethodError
  	  @log.debug("No Max Signal for Network : " + essid)
	    max_signal_dbm = "N/A"
    end


    if type == 'inf'
      #Setup Clients Array For infrastructure Networks (Adhoc and probe don't have clients)
      clients = Array.new
      net.search('wireless-client').each do |client|
        clients << client.search('client-mac').text
      end

      unless @infrastructure_networks[essid]
        @infrastructure_networks[essid] = Hash.new
      end

      unless @infrastructure_networks[essid][bssid]
        @infrastructure_networks[essid][bssid] = Hash.new
      end

      @infrastructure_networks[essid][bssid]['channel'] = channel
      @infrastructure_networks[essid][bssid]['cipher'] = encryption_cipher
      @infrastructure_networks[essid][bssid]['cloaked'] = cloaked
      @infrastructure_networks[essid][bssid]['clients'] = clients
  	  @infrastructure_networks[essid][bssid]['manufacturer'] = manufacturer
  	  @infrastructure_networks[essid][bssid]['max_signal_dbm'] = max_signal_dbm
	    @infrastructure_networks[essid][bssid]['first_seen'] = first_seen
  	  @infrastructure_networks[essid][bssid]['last_seen'] = last_seen
    elsif type == 'adhoc'
	    unless @adhoc_networks[essid]
        @adhoc_networks[essid] = Hash.new
      end

      unless @adhoc_networks[essid][bssid]
        @adhoc_networks[essid][bssid] = Hash.new
      end

      @adhoc_networks[essid][bssid]['channel'] = channel
      @adhoc_networks[essid][bssid]['cipher'] = encryption_cipher
      @adhoc_networks[essid][bssid]['cloaked'] = cloaked
	    @adhoc_networks[essid][bssid]['manufacturer'] = manufacturer
  	  @adhoc_networks[essid][bssid]['max_signal_dbm'] = max_signal_dbm
  	  @adhoc_networks[essid][bssid]['first_seen'] = first_seen
  	  @adhoc_networks[essid][bssid]['last_seen'] = last_seen
    elsif type == 'probe'
	    unless @probe_networks[bssid]
        @probe_networks[bssid] = Hash.new
      end
	    @probe_networks[bssid]['manufacturer'] = manufacturer
	  end
  end

  def analyse_gps
    @log.debug("Starting GPS Analysis")
    
    @doc.search('wireless-network').each do |net|
      if @options.gps
	      next if net.attribute('type').value == 'probe'
        next unless net.search('avg-lat').length > 0 && net.search('avg-lon').length > 0
        bssid = net.search('BSSID').text
        @options.gps_data[bssid] = Hash.new

        @options.gps_data[bssid]['lat'] = net.search('avg-lat')[0].text.to_f
        @log.debug("just wrote a value of " + net.search('avg-lat')[0].text + " for " + bssid)
        @options.gps_data[bssid]['lon'] = net.search('avg-lon')[0].text.to_f
        @log.debug("just wrote a value of " + net.search('avg-lon')[0].text + "for " + bssid )
      elsif @options.google_maps_lookup
        next if net.attribute('type').value == 'probe'
        require 'json'
        require 'net/http'
        require 'uri'
        bssid = net.search('BSSID').text

        host = 'www.google.com'
        port = '80'
        post_ws = "/loc/json"
        

        post_data = {
          "version" => "1.1.0",
          "wifi_towers" => [{
              "mac_address" => bssid,
              "ssid" => "0",
              "signal_strength" => -72
          }]
        }.to_json

        req = Net::HTTP::Post.new(post_ws, initheader = {'Content-Type' => 'application/json'})
        req.body = post_data
        response = Net::HTTP.new(host, port).start{|http| http.request(req)}
        unless response.code == "200"
          @log.info("Error on GPS Google Lookup got a  #{response.code} code")
          next
        end
        begin
        result = JSON.parse(response.body)
        rescue JSON::ParserError
          @log.info("Error doing JSON parse on google response")
          next
        end
        @options.gps_data[bssid] = Hash.new
        @options.gps_data[bssid]['lat'] = result['location']['latitude']
        @options.gps_data[bssid]['lon'] = result['location']['longitude']
      end
    end
      
    
    #We need the centre point for the map if it's enabled
    if @options.create_map
      base_lat = 0.00
      base_long = 0.00
      point_count = 0
      @options.gps_data.each do |point,data|
        @log.debug("about to write data for " + point)
        base_lat = base_lat + data['lat']
        base_long = base_long + data['lon']
        point_count = point_count + 1
      end
      @map_centre = Hash.new
      @map_centre['lat'] = base_lat / point_count
      @map_centre['long'] = base_long / point_count
    end
  end
  
  def text_report
    @txt_rep = File.new(@options.report_file + '.txt', 'w+')
	  @txt_rep.puts "Kismet Text Report"
	  @txt_rep.puts "-----------------------------"
	  @txt_rep.puts "Infrastructure networks"
	  @txt_rep.puts "------------------------------"
	  @infrastructure_networks.each do |essid,bssid|
	    @txt_rep.puts " "
	    @txt_rep.puts "Network : " + essid
	    @txt_rep.puts "-------------------"
	    bssid.each do |net,info|
  	    @txt_rep.puts net + ',' + info['channel'] + ',' + info['clients'].length.to_s + ',' + info['cipher'] + ',' + info['manufacturer']
  	  end
  	end
  	@txt_rep.puts " "
  	@txt_rep.puts " "
  	@txt_rep.puts " "
  	@txt_rep.puts "-----------------------------"
  	@txt_rep.puts "ad-hoc networks"
  	@txt_rep.puts "------------------------------"
  	@adhoc_networks.each do |essid,bssid|
  	  @txt_rep.puts " "
  	  @txt_rep.puts "Network : " + essid
  	  @txt_rep.puts "------------------"
  	  bssid.each do |net,info|
  	    @txt_rep.puts net + ',' + info['channel'] + ',' + info['cipher'] + ',' + info['manufacturer']
	    end
  	end
  	@txt_rep.puts " "
  	@txt_rep.puts " "
  	@txt_rep.puts " "
  	@txt_rep.puts "-----------------------------"
  	@txt_rep.puts "Probe requests"
	  @txt_rep.puts "------------------------------"
	  @probe_networks.each do |bssid, info|
  	  @txt_rep.puts bssid + ',' + info['manufacturer']
  	end
  end

  
end

if __FILE__ == $0
  analysis = KisAnalysis.new(ARGV)
  analysis.analyse
  analysis.html_report
  analysis.text_report
  
end
