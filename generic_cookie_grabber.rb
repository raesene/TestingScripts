#!/usr/bin/env ruby


# == Author
# Author::  Rory McCune
# Copyright:: Copyright (c) 2013 Rory Mccune
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

#Code to get the session tokens after a two stage login

require 'mechanize'

output_file = File.open('tokens','a+')
for i in 1..500
  agent = Mechanize.new

  #Set proxy to burp for troubleshooting
  #agent.set_proxy 'localhost', 8080
  #agent.idle_timeout = 1
  #agent.keep_alive=false


  #Turn off SSL verify when using burp
  agent.verify_mode = OpenSSL::SSL::VERIFY_NONE


  #get the pre-login page
  page = agent.get('http://127.0.0.1:3000/login/start')

  login_form = page.forms[0]

  #Fill in your customer ID here change field name as necessary
  login_form.field('username').value = 'admin'

  page2 = login_form.click_button

  login_form2 = page2.forms[0]

  #Here's our sample password
  password = ['b','s','i','d','e','s']

  #Here for our example we can work out what characters to enter
  #based on the numbers from the label elements
  c1 = page2.labels[0].to_s[/\d/]
  c2 = page2.labels[1].to_s[/\d/]
  c3 = page2.labels[2].to_s[/\d/]

  #snippet to remove one from each element to match up with the array numbering 
  c1 = c1.to_i - 1
  c2 = c2.to_i - 1
  c3 = c3.to_i - 1

  #Fill in the elements of the password form with our characters
  login_form2.field('char1').value = password[c1]
  login_form2.field('char2').value = password[c2]
  login_form2.field('char3').value = password[c3]

  page3 = login_form2.click_button

  #Example of looking for a token in the body of the response
  if page3.body[/[a-z]{50}/]
    output_file.puts page3.body[/[a-z]{50}/]
  else
    puts "didn't get a token"
  end

#Example of getting the value from a cookie on the page
  agent.cookies.each do |cookie|
    if cookie.name =~ /<cookie_We_want>/
      output_file.puts cookie.value
      puts 'captured a cookie'
    end
  end

end

