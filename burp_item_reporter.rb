#!/usr/bin/env ruby

require 'nokogiri'
require 'rubyXL'
require 'base64'

unless ARGV.length > 0 
  puts 'Syntax is burp_item_list.rb <inputfile>'
  exit
end

input_file = File.open(ARGV[0],'r').read


doc = Nokogiri::XML.parse(input_file)


items = doc.xpath('//item')


workbook = RubyXL::Workbook.new
sheet = workbook[0]


sheet.add_cell(0,0,"Item Number")
sheet.add_cell(0,1,"Time")
sheet.add_cell(0,2,"host")
sheet.add_cell(0,3,"port")
sheet.add_cell(0,4,"protocol")
sheet.add_cell(0,5,"method")
sheet.add_cell(0,6,"path")
sheet.add_cell(0,7,"extension")
sheet.add_cell(0,8,"request")
sheet.add_cell(0,9,"status")
sheet.add_cell(0,10,"response length")
sheet.add_cell(0,11,"MIME Type")
sheet.add_cell(0,12,"response")
sheet.add_cell(0,13,"comment")

count = 1
items.each do |item|
  sheet.add_cell(count,0,count)
  sheet.add_cell(count,1,item.xpath('time').inner_text)
  sheet.add_cell(count,2,item.xpath('host').inner_text)
  sheet.add_cell(count,3,item.xpath('port').inner_text)
  sheet.add_cell(count,4,item.xpath('protocol').inner_text)
  sheet.add_cell(count,5,item.xpath('method').inner_text)
  sheet.add_cell(count,6,item.xpath('path').inner_text)
  sheet.add_cell(count,7,item.xpath('extension').inner_text)
  sheet.add_cell(count,8,Base64.decode64(item.xpath('request').inner_text))
  sheet.add_cell(count,9,item.xpath('status').inner_text)
  sheet.add_cell(count,10,item.xpath('responselength').inner_text)
  sheet.add_cell(count,11,item.xpath('mimetype').inner_text)
  sheet.add_cell(count,12,Base64.decode64(item.xpath('response').inner_text))
  sheet.add_cell(count,13,item.xpath('comment').inner_text)
  count = count + 1
end

output_filename = ARGV[0] + '.xlsx'
workbook.write(output_filename)
