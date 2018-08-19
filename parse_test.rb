#!/usr/bin/env ruby

results = Hash.new
output_file = File.new('testout','w')

file_contents = File.open('Dockerfile','r').readlines
#Get rid of the line endings
file_contents.each {|line| line.chomp!}
#Remove Blank Lines
file_contents.delete_if {|line| line.length==0}





file_contents.each_index do |i|
  while file_contents[i] =~ /\\$/
  	file_contents[i].sub!(/\\$/,'')
  	file_contents[i] = file_contents[i] + file_contents[i+1].lstrip
  	file_contents.delete_at(i+1)
  end
end

file_contents.each {|line| output_file.puts line}