def CWE_23_Path_traversal
  # params - data received during a http request
  #
  # This function takes in a file name and creates a new text file in the parent directory
  #
  parent = "/path/to/parent_directory"
  Pathname.new(File.join(parent, params[:name]))
end


def sanitize_filename(filename)
  # function that sanitizes an input by ensuring it consists of only alphanumeric characters
  returning filename.strip do |name|
   name.gsub! /^.*(\\|\/)/, ''
    name.gsub!(/[^0-9A-Za-z.\-]/, 'x')
  end
end

def CWE_23_Path_traversal_mitigated
  # params - data received during a http request
  # This function takes in a file name and creates a new path in the parent directory
  parent = "/path/to/parent_directory"
  # sanitize user input
  filename = sanitize_filename(params[:name])
  Pathname.new(File.join(parent,filename))
end


def CWE_78_OS_injection
  # This function executes a command received from user
  cmd = gets
  system cmd
end

def CWE_78_OS_injection_mitigated
  # Don't allow a user to directly run a command, but only allow them to pass parameters
  cmd_params = gets
  cmd = "ls"
  # The key point is that the user input is in the second part of the Array
  # that is passed to the system function.
  # Make sure that no user input is in the first part of the Array that
  # contains the command itself.
  system(cmd,"#{cmd_params}")
end
