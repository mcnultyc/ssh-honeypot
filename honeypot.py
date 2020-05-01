
import base64
from binascii import hexlify
import os
import socket
import sys
import threading
import traceback
from queue import Queue
from pathlib import Path
import paramiko
import argparse
from paramiko.py3compat import b, u, decodebytes

# load host key from file
host_key = paramiko.RSAKey(filename="test_rsa.key")

class Server(paramiko.ServerInterface):
    
    # static member for user attempts 
    user_attempts = {} 
    
    def __init__(self):
        self.event = threading.Event() 

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        # check if user has attempted login
        if username not in self.user_attempts:
          self.user_attempts[username] = 0
        # increment number of user attempts
        self.user_attempts[username] += 1
        print("'{}' attempt # {}".format(username, self.user_attempts[username]))
        # check if user has attempted > 5 times
        if self.user_attempts[username] > 5:
          print(" * * * * * * ")
          # reset user attempts and provide access
          self.user_attempts[username] = 0
          return paramiko.AUTH_SUCCESSFUL 
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

class Shell:
   
  def __init__(self):
    self.root = "/" 
    # root node of file tree
    self.root_node = self.__create_node(self.root, None)
    # current node of session
    self.curr_node = self.root_node

  def __create_node(self, name, parent_node):
    node = {
      "name": name,           # name of directory
      "parent": parent_node,  # ref to parent dict
      "children": {}
    }
    return node

  def __get_abs_path(self, node):
    abs_path = ""
    # traverse parent nodes to root
    while node != None and node["parent"] != None:
      abs_path = node["name"] + "/" + abs_path
      node = node["parent"]
    # add root directory to path
    abs_path = self.root + abs_path
    return abs_path
      

  def __resolve_path(self, path):
    if path == ".":
      return self.curr_node
    
    tokens = path.split("/")
    
    # default relative path
    node = self.curr_node
    
    # path provided is absolute
    if tokens[0] == "":
      node = self.root_node
    
    for token in tokens:
      # ignore '.' and extra '/' in path resolution
      if token == "." or token == "":
        continue
      # resolve parent directory
      elif token == "..":
        parent = node["parent"]
        # root directory has no parent
        if parent != None:
          node = parent
      else:
        if token in node["children"]:
          node = node["children"][token]
        # path could not be resolved
        else:
          return None
    return node

  def __insert_file(self, node, name):
    # check if file already exists in directory
    if name in node["children"]:
      return None
    # create node and add as child
    node["children"][name] = self.__create_node(name, node)
    # return child node
    return node["children"][name]

  def __execute_cd(self, path):
    if path == None:
      self.curr_node = self.root_node
      return None 

    # get node from path
    node = self.__resolve_path(path)
    if node == None:
      error = "No such file or directory"
      return "cd: {path}: {error}".format(path=path, error=error)

    # update current node
    self.curr_node = node 
    return None
  
  def __execute_ls(self, path=None):
    if path != None:
      # get node from path
      node = self.__resolve_path(path)
      if node == None:
        error = "No such file or directory"
        return "ls: cannot access '{path}': {error}".format(path=path, error=error)
      else:
        return " ".join(node["children"].keys())
    # use current node 
    return " ".join(self.curr_node["children"].keys())

  def __execute_mkdir(self, path):
    # check for missing argument
    if path == None:
      return "mkdir: missing operand"

    error_format = "mkdir: cannot create directory '{}': {}"

    posix_path = Path(path)
    # get name of file being created
    name = str(posix_path.name)
    # get path without file
    parent_path = str(posix_path.parent)
    # attempt to create root directory
    if name == "" and parent_path == "/":
      error = "File exists"
      return error_format.format(path, error)
    # get node from path
    node = self.__resolve_path(parent_path)
    if node == None:
      error = "No such file or directory"
      return error_format.format(path, error)
    
    # get child node of inserted file
    child = self.__insert_file(node, name)
    if child == None:
      error = "File exists"
      return error_format.format(path, error)
    return None

  def get_curr_dir(self):
    # get absolute path of current node
    abs_path = self.__get_abs_path(self.curr_node)
    return abs_path

  def execute_command(self, command):
    # ignore blank input
    if command.strip() == "":
      return ""
    
    tokens = command.strip().split()
    # get executable
    exe = tokens[0]
    path = None    

    # get path
    if len(tokens) > 1:
      path = tokens[1]

    # execute corresponding command 
    if exe == "ls":
      return self.__execute_ls(path)
    elif exe == "cd":
      return self.__execute_cd(path)
    elif exe == "mkdir":
      return self.__execute_mkdir(path)
    return exe + ": command not found"



def main():
  parser = argparse.ArgumentParser()
  # add required argument for port
  parser.add_argument("-p", "--port", help="ssh port", required=True)
  # parse command line arguments
  args = parser.parse_args()  
  # get ssh port
  port = int(args.port) 
  
  # now connect
  try:
      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
      sock.bind(("", port))
  except Exception as e:
      print("*** Bind failed: " + str(e))
      traceback.print_exc()
      sys.exit(1)
    
  sock.listen(100)
  while True:
    client = None
    try:
      # wait for connection from ssh clients
      client, addr = sock.accept() 
      t = paramiko.Transport(client)
      t.add_server_key(host_key)
      # create ssh server for authentication
      server = Server()
      try:
          t.start_server(server=server)
      except paramiko.SSHException:
          sys.exit(1)
      
      # wait for authentication
      chan = t.accept(20)
      if chan is None:
          t.close()
          continue
     
      # wait for client to request a shell
      server.event.wait(10)
      if not server.event.is_set():
          print("*** Client never asked for a shell.")
          sys.exit(1)
      # set 60 second timeout for channel
      chan.settimeout(60)
      # create honeypot shell
      sh = Shell()
      prompt_format = t.get_username()+"@localhost:{}$ "
      while True: 
        # get the current directory 
        path = sh.get_curr_dir()
        # display prompt
        chan.send(prompt_format.format(path))        
        f = chan.makefile("rU")
        try:
          # read command from user
          command = f.readline().strip("\r\n")
        except socket.timeout:
          break
        if command == "exit":
          break
        # execute command
        output = sh.execute_command(command) 
        # send output from command to user
        if output != None:
          chan.send(output+"\r\n")
      t.close()
    except KeyboardInterrupt:
      # close connection
      if client != None:
        client.close()
      break




if __name__ == "__main__":
  main()






  
