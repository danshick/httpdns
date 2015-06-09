import socket
import requests

class DNSQuery:
  def __init__(self, data):
    self.data=data
    self.domain=''
    
    type = (data[2] >> 3) & 15   # Opcode bits
    if type == 0:                     # Standard query
      ind=12
      len=data[ind]
      while len != 0:
        self.domain+=data[ind+1:ind+len+1].decode('UTF-8')+'.'
        ind+=len+1
        len=data[ind]

  def response(self, auth_token):
    packet= b''
    if not self.domain:
      return packet
    if(self.domain[-5:] == ".lan."):
      self.domain = self.domain[:-5]
    #print(self.domain);
    s = requests.Session();
    ip = s.post('http://209.141.61.214/api/dns', data='{"domain":"'+ self.domain +'"}', headers={'Authorization':auth_token})
    if(ip.status_code != 200):
      #print(ip.text);
      return packet
    ip = ip.text
    #print(ip)
    packet+=self.data[:2] + b'\x81\x80'
    packet+=self.data[4:6] + self.data[4:6] + b'\x00\x00\x00\x00'   # Questions and Answers Counts
    packet+=self.data[12:]                                         # Original Domain Name Question
    packet+= b'\xc0\x0c'                                             # Pointer to domain name
    packet+= b'\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04'             # Response type, ttl and resource data length -> 4 bytes
    packet+= bytes(list(map(lambda x: int(x), ip.split('.')))) # 4bytes of IP
    return packet

if __name__ == '__main__':
  
  uname = input("Enter your username: ");
  passwd = input("Enter your password: ");
  s = requests.Session();
  auth_token = s.post('http://209.141.61.214/api/login', data='{"username":"'+ uname +'", "password":"'+ passwd +'"}').text
  ip='192.168.1.1'
  print('pymindfakeDNS:: dom.query. 60 IN A ', ip)
  
  udps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  udps.bind(('',53))
  
  try:
    while 1:
      try:
        data, addr = udps.recvfrom(1024)
        p=DNSQuery(data)
        res = p.response(auth_token)
        udps.sendto(res, addr)
        #print('Response: ', p.domain, ' -> ', ip)
      except Exception as e:
        #print("Some UDP error occured.");
        pass;
  except KeyboardInterrupt:
    print('Finished!')
    udps.close()
