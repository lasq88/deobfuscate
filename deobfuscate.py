#!/usr/bin/python

import re,sys,zlib,base64,argparse

obfuscation_methods = [
  ('replace','Replace String','replace\s?\('),
  ('decompress','Compress string','::decompress'), 
  ('split','ASCII table with split','-split'),
  ('ascii','ASCII table','\((?:\s?[0-9]{2,3}\s?,?){5,}\)')
]

def FindString(str,regx):
  match = re.compile(regx,flags=re.I)
  search = re.findall(match,str)
  return search

def StrChar(matchobj):
  return "'"+chr(int(matchobj.group(1)))+"'"

def FindReplaces(text,replacements):
  match = re.compile("replace\s*(\(|\(\(|)\\\\?'([a-zA-Z0-9]{2,4})\\\\?'(\)|),\\\\?'(.{1})\\\\?'(\)|)",flags=re.I)
  search = re.findall(match,text)
  if (search == []):
    return 0
  else:
    for i in search:
      replacements.add((i[1],i[3]))
    return replacements

def DeobfReplace(text):
  replacements = set()
  while True:
    text = re.sub("'\+'|''\+|\+''","",text)
    text = re.sub('\[char\]([0-9]{2,3})',StrChar,text,flags=re.I)
    text = re.sub("'\+'|''\+|\+''","",text)
    text = re.sub('\[string\]','',text,flags=re.I)
    if(FindReplaces(text, replacements) == 0):
      return text
    else:
      replacements = FindReplaces(text, replacements)
      for i in replacements:
        text = re.sub("'\+'|''\+|\+''","",text)
        text = text.replace(i[0],i[1])


def Detect(text):
  for (_, method, regx) in obfuscation_methods:
    match = re.compile(regx,flags=re.I)
    search = re.findall(match,text)
    if (search != []):
      return method
  if (search == []):
    return -1

def Deobfuscate(text,method):
  try:
    if (method == "Replace String"):
      return DeobfReplace(text)
    elif (method == "Compress string"):
      compressed = FindString(text,"frombase64string\(\s?'(\S*)'")[0]
      return zlib.decompress(base64.b64decode(compressed),-zlib.MAX_WBITS)
    elif (method == "ASCII table with split"):
      split_by = '|'.join(FindString(text,"split\s?'(\S)'"))
      ascii_table = re.split(split_by,FindString(text,"\('(\S*)'")[0])
      return ''.join(chr(int(i)) for i in ascii_table)
    elif (method == "ASCII table"):
      ascii_table = re.split(',',FindString(text,'\(((?:\s?[0-9]{2,3}\s?,?){5,})\)')[0])
      return ''.join(chr(int(i)) for i in ascii_table) 
  except:
    print "Unfortunately deobfuscation failed. Maybe you provided wrong method or there is no method to deobfuscate this code."
    return -1

def main():
  parser = argparse.ArgumentParser(description='Deobfuscates Emotet\'s powershell payload')
  parser.add_argument("file", type=argparse.FileType('r'), help="file with obfuscated code")
  parser.add_argument("-m", "--method",type=str, choices=['replace', 'decompress', 'split', 'ascii'], help="Specify obfuscation method")
  args = parser.parse_args()
  text = args.file.readlines()
  for line in text:
    if (args.method != None):
      for i in obfuscation_methods:
        if (i[0] == args.method):
          detected = i[1]
          print "Provided obfuscation method: " + detected
          deobfuscated_text = Deobfuscate(line,detected)
    else:
      detected = Detect(line)
      if (detected != -1):
        print "Detected obfuscation method: " + detected
        deobfuscated_text = Deobfuscate(line,detected)
      else:
        print "Obfuscation method could not be detected automatically. Try to specify deobfuscation method by using --method"
        return -1
    if (deobfuscated_text != -1):
      urls = FindString(deobfuscated_text,'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[/\-\w]+')
      print ''
      print 'Deobfuscated text: '
      print deobfuscated_text
      print ''
      print 'IoC Found: '
      for url in urls:
        print url

if __name__ == "__main__":
  main()