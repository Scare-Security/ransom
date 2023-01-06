# ransom
Basic Ransomware in Nim  
> For learning purpose only

# usage
```
ransom e [path] [ip] [port]
ransom d [path] [key]
```
- **the key will be sent in plain text to the server**

# how
For each file, the ransom will generate a new key using the master key generated.  
```
KDF(masterKey, filename, filesize) = AES(masterkey, SHA(filename & $(filesize))
```

# TODO
- [X] use thread depending on the size of the file
- [ ] send the key to the server via DNS
- [ ] encrypt the key before sending to the server
- [ ] add the filename + size in the file just in case
