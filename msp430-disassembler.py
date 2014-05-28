#!/usr/bin/python

import mmap
import sys

class StreamWrapper(object):
  def __init__(self, stream):
    self.stream = stream
    self.read_buffer = []
  def read(self, num_bytes):
    rv = self.stream.read(num_bytes)
    self.read_buffer.append(rv)
    return rv
  def dump_buffer(self):
    rv = self.read_buffer
    self.read_buffer = []
    return rv

def regname(reg):
  if reg == 0: return 'PC'
  elif reg == 1: return 'SP'
  elif reg == 2: return 'SR'
  elif reg == 3: return 'CG'
  else: return "R" + str(reg)

def hexstr(raw):
  return ''.join("{:02X}".format(ord(c)) for c in raw)

def wordval(raw):
  return (ord(raw[1]) << 8) + ord(raw[0])

def jmpoffset(word):
  rv = word & 511
  if (word >> 9) & 1:
    rv = rv - 512
  return rv * 2 + 2

jmp_conditions = {
  0b000: 'jnz',
  0b001: 'jz',
  0b010: 'jnc',
  0b100: 'jn',
  0b101: 'jge',
  0b110: 'jl',
  0b111: 'jmp',
}

single_operand = {
  0b0000: 'rrc',
  0b0001: 'rrc.b',
  0b0010: 'swpb',
  0b0100: 'rra',
  0b0101: 'rra.b',
  0b0110: 'sxt',
  0b1000: 'push',
  0b1001: 'push.b',
  0b1010: 'call',
  0b1100: 'reti',
}

double_operand = {
  0b0100: 'mov',
  0b0101: 'add',
  0b0110: 'addc',
  0b0111: 'subc',
  0b1000: 'sub',
  0b1001: 'cmp',
  0b1010: 'dadd',
  0b1011: 'bit',
  0b1100: 'bic',
  0b1101: 'bis',
  0b1110: 'xor',
  0b1111: 'and',
}


def decode_addr(As, reg, stream):
  # constant values
  if reg == 2:  # SP (CG1)
    if As == 1:
      addr = wordval(stream.read(2))
      return "&%s" % hex(addr)
    elif As == 2: return '#4'
    elif As == 3: return '#8'
  elif reg == 3:  # R3 (CG2)
    if As == 0: return '#0'
    elif As == 1: return '#1'
    elif As == 2: return '#2'
    elif As == 3: return '#-1'

  if As == 0:
    # register mode
    return regname(reg)
  elif As == 1:
    # indexed, symbolic, absolute mode
    addr = wordval(stream.read(2))
    return "%s(%s)" % (hex(addr), regname(reg))
  elif As == 2:
    return "@R%s" % reg  # indirect mode
  elif As == 3:
    if reg == 0:  return "#%s" % hex(wordval(stream.read(2)))  # equivalent to @PC+
    else: return "@%s+" % regname(reg)  # autoincrement
  else:
    raise Exception("unknown instruction, As %s" % As)


def print_insn(cnt, words, op, addr1, addr2=None):
  words = ' '.join(map(hexstr, words))
  rv = "{cnt:7X}: {words:14} {op:6} {addr1}".format(cnt=cnt, words=words, op=op, addr1=addr1)
  if addr2:
    rv += ", {addr2}".format(addr2=addr2)
  print rv
  return rv


def disassemble(stream, depth=None):
  insn_count = 0

  while True:
    raw_word = stream.read(2)
    if raw_word == '':
      break
    ins = wordval(raw_word)
 
    if (ins >> 10) == 0b000100:
      # single-operand arithmetic
      opcode = (ins >> 6) & 0b1111
      As = (ins >> 4) & 0b11
      src = ins & 0b1111
     
      print_insn( 
        cnt=insn_count,
        op=single_operand[opcode],
        addr1=decode_addr(As, src, stream),
        words=stream.dump_buffer()
      )

    elif (ins >> 13) == 0b001:
      # conditional jump
      cond = (ins >> 10) & 0b111
      print_insn(
        cnt=insn_count,
        op=jmp_conditions[cond],
        addr1="{:+X}".format(jmpoffset(ins)),
        words=stream.dump_buffer()
      )
    else:
      # two-operand arithmetic
      opcode = ins >> 12
      src = (ins >> 8) & 0b1111
      Ad = (ins >> 7) & 0b1
      Bw = (ins >> 6) & 0b1
      As = (ins >> 4) & 0b11
      dst = ins & 0b1111

      opname = double_operand[opcode]
      print_insn( 
        cnt=insn_count,
        op=opname + ".b" if Bw else opname,
        addr1=decode_addr(As, src, stream),
        addr2= decode_addr(Ad, dst, stream),
        words=stream.dump_buffer()
      )

    if insn_count == depth:
      break
    insn_count += 1

if __name__ == '__main__':
  import argparse
  parser = argparse.ArgumentParser()
  parser.add_argument('tracefile', help='instruction trace file')
  parser.add_argument("--depth", help='terminate disassembly at depth', type=int)
  args = parser.parse_args()
  
  with open(args.tracefile, 'r') as f:
    m = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
    disassemble(StreamWrapper(m), depth=args.depth)

