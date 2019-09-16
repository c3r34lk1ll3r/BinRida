'''
binrida.py - Stalk,dump and instrumentation with Frida

Copyright (c) 2019 Andrea Ferraris

Permission is hereby granted, free of charge, to any person obtaining a
copy of this software and associated documentation files (the "Software"),
to deal in the Software without restriction, including without limitation
the rights to use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
'''
import binaryninja as bn
import binrida as brida
import sys

#bn.PluginCommand.register_for_function('BINRIDA: Stalk function execution', 'Stalk the basic block of this function', brida.start_stalk_f)
bn.PluginCommand.register_for_function('BINRIDA: Stalk program execution', 'Stalk the process with Frida', brida.start_stalking)
#bn.PluginCommand.register_for_function('BINRIDA: Dump context of this function','Dump the context of this function with Frida',brida.start_dump)
#bn.PluginCommand.register_for_address('BINRIDA: Instrument this address','Instrument this address with Frida',brida.start_instrumentation)
