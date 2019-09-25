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
import psutil
import frida
from .FridaHandler import FridaHandler
from .output import *

def SettingsGUI(bv,action=None,extra_settings=None):
    ## Frida devices enumeration
    devices     = frida.enumerate_devices()
    f_dev       = bn.ChoiceField('Device\t', [a.id for a in devices])
    ## TODO:: TCP GUI
    f_appName   = bn.TextLineField('Application\t')
    cmdLine     = bn.TextLineField('Command line\t')
    spawn       = bn.ChoiceField('Execution mode\t',['Spawn a new process', 'Attacch to PID'])
    pid         = []
    ## I don't know if it is usefull or it is a problem... for example, remote attach
    for i in psutil.process_iter(attrs=['pid','name']):
        pid.append(i.info['name']+' ('+str(i.info['pid'])+')')
    f_pid       = bn.ChoiceField('PID\t',pid)
    form        = [bn.LabelField('Frida general settings'), bn.SeparatorField(),f_dev,f_appName,cmdLine,spawn,f_pid]
    if extra_settings != None:
        form += [bn.SeparatorField(),bn.LabelField(action)] + extra_settings
    ret         = bn.interaction.get_form_input(form, 'BinRida')
    ## Global settings
    settings = {}
    if ret:
        settings['dev']  = devices[f_dev.result]
        settings['name'] = f_appName.result
        settings['pid']  = int(pid[f_pid.result].split('(')[1][:-1])
        #  0 for spawn, 1 else
        settings['spawn']= spawn.result
        settings['cmd']  = cmdLine.result
    return ret,settings

def start_stalking(bv,addr = None):
    colors      = [bn.HighlightStandardColor.BlueHighlightColor, bn.HighlightStandardColor.CyanHighlightColor, 	bn.HighlightStandardColor.GreenHighlightColor,bn.HighlightStandardColor.MagentaHighlightColor, bn.HighlightStandardColor.OrangeHighlightColor, bn.HighlightStandardColor.RedHighlightColor, bn.HighlightStandardColor.WhiteHighlightColor,bn.HighlightStandardColor.YellowHighlightColor]
    f_colors    = bn.ChoiceField('Highlight color\t',[ a.name for a in colors])
    extra_settings = [f_colors]
    ret,settings = SettingsGUI(bv,'Stalker',extra_settings)
    if ret:
        execute = bv.file.original_filename
        if settings['name'] != "":
            execute = settings['name']
        bn.log.log_info('Start \''+execute+' '+settings['cmd']+'\' on '+settings['dev'].id+' device ')
        data = {}
        ## Set the device
        data['device']  = settings['dev']
        ## Command to spawn
        data['execute'] = [execute]
        if settings['cmd'] != "":
            for i in settings['cmd'].split(' '):
                data['execute'].append(i)
        ## Spawning
        spawn           = True
        if settings['spawn'] == 1:
            data['pid'] = settings['pid']
            spawn = False
        ## Preparing block
        data['maps']    = []
        data['blocks']  = []
        data['functions'] = bv.functions if addr == None else [addr]
        stalker = FridaHandler(data,bv.file.original_filename,spawn,'stalk')
        stalker.start()
        bn.show_message_box('Frida running','Press OK button to terminate.')
        stalker.cancel()
        stalker.join()
        colorize(data,colors[f_colors.result],bv)

def start_dump(bv,funct):
    extra_settings = []
    index = 0
    for i in funct.parameter_vars:
        f = bn.LabelField('\''+i.name+'\'')
        extra_settings.append(f);
    extra_settings.append(bn.MultilineTextField('Dumping data. v_args[NAME] is printed in report'))
    ret,settings    = SettingsGUI(bv,'Dump function contents',extra_settings)
    if ret:
        execute = bv.file.original_filename
        if settings['name'] != "":
            execute = settings['name']
        bn.log.log_info('Start \''+execute+' '+settings['cmd']+'\' on '+settings['dev'].id+' device ')
        data = {}
        ## Set the device
        data['device']  = settings['dev']
        ## Command to spawn
        data['execute'] = [execute]
        if settings['cmd'] != "":
            for i in settings['cmd'].split(' '):
                data['execute'].append(i)
        ## Spawning
        spawn           = True
        if settings['spawn'] == 1:
            data['pid'] = settings['pid']
            spawn = False
        ## Preparing block
        data['dump']    = []
        data['maps']    = []
        data['functions']   = funct
        data['arguments']    = extra_settings[-1].result
        stalker = FridaHandler(data,bv.file.original_filename,spawn,'dump')
        stalker.start()
        bn.show_message_box('Frida running','Press OK button to terminate.')
        stalker.cancel()
        stalker.join()
        CreateMarkdownReport(bv,funct,data)

def start_instrumentation(bv,address):
    ## TODO: Check the instrumented instruction. Frida has problem with some instruction
    f = bv.get_functions_containing(address)
    f_function  = bn.LabelField('Container function\t'+ f[0].name)
    f_funct     = bn.LabelField('Instrumented instruction\t'+bv.get_disassembly(address))
    f_script    = bn.MultilineTextField("Frida script\t")
    extra_settings = [f_function,f_funct,f_script]
    ret,settings = SettingsGUI(bv,'Instrumentation',extra_settings)
    if ret:
        execute = bv.file.original_filename
        if settings['name'] != "":
            execute = settings['name']
        bn.log.log_info('Start \''+execute+' '+settings['cmd']+'\' on '+settings['dev'].id+' device ')
        data = {}
        ## Set the device
        data['device']  = settings['dev']
        ## Command to spawn
        data['execute'] = [execute]
        if settings['cmd'] != "":
            for i in settings['cmd'].split(' '):
                data['execute'].append(i)
        ## Spawning
        spawn           = True
        if settings['spawn'] == 1:
            data['pid'] = settings['pid']
            spawn = False
        ## Stalker data
        data['maps'] = []
        data['functions'] = [f[0].start, address]
        data['script'] = f_script.result
        stalker = FridaHandler(data,bv.file.original_filename,spawn,'instr')
        stalker.start()
        bn.show_message_box('Frida running','Press OK button to terminate.')
        stalker.cancel()
        stalker.join()
