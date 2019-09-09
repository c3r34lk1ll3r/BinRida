'''
binrida.py - Highlight the executed block using Frida

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

def start_stalking(bv):
    colors      = [bn.HighlightStandardColor.BlueHighlightColor, bn.HighlightStandardColor.CyanHighlightColor, 	bn.HighlightStandardColor.GreenHighlightColor,bn.HighlightStandardColor.MagentaHighlightColor, bn.HighlightStandardColor.OrangeHighlightColor, bn.HighlightStandardColor.RedHighlightColor, bn.HighlightStandardColor.WhiteHighlightColor,bn.HighlightStandardColor.YellowHighlightColor]
    f_colors    = bn.ChoiceField('Highlight color\t',[ a.name for a in colors])
    f_funct     = bn.ChoiceField('Intercept function\t',[a.name for a in bv.functions])
    extra_settings = [f_colors, f_funct]
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
        data['entry']   = bv.functions[f_funct.result].start
        stalker = FridaHandler(data,bv.file.original_filename,spawn,'stalk')
        stalker.start()
        bn.show_message_box('Frida stalking','Press OK button to terminate stalking')
        stalker.cancel()
        stalker.join()
        colorize(data,colors[f_colors.result],bv)    

def start_dump(bv,funct):
    ret,settings    = SettingsGUI(bv)
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
        data['entry']   = funct.start
        stalker = FridaHandler(data,bv.file.original_filename,spawn,'dump')
        stalker.start()
        bn.show_message_box('Frida stalking','Press OK button to terminate stalking')
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
        data['entry'] = address
        data['script'] = f_script.result
        stalker = FridaHandler(data,bv.file.original_filename,spawn,'instr')
        stalker.start()
        bn.show_message_box('Frida stalking','Press OK button to terminate stalking')
        stalker.cancel()
        stalker.join()
