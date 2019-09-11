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
import frida
import time
import os.path
class FridaHandler(bn.BackgroundTaskThread):
    def __init__(self,data,bnFile,spawn,action):
        bn.BackgroundTaskThread.__init__(self, "Stalking with Frida...", True)
        self.data       = data
        self.base       = 0
        self.end        = 0
        self.rebase     = False
        self.respawn    = spawn
        self.bnFile     = bnFile
        self.action     = action
    def run(self):
        ## TODO: Handling frida error
        if self.respawn:
            pid = self.data['device'].spawn(self.data['execute'])
        else:
            pid = self.data['pid']
        bn.log.log_info('Process '+str(self.data['execute'])+' has PID '+str(pid))
        process = self.data['device'].attach(pid)

    
        ## I am not sure that there is no other way
        bn.log.log_debug('Retrieving mappings')
        maps_script = 'send(Process.enumerateModules())'
        script = process.create_script(maps_script)
        script.on('message', self.mappings)
        script.load()

        ## This should be done with a sync mechanism
        bn.log.log_debug('Waiting 1 seconds for data')
        time.sleep(1)
        bn.log.log_info('Mapping:'+hex(self.base)+' - '+hex(self.end));
        
        path = bn.user_plugin_path()+'/BinRida/binrida/'
        if not os.path.isfile(path+'stalker.js'):
            path = bn.bundled_plugin_path()+'/BinRida/binrida/'
            if not os.pth.isfile(path+'stalker.js'):
                bn.log.log_error('Javascript code not found!')
                return

        #If we want to stalker
        if self.action == 'stalk':
            stalk = open(path+'stalker.js').read()
            callback = self.stalked
        elif self.action == 'dump':
            stalk = open(path+'dumper.js').read()
            callback = self.dump
        elif self.action == 'instr':
            stalk ='''
var p = ptr('ADDRESS');
Interceptor.attach(p, {
'''
            stalk += self.data['script']
            stalk += '});'

            callback = self.instr
        if self.data['entry'] >= self.base and self.data['entry'] <= self.end:
            stalk = stalk.replace('ADDRESS',str(self.data['entry']))
            self.rebase = False
        else:
            stalk = stalk.replace('ADDRESS',str(self.base+self.data['entry']))
            self.rebase = True
        bn.log.log_info("Executed instrumentation script:\n"+stalk)

        script = process.create_script(stalk)
        script.on('message',callback)
        script.load()
        
        if self.respawn:
            self.data['device'].resume(pid)
        
        
        ## Waiting the stop
        while True:
            if self.cancelled == True:
               break
            time.sleep(1) 
        try:
            self.data['device'].kill(pid)
        except frida.ProcessNotFoundError:
            bn.log.log_info('Process already finished')
        return
    def instr(self,message,payload):
        bn.log.log_info(str(message))
    def dump(self,message,payload):
        bn.log.log_info("Data Received!")
        try:
            self.data['dump'].append(message['payload'])
        except KeyError as e:
            bn.log.log_error('ERROR!  Dump message:\n'+str(message))
    def mappings(self,message,payload):
        appName = self.bnFile.split('/')[-1]
        #print(appName)
        for i in message['payload']:
            i['base'] = int(i['base'],16)
            i['end']  = i['base']+i['size']
            self.data['maps'].append(i)
            if i['name'] == appName:
                self.base = i['base']
                self.end = i['end']
    def stalked(self,message,payload):
        bn.log.log_info('DATA RECEIVED')
        try:
            for i in message['payload']:
                i[1] = int(i[1],16)
                i[2] = int(i[2],16)
                if i[1] >= self.base and i[2] <= self.end:
                    if self.rebase:
                        i[1] = i[1] - self.base
                        i[2] = i[2] - self.base
                    self.data['blocks'].append(i)    
        except KeyError as e:
            bn.log.log_error('ERROR! Dump message\n'+str(message))
