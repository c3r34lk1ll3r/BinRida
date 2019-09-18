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
        self.path = bn.user_plugin_path()+'/BinRida/binrida/'
        if not os.path.isfile(self.path+'m_stalker.js'):
            self.path = bn.bundled_plugin_path()+'/BinRida/binrida/'
            if not os.pth.isfile(self.path+'m_stalker.js'):
                bn.log.log_error('Javascript code not found!')
                raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), self.path+'stalker.js')
    ## Rebasing address
    def rebaser(self,i):
        if i >= self.base and i <= self.end:
            reb_addr = str(i)
            self.rebase = False
        else:
            reb_addr = str(self.base + i)
            self.rebase = True
        return reb_addr;
    ## Create script for stalker
    def stalker(self):
        script = ""
        ff = open(self.path+'m_stalker.js').read();
        scr = ff.split('//CUT HERE');
        script += scr[0];
        for func in self.data['functions']:
            if func.symbol.type == bn.SymbolType.ImportedFunctionSymbol:
                continue
            s = 0
            for i in func.basic_blocks:
                s += i.length
            if s <= 16:
                bn.log.log_error('Function '+func.name+' is too little (only '+str(s)+' bytes)')
                continue
            if func.name == "_start":
                continue
            ## function length
            print(func)
            var_s = scr[1]
            address = self.rebaser(func.start);
            var_s = var_s.replace('ADDRESS',address)
            br_hooking = "var br_hooking=["
            #jmp_hooking= "var jmp_hooking=["
            for j in func.basic_blocks[1:]:
                address = self.rebaser(j.start)
                #if j.length >= 16:
                    ## jmp
                #    jmp_hooking += "ptr("+address+"),"
                #else:
                br_hooking  += "ptr("+address+"),"
            vector = ""
            if 'ptr' in br_hooking:
                vector +=br_hooking[:-1]+']\n'
            #if 'ptr' in jmp_hooking:
            #    vector +=jmp_hooking[:-1]+']'
            if vector == "":
                vector = "var br_hooking = []"
            print(vector);
            var_s =  var_s.replace('//Change HERE!',vector);
            script += var_s + '\n\n'
        return script
    def instrumentation(self):
        script = ""
        ff = open(self.path+'g_instr.js').read();
        funct = self.rebaser(self.data['functions'][0])
        base  = self.rebaser(self.data['functions'][1])
        script = ff.replace("ADDRESS",funct,1).replace("//Change HERE!","var p=ptr(\""+base+'\")')
        script = script.replace("//INSERT CODE HERE",self.data["script"]);
        return script;
    ## Callback functions
    ## For instrumenting a single instruction
    def instr(self,message,payload):
        bn.log.log_info(str(message))
        bn.log.log_info(str(payload));
    ## For dumping the function context
    def dump(self,message,payload):
        bn.log.log_info("Data Received!")
        try:
            self.data['dump'].append(message['payload'])
        except KeyError as e:
            bn.log.log_error('ERROR!  Dump message:\n'+str(message))
    ## Find the mappings
    def mappings(self,message,payload):
        appName = self.bnFile.split('/')[-1]
        print(appName)
        for i in message['payload']:
            i['base'] = int(i['base'],16)
            i['end']  = i['base']+i['size']
            self.data['maps'].append(i)
            if i['name'] == appName:
                self.base = i['base']
                self.end = i['end']
    ## For executiong stalking
    def stalked(self,message,payload):
        bn.log.log_info('DATA RECEIVED')
        print(message);
        try:
            i = message['payload']
            addr = int(i,16)
            if self.rebase:
                addr = addr - self.base
            self.data['blocks'].append(addr)    
        except KeyError as e:
            bn.log.log_error('ERROR! Dump message\n'+str(message))

    ## Thread
    def run(self):
        ## TODO: Handling frida error
        ## Spawn or attach to process 
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
        while True:
            script.load()
            ## This should be done with a sync mechanism
            bn.log.log_debug('Waiting 1 seconds for data')
            time.sleep(1)
            bn.log.log_info('Mapping:'+hex(self.base)+' - '+hex(self.end));
            if self.base != 0 and self.end != 0:
                break
            del self.data['maps'][:]
            if self.cancelled == True:
                return
        ## Different function with different script
        if self.action == 'stalk':
            v_script = self.stalker()
            callback = self.stalked
        elif self.action == 'instr':
            v_script = self.instrumentation()
            callback = self.instr 
        #elif self.action == 'stalk_f':
        #    stalk_one = open(path+'m_stalker.js').read()
        #    stalk = ""
        #    i = 0
        #    while i < len(self.data['entry']):
        #         stalk += stalk_one+'\n'
        #        i+=1
        #        break
        #    callback = self.instr
        #elif self.action == 'dump':
        #    stalk = open(path+'dumper.js').read()
        #    callback = self.dump
        #elif self.action == 'instr':
        #    stalk ='''
#var p = ptr('ADDRESS');
#Interceptor.attach(p, {
#'''
#            stalk += self.data['script']
#            stalk += '});'
#            callback = self.instr
#        for i in self.data['entry']:
#            if i.start >= self.base and i.start <= self.end:
#                stalk = stalk.replace('ADDRESS',str(i.start),0)
#                self.rebase = False
#            else:
#                stalk = stalk.replace('ADDRESS',str(self.base+i.start),1)
#                self.rebase = True
#            break
        bn.log.log_info("Executed instrumentation script:\n"+v_script)

        script = process.create_script(v_script)
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
