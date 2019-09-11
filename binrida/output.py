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

def colorize(data,color,bv):
    for i in data['blocks']:
        for j in bv.get_basic_blocks_at(i[1]):
            j.set_user_highlight(color)

def CreateMarkdownReport(bv,funct,data):
    ## We need a more efficient methods
    c = ""
    c += '# Dump data from `'+funct.name+'`\n'
    c += '## Information\n'
    c += '- Device: **'+data['device'].id+'**\n'
    c += '- Exec command: **`'+str(data['execute'])[1:-1]+'`**\n'
    c += '- Attached to **'+str(data['pid'])+'**' if 'pid' in data else '- **New process**'
    c += '\n'
    for i in data['dump']:
        #for j in i['memMaps']:
            #print(str(j))
        if i['action'] == 'enter':
            c += '\n\n\n## Data entering function\n'
            c += '- Depth: '+str(i['depth'])+'\n'
            mapped = ""
            value = int(i['return'],16)
            for m in data['maps']:
                if value >= m['base'] and value <= m['end']:
                    mapped = ' **('+m['name']+')**'
                    break
            c += '- Callee function: '+i['return']+mapped+'\n'
        else:
            c += '\n\n\n## Data leaving function\n'
        c += '### Context Information\n'
        c += '| Register | Value | Maps to |\n'
        c += '|:--------:|:-----:| -------:|\n'
        ct = i['context']
        if bv.arch.name == 'x86_64':
            register = ['rax','rbx','rcx','rdx','rsp','rbp','rsi','rdi','rip','r8','r9','r10','r11','r12','r13','r14','r15']
        elif bv.arch.name == 'x86':
            register = ['eax','ebx','ecx','edx','esp','ebp','esi','edi','eip']
        else:
            register = ct.keys()
        for j in register:
            value = int(ct[j],16)
            mapped = ""
            for m in data['maps']:
                if value >= m['base'] and value <= m['end']:
                    mapped = '**'+m['name']+'**' 
                    break 
            c += '| `'+j+'` | **'+ct[j]+'** | '+mapped+' |\n'
        c += "### Memory mappings\n"
        c += "| Path | Base | End  | Protection |\n"
        c += "| ---- |:----:|:----:|:----------:|\n"
        for m in i['memMaps']:
            c += '|** '+m['file']['path']+' **|' if 'file' in m else '|  |'
            c += '`'+m['base']+'`|'
            c += '`'+hex(int(m['base'],16)+m['size'])+'`|'
            c += '**'+m['protection']+'**|\n'
    c += '\n\n\n## Module Mappings\n'
    c += '| Path | Base | End | Name |\n'
    c += '|----- |:----:|:---:|:----:|\n' 
    for m in data['maps']:
        c += '|'+m['path']+'|`'+hex(m['base'])+'`|`'+hex(m['end'])+'`|**'+m['name']+'**|\n' 
    c += '\n\n\n## Raw data\n'
    c += str(data['dump']) 
    bv.show_markdown_report('Frida dump',c,"")
