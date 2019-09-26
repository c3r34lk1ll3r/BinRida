# BinRida (v1.0)
Author: **Andrea Ferraris**

_This plugin allows to stalk, dump and instrument a process using Frida functionalities._
## Description:
_BinRida_ allows to use [Frida](https://www.frida.re/) directly inside Binary Ninja. 

To install, simply navigate to your Binary Ninja plugins directory and run
```
 git clone https://github.com/bowline90/BinRida.git
```
## Usage
There are four different commands:
* _"BINRIDA: Dump context of this function"_ : retrieve various information entering and leaving a function;  
* _"BINRIDA: Instrument this address"_ : instrument this address. We can inspect or modify the status of the process during the execution of that specific instruction;
* _"BINRIDA: Stalk function execution"_ : stalk this specific function;
* _"BINRIDA: Stalk program execution"_ : stalk all the functions.

## Frida Settings
Each command will prompt a form for define various settings. There is a _common_ area that specify how connect _Frida_ to the process:
 * _Device_: setting the frida device (_local_, _tcp_, ecc.);
 * _Application_: this is the program that _Frida_ will spawn. The default application is the same opened in Binary Ninja but it is possible to specify another application (for example, if you are reversing a shared library). The address are automatic rebased in the new process map;
 * _Command line_: the command line arguments passed (default no one);
 * _Execution mode_: spawn a new process or attach to an exist one;
 * _PID_: in _attach_ mode, this is the PID of the process. 

If you need to interact with the program, you can use `frida-server` and set `TCP` as device.
 In the _stalk program exection_ command you should also set the function to intercept and start the stalking. 
## Commands
### BINRIDA: Dump context of this function
This command allows to view different and, possibly, usefull information during entering and leaving the function. The _target_ function is the one opened in Binary Ninja.
#### Settings
In addition to the _Frida_ settings, we have a multi-lines field where we can put a Javascript _Frida_ code. In particular, we can use this form for retrieve the value of the arguments.
For example, we have this function:
```
int32_t  auth(char* arg1, int32_t arg2)
```
and we want to retrieve the runtime value of _arg1_ and _arg2_. We can use this commands and write the following JS code:
```
v_args['arg1'] = arg1.readCString();
v_args['arg2'] = arg2.toInt32();
```
and retrieve the runtime value in the final report. You can also use `hexdump` function.

**Note:** the code entered is executed as Frida's JS code so you can use [JS API](https://www.frida.re/docs/javascript-api/) to perform wathever you need to do (deference various pointer for example). For arguments, you can use the name defined in Binary Ninja (arg1, arg2 for example) and this will converted for Frida. `v_args` will be sended out. This code is executed during the `onEnter` callback. 

#### Output
A markdown report will be generated at the end of the stalking and contains the following information:
 * _Depth_ : this value is the recursion of the function;
 * _Callee function_ : the callee function and the relative module;
 * _Arguments_  : the output from `v_args`;
 * _Register_ : value of the register entering (and before leaving) the function;
 * _Memory Mappings_ : the virtual memory map of the process;
 * _Module Mapping_ : the list of module mapped (with the address);
 * _Return Value_ : the returned value.

### BINRIDA: Instrument this address
This command allows to instrument a single instruction. The _target_ instruction is the one selected in Binary Ninja.
#### Settings
In addition to the _Frida_ settings, we have a multi-lines field where we can put a Javascript _Frida_ code.
This command can be a bit tricky to use: our code is executed during an _Exception_ so all the thread are frozen. For example, if we want to retrieve the value of `RAX` and `RBX` we can use the following code:
```
send(context['rax']);
send(context['rbx']);
```
We can also change the value of the register:
```
context['rax'] = 10;
```
In particular, our code is executed inside an [ExceptionHandler](https://www.frida.re/docs/javascript-api/#process) and we can use the _context_ arguments. The value of `PC` is changed in a stub but you can modify it (there is no rebasing for now).
You can also skip the execution of that instruction writing `//SKIP` inside the script.
There is no formatted output: if you need one you can use the `send` function and read the results in the _log_.

**Note:** the code entered is executed as Frida's JS code so you can use [JS API](https://www.frida.re/docs/javascript-api/) to perform wathever you need to do. 

### BINRIDA: Stalk program/function execution
These two commands allow to _stalk_ the program execution: you can view the path followed by a specific execution.
#### Settings
In addition to the _Frida_ settings, you can choose the color to use to highlight the executed block. 

This commands can be usefull for tracking the executed path and search unexplored path.

**Note:** The _stalk program execution_ breaks the execution in _real world binary_ but the _stalk function execution_ seems to be fine. Moreover, I changed the _stalking method_ from the previous version: instead of using _Frida Stalker_ function I will perform various runtime memory patching inserting breakpoint to retrieve the executed address. The basic blocks are retrieved by Binary Ninja. These features have various problems...

## Dependencies: 
 - `psutil` 
 - `frida`

## Installation Instructions

### Linux

`pip install psutil frida`
## Minimum Version

This plugin requires the following minimum version of Binary Ninja:

 * 1689
"
## TODO:
- [ ] Add a no UI mode
- [ ] Form for using a different TCP server (not localhost)
- [ ] Some sort of _memory_ for settings.
- [ ] Testing in real world

## License

This plugin is released under a MIT license.
## Metadata Version

2
