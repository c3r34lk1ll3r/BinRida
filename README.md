# BinRida (v0.9)
Author: **Andrea Ferraris**

_This plugin allows to stalk, dump and instrument a process using Frida functionalities._
## Description:
This plugin enables a Binary Ninja user to use Frida features to speed up the reverse engineering.

 To install this plugin, navigate to your Binary Ninja plugins directory, and run
```
 git clone https://github.com/bowline90/BinRida.git

```

 ## Usage:

This plugin will add three new commands in the Binary Ninja GUI:
 * `BINRIDA: Dump context of this function`: this command allows to dump various information about the runtime environment. It hooks the selected function and dump the following information:
 * `Depth`: this value is the recursion of the function;
 * `Callee function`: the callee function and the relative module;
 * `Register`: Value of the register entering (and before leaving) the function;
 * `Memory Mappings`: The virtual memory map of the process;
 * `Module Mapping`: The list of module mapped (with the address).
 * `BINRIDA: Instrument this address`: this command allows to instrument one specific address. We can write our custom code inside `frida script` form. Consider that this code will be executed inside an `Interceptor.attach(p, {` statment.
For example, we can write:
```
 onEnter: function(args) { send('Entering...');},
 onLeave: function(args) { send('Leaving...');}
```
 You can use write and use the Javascript Frida API 
 `BINRIDA: Stalk program execution`: this command allows to _stalk_ the program execution. It highlights the basic block executed, you can execute this command many time with different colors to track the different executed path.

## Frida settings:
 Each command will prompt a form for define various settings. There is a _common_ area that specify how connect to process.
 `Device`: setting the frida device (`local`, `tcp`, ecc.) 
 `Application`: this is the program that Frida will spawn. The default application is the same opened in Binary Ninja but it is possible to specify another application (for example if you are reversing a shared library). The address are automatic rebased in the new process map. 
 * `Command line`: the command line arguments passed (default no one). 
 * `Execution mode`: spawn a new process or attach to an exist one 
 * `PID`: in _attach_ mode, this is the PID of the process 

 In the _stalk program exection_ command you should also set the function to intercept and start the stalking. 

 If you want to communicate with the program you can use `frida-server` and set `TCP` as device.

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
