//Instrument address
var p = ptr('ADDRESS');
//CallBack onEnter instruction

var onEnter = new NativeCallback(function(arg){
    var n = ptr(arg)
    var array = n.readByteArray(100);
    send('onEnter! '+hexdump(array));
},'void',['uint64']);
var onE = new NativeFunction(onEnter,"void",['uint']);
//Callback onLeave instruction
var onLeave = new NativeCallback(function(arg) {
    send('OnLeave! '+arg);
},'void',['int']);
var onL = new NativeFunction(onLeave,'void',['int'])
//Compute block size for instr
var i = Instruction.parse(p);
var addr;

var size = i.size
while (size<=16) {
    addr = i.next
    i = Instruction.parse(addr);
    size+=i.size
}
addr = i.next
console.log(addr)
console.log(size)
var ret_pointer = new NativeFunction(addr, "int",[]);



console.log('What is func???')
var d1 = Instruction.parse(onEnter)
console.log(d1);
//Testing with X86Relocator
var readed = 0;
var mem_stub = Memory.alloc(Process.pageSize);
//Memory.protect(mem_stub,Process.pageSize,'rwx');
Memory.patchCode(mem_stub, Process.pageSize, function(code){
    var cw = new X86Writer(code, {pc: code});
    var x86r = new X86Relocator(p, cw);
    //Because I want a guard!
    cw.putBreakpoint();
    //If x86 we have pushax, in arm we need to push ourself
    cw.putPushax();
    //cw.putSubRegImm('xsp', stackAlignOffset);
    //cw.putLeaRegRegOffset('rdi','xip',0);
    //cw.pusPushReg('xsp');
    //cw.putPopReg('xax');
    cw.putCallAddressWithArguments(onEnter,['rsp']);
    cw.putPopax();
    readed = x86r.readOne();
    x86r.writeOne();
    cw.putPushax();
    cw.putCallAddressWithArguments(onL,['xbx']);
    cw.putPopax();
    while (readed <= size){
        readed += x86r.readOne();
    }
    x86r.readOne();
    x86r.writeAll();
    cw.putJmpAddress(ret_pointer);
    cw.flush();
});


//DEBUG USELESS
i = 0
var dd = Instruction.parse(mem_stub);
console.log('DEBUG DATA');
while (i<100){
    console.log(dd);
    i++;
    dd = dd.next;
    dd = Instruction.parse(dd);
}
console.log(mem_stub.readByteArray(100));
console.log("Patching!");
Memory.patchCode(p, 64, function(code) {
    var loc = new X86Writer(code, {pc: code})
    loc.putJmpAddress(mem_stub)
    //loc.putCallAddress(mem_stub);
    loc.flush();
});


Process.setExceptionHandler(function(args){
console.log(args.type)
if (args.type == 'breakpoint'){
    console.log("THIS IS PATHCHING!");
    console.log("THIS IS PATHCHING!");
    console.log("THIS IS PATHCHING!");
    return true
}
console.log('Indirizzo '+args.address)
console.log('Base address '+mem_stub)
return false
});

/*
//Allocate a memory for executing code
//Instruction to instrument
var i2ins = Instruction.parse(p);
//Raw bytes for restoring
var r_i2ins = p.readByteArray(in_size.size);
var nx = in_size.next
var raw_bytes = nx.readByteArray(size-in_size.size);
var mem_stub = Memory.alloc(Process.pageSize);
Memory.protect(mem_stub, size+124, "rwx")
//Prepare the onEnter function
var stackAlignOffset = Process.pointerSize;
var cw = new X86Writer(mem_stub, {pc: mem_stub});
cw.putBreakpoint()
//X64! Save register before calling
cw.putPushax()
//cw.putSubRegImm('xsp', stackAlignOffset);
cw.putCallAddressWithArguments(onE,['xip']);
//cw.putAddRegImm('xsp', stackAlignOffset);
cw.putPopax()
cw.putBytes(instruction);
cw.putBreakpoint();
//OnLeave
cw.putPushax()
cw.putCallAddressWithArguments(onL,['xip'])
cw.putPopax()
cw.putBytes(raw_bytes);
cw.putJmpAddress(ret_pointer);
cw.flush()
*/
/*
console.log('Copying '+size+' bytes');
Memory.copy(mem_stub,p,size);
var mem_handler=mem_stub.add(size);
console.log('!!!!'+mem_handler)
var cw = new X86Writer(mem_handler, {pc: mem_handler});
cw.putBreakpoint()
var stackAlignOffset = Process.pointerSize;
cw.putSubRegImm('xsp', stackAlignOffset);
cw.putCallAddressWithArguments(func,['rip']);
cw.putAddRegImm('xsp', stackAlignOffset);
cw.putBreakpoint();
cw.putJmpAddress(ret_pointer);
//This is a guard
cw.putBreakpoint()
cw.putBreakpoint()
cw.putBreakpoint()
cw.flush();
*/
//Debugging purpose
