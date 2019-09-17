//Instrument address
//CallBack onEnter instruction

function onEnter(args){
    //INSERT CODE HERE
};

Process.setExceptionHandler(function(args){
console.log(args.type)
if(args.type == 'breakpoint'){
    onEnter(args); 
    args.context['pc'] = b_hooking[args.address.sub(1)];
    return true;
}
console.log('Indirizzo '+args.address)
return false
});

var b_hooking = {}
var hook_func;
hook_func = ptr("ADDRESS");

Interceptor.attach(hook_func, {
    onEnter: function(args) {
        //Change HERE!
        //var p=ptr
        var index;
        var p;
        var i;
        var size;
        var addr;
        var ret_pointer;
        var cw;
        var mem_b;
        console.log("Instrument basic block "+p+" with BREAKPOINT");
        i = Instruction.parse(p)
        mem_b = Memory.alloc(Process.pageSize);
        b_hooking[p] = mem_b;
        ret_pointer = p.add(1)
        console.log("Mem stub: "+mem_b+" should return to "+ret_pointer);
        Memory.patchCode(mem_b, 64, function(code) {
            var cw = new X86Writer(code, {pc:code});
            var dw = new X86Relocator(p, cw);
            dw.readOne();
            dw.writeOne();
            cw.putJmpAddress(ret_pointer);
            cw.flush();
        });
        Memory.patchCode(p, 64, function(code) {
            cw = new X86Writer(code, {pc: code})
            cw.putBreakpoint(); 
            cw.putNopPadding(i.size-1);
        });
    }
});
