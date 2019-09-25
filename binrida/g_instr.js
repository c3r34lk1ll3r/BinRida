//Instrument address
//CallBack onEnter instruction

function onEnter(context){
    //INSERT CODE HERE
};

Process.setExceptionHandler(function(args){
if(args.type == 'breakpoint'){
    onEnter(args.context);
    args.context['pc'] = b_hooking[args.address.sub(1)];
    return true;
}
console.log(args.type)
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
        var skip = 0;
        i = Instruction.parse(p)
        mem_b = Memory.alloc(Process.pageSize);
        b_hooking[p] = mem_b;
        ret_pointer = p.add(1)
        Memory.patchCode(mem_b, 64, function(code) {
            var cw = new X86Writer(code, {pc:code});
            var dw = new X86Relocator(p, cw);
            if (skip == 0){
                dw.readOne();
                dw.writeOne();
            }
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
