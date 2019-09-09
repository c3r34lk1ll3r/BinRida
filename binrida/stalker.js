var p = ptr('ADDRESS');
Interceptor.attach(p, {
    onEnter: function(args){
        Stalker.follow(Process.getCurrentThreadId(),{
            events:{
                call:   false,
                ret:    false,
                exec:   false,
                block:  true,
                compile:true
            },
            onReceive: function(data) {
                send(Stalker.parse(data));
            }
        })
    }
});
