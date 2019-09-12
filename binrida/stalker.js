var p = ptr('ADDRESS');
Interceptor.attach(p, {
    onEnter: function(args){
        console.log('Starting stalking...');
        console.log(Process.getCurrentThreadId());
        Stalker.follow(Process.getCurrentThreadId(),{
            events:{
                call:   true,
                ret:    false,
                exec:   false,
                block:  true,
                compile:true
            },
            onReceive: function(data) {
                send(Stalker.parse(data));
            }
        });
        console.log('STALKER!');
    },
    onLeave: function(args){ console.log('Instrumented!');}
});

