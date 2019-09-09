var p = ptr(ADDRESS);

Interceptor.attach(p, {
  onEnter: function (args) {
    var data = {}
    data['action']  = 'enter';
    data['context'] = this.context;
    data['return']  = this.returnAddress;
    data['depth']   = this.depth;
    data['threadId']= this.threadId;
    data['memMaps'] = Process.enumerateRanges('---')
    send(data)
  },
  onLeave: function (result) {
    var data = {}
    data['action']  = 'leave';
    data['memMaps'] = Process.enumerateRanges('---')
    data['context'] = this.context;
    send(data)
  }
})
