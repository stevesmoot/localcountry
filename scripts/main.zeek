# Use local info for connection locations, use nets.in to assign addresses
# (note you can overide Maxmind with this if desired)

module LOCALCO;

type Idx: record {
    ips: subnet;
    };
type Val: record {
    name:string;
    };

global nets: table[subnet] of Val = table();
redef record Conn::Info += {
    orig_cc:string &log &optional; 
    resp_cc:string &log &optional;
    };

# label what we can
event connection_state_remove(c: connection)
    {
    if ( c$id$orig_h in nets )
      c$conn$orig_cc = nets[c$id$orig_h]$name;
    if ( c$id$resp_h in nets )
      c$conn$resp_cc = nets[c$id$resp_h]$name;
    }

event zeek_init()
    {
    Input::add_table([$source="nets.in",
        $idx=Idx, $name="nets", $destination=nets, $val=Val,
        $mode=Input::REREAD]);      
    }