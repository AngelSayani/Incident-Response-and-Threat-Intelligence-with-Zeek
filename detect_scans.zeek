@load base/frameworks/notice

module PortScan;

export {
    redef enum Notice::Type += {
        Port_Scan_Detected,
        Multiple_Ports_Scanned
    };
    
    # Track scan attempts per source
    global scan_attempts: table[addr] of set[port] &create_expire=5min;
    global scan_threshold = 10 &redef;
}

event connection_attempt(c: connection)
{
    # Check for failed connection attempts
    if ( c$history == "S" || c$history == "Sr" || c$conn$conn_state == "S0" )
    {
        local src = c$id$orig_h;
        local dst_port = c$id$resp_p;
        
        # Initialize tracking for new scanner
        if ( src !in scan_attempts )
            scan_attempts[src] = set();
        
        # Add this port to the set of scanned ports
        add scan_attempts[src][dst_port];
        
        # Check if threshold exceeded
        if ( |scan_attempts[src]| == scan_threshold )
        {
            NOTICE([$note=Port_Scan_Detected,
                    $msg=fmt("Port scan detected from %s (scanned %d ports)", src, |scan_attempts[src]|),
                    $src=src,
                    $identifier=cat(src)]);
        }
        
        # Also generate per-attempt notices for visibility
        if ( |scan_attempts[src]| > 1 && |scan_attempts[src]| < 5 )
        {
            NOTICE([$note=Multiple_Ports_Scanned,
                    $msg=fmt("Multiple port scan attempts from %s to port %s", src, dst_port),
                    $src=src,
                    $conn=c]);
        }
    }
}

event zeek_done()
{
    # Final summary of scanning sources
    for ( src in scan_attempts )
    {
        if ( |scan_attempts[src]| >= scan_threshold )
        {
            print fmt("Scanner %s attempted %d different ports", src, |scan_attempts[src]|);
        }
    }
}
