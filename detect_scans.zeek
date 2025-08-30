@load base/frameworks/notice
@load base/frameworks/sumstats

module PortScan;

export {
    redef enum Notice::Type += {
        Vertical_Port_Scan,
        Horizontal_Port_Scan
    };
    
    # Thresholds for detection
    const vertical_scan_threshold = 15 &redef;
    const horizontal_scan_threshold = 10 &redef;
    const scan_interval = 5min &redef;
    
    # Track scanning sources
    global scanning_sources: set[addr] &create_expire=10min;
}

event connection_attempt(c: connection)
{
    local is_failed = F;
    
    # Check for failed connection attempts
    if ( c$history == "S" || c$history == "Sr" || c$conn$conn_state == "S0" )
        is_failed = T;
    
    if ( is_failed )
    {
        # Track vertical scanning (many ports, same host)
        SumStats::observe("port_scan.vertical", 
                         SumStats::Key($host=c$id$orig_h),
                         SumStats::Observation($num=1));
        
        # Track horizontal scanning (same port, many hosts)  
        SumStats::observe("port_scan.horizontal",
                         SumStats::Key($str=cat(c$id$resp_p)),
                         SumStats::Observation($num=1));
        
        add scanning_sources[c$id$orig_h];
    }
}

event zeek_init()
{
    # Vertical scan detection
    local vertical_r1 = SumStats::Reducer($stream="port_scan.vertical",
                                          $apply=set(SumStats::SUM));
    
    SumStats::create([$name="detect_vertical_scans",
                      $epoch=scan_interval,
                      $reducers=set(vertical_r1),
                      $threshold=vertical_scan_threshold,
                      $threshold_val(key: SumStats::Key, result: SumStats::Result) =
                      {
                          return result["port_scan.vertical"]$sum;
                      },
                      $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
                      {
                          NOTICE([$note=Vertical_Port_Scan,
                                  $msg=fmt("Vertical port scan detected from %s", key$host),
                                  $src=key$host,
                                  $identifier=cat(key$host)]);
                      }]);
    
    # Horizontal scan detection
    local horizontal_r1 = SumStats::Reducer($stream="port_scan.horizontal",
                                            $apply=set(SumStats::SUM));
    
    SumStats::create([$name="detect_horizontal_scans",
                      $epoch=scan_interval,
                      $reducers=set(horizontal_r1),
                      $threshold=horizontal_scan_threshold,
                      $threshold_val(key: SumStats::Key, result: SumStats::Result) =
                      {
                          return result["port_scan.horizontal"]$sum;
                      },
                      $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
                      {
                          NOTICE([$note=Horizontal_Port_Scan,
                                  $msg=fmt("Horizontal scan detected on port %s", key$str),
                                  $identifier=key$str]);
                      }]);
}
