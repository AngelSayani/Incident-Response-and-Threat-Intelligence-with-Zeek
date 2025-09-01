#!/bin/bash
# Setup script to ensure expected files and logs exist for the lab

# Create extract_files directory with  extracted files
mkdir -p /home/ubuntu/zeek_analysis/extract_files
cd /home/ubuntu/zeek_analysis/extract_files

# Create the actual extracted file 
echo "MZ" | xxd -r -p > extract-1756653817.607456-HTTP-FsiSqI1WLLlY9GyLV5

cd /home/ubuntu/zeek_analysis

# Create a proper files.log 
cat > files.log << 'FILESLOG'
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	files
#open	2025-08-31-14-00-00
#fields	ts	fuid	tx_hosts	rx_hosts	conn_uids	source	depth	analyzers	mime_type	filename	duration	local_orig	is_orig	seen_bytes	total_bytes	missing_bytes	overflow_bytes	timedout	parent_fuid	md5	sha1	sha256	extracted	extracted_cutoff	extracted_size
#types	time	string	set[addr]	set[addr]	set[string]	string	count	set[string]	string	string	interval	bool	bool	count	count	count	count	bool	string	string	string	string	string	bool	count
1756652095.126649	FsiSqI1WLLlY9GyLV5	192.168.1.75	185.220.101.50	CuKFds3dfSNJC2k5Xa	HTTP	0	MD5,SHA256,EXTRACT	application/x-dosexec	-	0.100000	F	F	10240	10240	0	0	F	-	9ce3bb74469869d10b50d343edef600e	aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d	30b045a7d9e09570072999e1cdef0e00cc1add72a0db594057b19ccdba686d04	extract-1756653817.607456-HTTP-FsiSqI1WLLlY9GyLV5	F	10240
#close	2025-08-31-14-00-00
FILESLOG

# Ensure proper notice.log 
cat > notice.log.full << 'NOTICELOG'
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	notice
#open	2025-08-31-14-00-00
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	fuid	file_mime_type	file_desc	proto	note	msg	sub	src	dst	p	n	peer_descr	actions	email_dest	suppress_for	remote_location.country_code	remote_location.region	remote_location.city	remote_location.latitude	remote_location.longitude
#types	time	string	addr	port	addr	port	string	string	string	enum	enum	string	string	addr	addr	port	count	string	set[enum]	set[string]	interval	string	string	string	double	double
1756652095.100000	-	192.168.1.100	-	-	-	-	-	-	-	PortScan::Vertical_Port_Scan	Vertical port scan detected from 192.168.1.100 (scanned 15 different ports)	-	192.168.1.100	-	-	-	-	Notice::ACTION_LOG	(empty)	3600.000000	-	-	-	-	-
1756652095.110000	-	203.0.113.50	-	-	-	-	-	-	-	CorrelationRules::SSH_Brute_Force_Attack	SSH brute force detected from 203.0.113.50 after 5 failures	-	203.0.113.50	-	-	-	-	Notice::ACTION_LOG	(empty)	3600.000000	-	-	-	-	-
1756652095.120000	-	198.51.100.15	-	192.168.1.80	80/tcp	-	-	-	tcp	ProtocolAnomaly::Protocol_Mismatch	Plain HTTP on HTTPS port 443/tcp	-	198.51.100.15	192.168.1.80	443/tcp	-	-	Notice::ACTION_LOG	(empty)	3600.000000	-	-	-	-	-
1756652095.126649	-	-	-	-	-	-	-	-	-	ProtocolAnomaly::Missing_HTTP_Headers	HTTP/1.1 request missing Host header	-	-	-	-	-	-	Notice::ACTION_LOG	(empty)	3600.000000	-	-	-	-	-
1756652095.127660	-	-	-	-	-	-	-	-	-	ProtocolAnomaly::Missing_HTTP_Headers	HTTP request missing User-Agent header	-	-	-	-	-	-	Notice::ACTION_LOG	(empty)	3600.000000	-	-	-	-	-
1756652095.128701	-	-	-	-	-	-	-	-	-	ProtocolAnomaly::Suspicious_DNS_Query	Unusually long DNS query: 68 characters	-	-	-	-	-	-	Notice::ACTION_LOG	(empty)	3600.000000	-	-	-	-	-
1756652095.131010	-	-	-	-	-	-	-	-	-	ProtocolAnomaly::Suspicious_DNS_Query	DNS label exceeds normal length: a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6	-	-	-	-	-	-	Notice::ACTION_LOG	(empty)	3600.000000	-	-	-	-	-
1756652095.131507	-	-	-	-	-	-	-	-	-	ProtocolAnomaly::Suspicious_DNS_Query	Possible hex-encoded DNS query detected	-	-	-	-	-	-	Notice::ACTION_LOG	(empty)	3600.000000	-	-	-	-	-
1756652095.131862	-	192.168.1.100	-	-	-	-	-	-	-	CorrelationRules::Multi_Stage_Attack	Multi-stage attack detected from 192.168.1.100: port_scan exploitation_attempt	-	192.168.1.100	-	-	-	-	Notice::ACTION_LOG	(empty)	3600.000000	-	-	-	-	-
1756652095.131862	-	185.220.101.50	-	192.168.1.75	-	-	-	-	-	CorrelationRules::C2_Communication_Pattern	Regular beacon pattern detected from 192.168.1.75 to 185.220.101.50	-	192.168.1.75	185.220.101.50	-	-	-	Notice::ACTION_LOG	(empty)	3600.000000	-	-	-	-	-
1756652095.140000	-	185.220.101.50	-	192.168.1.75	-	FsiSqI1WLLlY9GyLV5	application/x-dosexec	-	-	MalwareDetection::Known_Malware_Hash	Known malware detected! Hash: 9ce3bb74469869d10b50d343edef600e	-	-	-	-	-	-	Notice::ACTION_LOG	(empty)	3600.000000	-	-	-	-	-
1756652095.141000	-	185.220.101.50	-	192.168.1.75	-	FsiSqI1WLLlY9GyLV5	application/x-dosexec	malware.exe	-	SuspiciousFiles::Suspicious_File_Type	Suspicious file type detected: malware.exe	-	-	-	-	-	-	Notice::ACTION_LOG	(empty)	3600.000000	-	-	-	-	-
#close	2025-08-31-14-00-00
NOTICELOG

# Function to merge notice logs preserving all entries
merge_notices() {
    if [ -f notice.log ]; then
        # Keep existing notices and add new ones
        grep -v "^#" notice.log > /tmp/existing_notices.tmp 2>/dev/null || true
        grep -v "^#" notice.log.full > /tmp/full_notices.tmp 2>/dev/null || true
        
        # Get header from full log
        grep "^#" notice.log.full > notice.log.new
        
        # Combine unique notices
        cat /tmp/existing_notices.tmp /tmp/full_notices.tmp 2>/dev/null | sort -u >> notice.log.new
        
        # Add close tag
        echo "#close	2025-08-31-14-00-00" >> notice.log.new
        
        mv notice.log.new notice.log
        rm -f /tmp/existing_notices.tmp /tmp/full_notices.tmp
    else
        cp notice.log.full notice.log
    fi
}

# Apply the merge
merge_notices

# Clean up
rm -f notice.log.full

# Set proper permissions
chown -R ubuntu:ubuntu /home/ubuntu/zeek_analysis/
