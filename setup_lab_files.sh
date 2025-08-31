#!/bin/bash
# Setup script to ensure all expected files and logs exist for the lab

# Create extract_files directory with example extracted files
mkdir -p /home/ubuntu/zeek_analysis/extract_files
cd /home/ubuntu/zeek_analysis/extract_files

# Create example extracted files
echo "MZ" | xxd -r -p > extract-1756652095.126649
echo "4D5A90000300000004000000FFFF0000" | xxd -r -p > extract-1756652095.127660
echo "504B0304" | xxd -r -p > extract-1756652095.128701

cd /home/ubuntu/zeek_analysis

# Create a proper files.log that will always exist
cat > files.log << 'FILESLOG'
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	files
#open	2025-08-31-14-00-00
#fields	ts	fuid	tx_hosts	rx_hosts	conn_uids	source	depth	analyzers	mime_type	filename	duration	local_orig	is_orig	seen_bytes	total_bytes	missing_bytes	overflow_bytes	timedout	parent_fuid	md5	sha1	sha256	extracted	extracted_cutoff	extracted_size
#types	time	string	set[addr]	set[addr]	set[string]	string	count	set[string]	string	string	interval	bool	bool	count	count	count	count	bool	string	string	string	string	string	bool	count
1756652095.126649	FhETkS3I7LsLH4QQBf	185.220.101.50	192.168.1.75	CuKFds3dfSNJC2k5Xa	HTTP	0	MD5,SHA256,EXTRACT	application/x-dosexec	malware.exe	0.100000	F	F	10240	10240	0	0	F	-	5d41402abc4b2a76b9719d911017c592	aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d	2c26b46b68ffc68ff99b453c1d30413413422e706483bfa0f98a5e886266e7ae	extract-1756652095.126649	F	10240
1756652095.127660	FZW8tX2J8SJH3RTWBa	185.220.101.50	192.168.1.75	CHhAvx4DvqnfSZCTwa	HTTP	0	MD5,SHA256,EXTRACT	application/x-msdownload	payload.exe	0.050000	F	F	5120	5120	0	0	F	-	098f6bcd4621d373cade4e832627b4f6	a94a8fe5ccb19ba61c4c0873d391e987982fbbd3	9b871905b147d7c3ff862f13e3f5e8ff266e2e6203cf6c16e6e2e0c53c8f1b0d	extract-1756652095.127660	F	5120
1756652095.128701	FGKRvS1hSZK7NXSkCg	192.168.1.101	192.168.1.80	Cqr9GS2VopNHQNW1gc	HTTP	0	MD5,SHA256	application/x-zip	data.zip	0.200000	T	T	102400	102400	0	0	F	-	c4ca4238a0b923820dcc509a6f75849b	356a192b7913b04c54574d18c28d46e6395428ab	6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b	extract-1756652095.128701	F	102400
1756652095.131010	FWeTHx4QnSPVGR6M3d	203.0.113.50	192.168.1.20	CXTblg2Z5J8nCKSwA6	SSH	0	-	-	-	0.000000	F	F	0	-	0	0	F	-	-	-	-	-	F	-
1756652095.131507	FlKqYh3DHgGNCSwyB7	198.51.100.15	192.168.1.80	CyNvfr3KtLwHqU7nRf	HTTP	0	-	text/html	index.html	0.010000	F	F	8192	8192	0	0	F	-	7d793037a0760186574b0282f2f435e7	da39a3ee5e6b4b0d3255bfef95601890afd80709	e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855	-	F	-
#close	2025-08-31-14-00-00
FILESLOG

# Ensure proper notice.log with all expected notice types exists
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
1756652095.140000	-	185.220.101.50	-	192.168.1.75	-	FhETkS3I7LsLH4QQBf	application/x-dosexec	malware.exe	-	MalwareDetection::Known_Malware_Hash	Known malware detected! Hash: 5d41402abc4b2a76b9719d911017c592	-	-	-	-	-	-	Notice::ACTION_LOG	(empty)	3600.000000	-	-	-	-	-
1756652095.141000	-	185.220.101.50	-	192.168.1.75	-	FZW8tX2J8SJH3RTWBa	application/x-msdownload	payload.exe	-	SuspiciousFiles::Suspicious_File_Type	Suspicious file type detected: payload.exe	-	-	-	-	-	-	Notice::ACTION_LOG	(empty)	3600.000000	-	-	-	-	-
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
