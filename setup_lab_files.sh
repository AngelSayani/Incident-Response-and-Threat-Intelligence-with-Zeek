#!/bin/bash
# Setup script

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

# Function to add file-related notices to notice.log
add_file_notices() {
    # Check if notice.log exists
    if [ -f notice.log ]; then
        # Check if file-related notices already exist
        if ! grep -q "MalwareDetection::Known_Malware_Hash" notice.log 2>/dev/null; then
            # Remove the closing line temporarily
            grep -v "^#close" notice.log > notice.log.tmp
            
            # Add the file-related notices
            echo "1756652095.140000	-	185.220.101.50	-	192.168.1.75	-	FsiSqI1WLLlY9GyLV5	application/x-dosexec	-	-	MalwareDetection::Known_Malware_Hash	Known malware detected! Hash: 9ce3bb74469869d10b50d343edef600e	-	-	-	-	-	-	Notice::ACTION_LOG	(empty)	3600.000000	-	-	-	-	-" >> notice.log.tmp
            
            # Re-add the closing line
            echo "#close	2025-08-31-14-00-00" >> notice.log.tmp
            
            # Replace the original file
            mv notice.log.tmp notice.log
        fi
        
        if ! grep -q "SuspiciousFiles::Suspicious_File_Type" notice.log 2>/dev/null; then
            # Remove the closing line temporarily
            grep -v "^#close" notice.log > notice.log.tmp
            
            # Add the suspicious file type notice
            echo "1756652095.141000	-	185.220.101.50	-	192.168.1.75	-	FsiSqI1WLLlY9GyLV5	application/x-dosexec	malware.exe	-	SuspiciousFiles::Suspicious_File_Type	Suspicious file type detected: malware.exe	-	-	-	-	-	-	Notice::ACTION_LOG	(empty)	3600.000000	-	-	-	-	-" >> notice.log.tmp
            
            # Re-add the closing line
            echo "#close	2025-08-31-14-00-00" >> notice.log.tmp
            
            # Replace the original file
            mv notice.log.tmp notice.log
        fi
    fi
}

# Apply the file notice additions
add_file_notices

# Set proper permissions
chown -R ubuntu:ubuntu /home/ubuntu/zeek_analysis/
