#!/bin/bash
# Bold
NOCOLOR='\033[0m'
BBlack='\033[1;30m'       # Black
BRed='\033[1;31m'         # Red
BGreen='\033[1;32m'       # Green
BYellow='\033[1;33m'      # Yellow
BBlue='\033[1;34m'        # Blue
BPurple='\033[1;35m'      # Purple
BCyan='\033[1;36m'        # Cyan
BWhite='\033[1;37m'       # White


folder=$(realpath $1);
if [ -f "$folder/scope.txt" ]
then

    for domain in $(cat $folder/scope.txt)
    do
        echo -e $BPurple "Recon in domain: $domain" $NOCOLOR
        echo -e $BRed "Creating directories" $NOCOLOR
        mkdir -p $folder/$domain/recon/crawlling/;
        mkdir -p $folder/$domain/recon/subdomains/;

        if [ ! -f '/home/drogas/bounty/resolvers.txt' ]
        then
            echo -e $BRed "Generate list of valid resolvers" $NOCOLOR
            dnsvalidator -tL https://public-dns.info/nameservers.txt -threads 100 -o /home/drogas/bounty/resolvers.txt
        fi
        # Horizontal Enumeration
        # Finding IPs
        echo -e $BRed "Horizontal Enumeration" $NOCOLOR
        if [ ! -f "$folder/$domain/recon/ips.txt" ]
        then
            echo -e $BBlue "Finding IPs" $NOCOLOR
            dig $domain +short > $folder/$domain/recon/ips.txt;
        fi

        if [ ! -z "$2" ]
        then
            # ANS
            echo -e $BGreen "ANS" $NOCOLOR
            whois -h whois.radb.net  -- '-i origin '$2 | grep -Eo "([0-9.]+){4}/[0-9]+" | uniq | anew -q $folder/$domain/recon/subdomains/asn_cidr.txt
            whois -h whois.arin.net  -- '-i origin '$2 | grep -Eo "([0-9.]+){4}/[0-9]+" | uniq | anew -q $folder/$domain/recon/subdomains/asn_cidr.txt

            # Parse CIDR from ASN Lookup too AMass Enum
            echo -e $BGreen "Parse CIDR from ASN Lookup too AMass Enum" $NOCOLOR
            for cidr in $(cat $folder/$domain/recon/subdomains/asn_cidr.txt)
            do
                amass enum -d $domain -cidr $cidr | anew -q $folder/$domain/recon/subdomains/sub_asn_cidr.txt
            done

            # PTR Records
            echo -e $BGreen "PTR Records" $NOCOLOR
            for cidr in $(cat $folder/$domain/recon/subdomains/asn_cidr.txt); do
                echo $cidr | mapcidr -silent | dnsx -ptr -resp-only | grep $domain | anew -q $folder/$domain/recon/subdomains/sub_ptr.txt
            done
        fi
        # Vertical enumeration
        # Passive enumeration
        echo -e $BRed "Vertical enumeration" $NOCOLOR
        echo -e $BYellow "Passive enumeration" $NOCOLOR
        echo -e $BGreen "Running Amass" $NOCOLOR
        amass enum -passive -d $domain -config $HOME/.config/amass/config.ini -o $folder/$domain/recon/subdomains/sub_amass.txt;

        echo -e $BGreen "Running Subfinder" $NOCOLOR
        subfinder -d $domain -all -config $HOME/.config/subfinder/config.yaml -o $folder/$domain/recon/subdomains/sub_subf.txt;
        # Subfinder return many subdomains starting with "-" (hyphen), then is necessary to remove them
        for line in $(cat $folder/$domain/recon/subdomains/sub_subf.txt);
        do
            if [ ${line:0:1} != '-' ]
            then
                echo $line | anew $folder/$domain/recon/subdomains/sub_subfinder.txt;
            fi
        done
        rm $folder/$domain/recon/subdomains/sub_subf.txt

        echo -e $BGreen "Running Assetfinder" $NOCOLOR
        assetfinder --subs-only $domain > $folder/$domain/recon/subdomains/sub_assetfinder.txt;

        echo -e $BGreen "Running Findomain" $NOCOLOR
        findomain -t $domain -u $folder/$domain/recon/subdomains/sub_findomain.txt;

        # Internet Archive
        echo -e $BBlue "Internet Archive" $NOCOLOR
        echo -e $BGreen "Running Gauplus" $NOCOLOR
        gauplus -t 5 -random-agent -subs $domain |  unfurl -u domains | anew $folder/$domain/recon/subdomains/sub_gauplus.txt;

        echo -e $BGreen "Running Waybackurls" $NOCOLOR
        waybackurls $domain |  unfurl -u domains | sort -o $folder/$domain/recon/subdomains/sub_waybackurls.txt;

        # Github Scraping
        echo -e $BBlue "Github Scraping" $NOCOLOR
        echo -e $BGreen "Running github-subdomains" $NOCOLOR
        github-subdomains -d $domain -t ~/tools/git_tokens.txt -o $folder/$domain/recon/subdomains/sub_github.txt;

        # Rapid7 Project Sonar dataset
        echo -e $BBlue "Rapid7 Project Sonar dataset" $NOCOLOR
        echo -e $BGreen "Running Crobat" $NOCOLOR
        crobat -s $domain > $folder/$domain/recon/subdomains/sub_crobat.txt;

        # Certificate Transparency Logs
        echo -e $BBlue "Certificate Transparency Logs" $NOCOLOR
        echo -e $BGreen "Running CTFR" $NOCOLOR
        python3 ~/tools/ctfr/ctfr.py -d $domain -o $folder/$domain/recon/subdomains/sub_ctfr.txt;
        curl "https://tls.bufferover.run/dns?q=.$domain" -H 'x-api-key: XhRdrw1j1h98VOf51qLai3NnY1c7vUbt8o4LydXK' | jq -r .Results[] | cut -d ',' -f4 | grep -F ".$domain" | anew -q $folder/$domain/recon/subdomains/sub_bufferover.txt;
        curl "https://dns.bufferover.run/dns?q=.$domain" -H 'x-api-key: XhRdrw1j1h98VOf51qLai3NnY1c7vUbt8o4LydXK' | jq -r '.FDNS_A'[],'.RDNS'[]  | cut -d ',' -f2 | grep -F ".$domain" | anew -q $folder/$domain/recon/subdomains/sub_bufferover_fdns.txt;

        # Recursive enumeration
        echo -e $BBlue "Recursive enumeration" $NOCOLOR
        sort $folder/$domain/recon/subdomains/sub_* -u > $folder/$domain/recon/subdomains/subdomains.txt; # juntar todos arquivos de subdominios gerados anteriormente em um único arquivo
        for sub in $( ( cat $folder/$domain/recon/subdomains/subdomains.txt | rev | cut -d '.' -f 3,2,1 | rev | sort | uniq -c | sort -nr | grep -v '1 ' | head -n 10 && cat $folder/$domain/recon/subdomains/subdomains.txt | rev | cut -d '.' -f 4,3,2,1 | rev | sort | uniq -c | sort -nr | grep -v '1 ' | head -n 10 ) | sed -e 's/^[[:space:]]*//' | cut -d ' ' -f 2);do 
            if [ ${sub:0:1} != '-' ]
            then
                subfinder -d $sub -all -silent | anew -q $folder/$domain/recon/subdomains/sub_subf.txt
                # Subfinder return many subdomains starting with "-" (hyphen), then is necessary to remove them
                for line in $(cat $folder/$domain/recon/subdomains/sub_subf.txt);
                    do
                        if [ ${line:0:1} != '-' ]
                        then
                            echo $line | anew $folder/$domain/recon/subdomains/sub_passive_recursive.txt;
                        fi
                    done
                rm $folder/$domain/recon/subdomains/sub_subf.txt
                assetfinder --subs-only $sub | anew -q $folder/$domain/recon/subdomains/sub_passive_recursive.txt
                amass enum -passive -d $sub | anew -q $folder/$domain/recon/subdomains/sub_passive_recursive.txt
                findomain --quiet -t $sub | anew -q $folder/$domain/recon/subdomains/sub_passive_recursive.txt
            fi
        done

        # Active Enumeration
        echo -e $BYellow "Active Enumeration" $NOCOLOR

        # DNS Bruteforcing
        echo -e $BBlue "DNS Bruteforcing" $NOCOLOR
        echo -e $BGreen "Running Puredns" $NOCOLOR
        puredns bruteforce ~/tools/seclists/Discovery/Web-Content/jhaddix_all.txt $domain -r /home/drogas/bounty/resolvers.txt --write $folder/$domain/recon/subdomains/sub_puredns.txt --write-wildcards $folder/$domain/recon/subdomains/wildcards.txt --write-massdns $folder/$domain/recon/subdomains/massdns.txt;

        # Permutation / Alterations
        echo -e $BBlue "Permutation / Alterations" $NOCOLOR
        echo -e $BGreen "Running Gotator" $NOCOLOR
        split $folder/$domain/recon/subdomains/subdomains.txt -l 100 -a 5
        for x in $(ls xa*)
        do
            gotator -sub $x -perm ~/tools/seclists/Discovery/Web-Content/permutations.txt -depth 1 -numbers 10 -mindup -adv -md > $folder/$domain/recon/subdomains/sub_gotator_$x.txt;
            echo -e $BGreen "Running Puredns" $NOCOLOR
            puredns resolve $folder/$domain/recon/subdomains/sub_gotator_$x.txt -r /home/drogas/bounty/resolvers.txt --write $folder/$domain/recon/subdomains/permutations_$x.txt;
            cat $folder/$domain/recon/subdomains/permutations_$x.txt | grep $domain >> $folder/$domain/recon/subdomains/permutations.txt;
            rm $folder/$domain/recon/subdomains/permutations_$x.txt $folder/$domain/recon/subdomains/sub_gotator_$x.txt ;
        done
        cat $folder/$domain/recon/subdomains/permutations.txt | sort -u > $folder/$domain/recon/subdomains/sub_permutations.txt
        rm $folder/$domain/recon/subdomains/permutations.txt
        rm xa*

        # Google Analytics
        echo -e $BBlue "Google Analytics" $NOCOLOR
        echo -e $BGreen "Running Analyticsrelationships" $NOCOLOR
        analyticsrelationships -u https://$domain > $folder/$domain/recon/subdomains/sub_analytics.txt;

        # TLS Probing
        echo -e $BBlue "TLS Probing" $NOCOLOR
        echo -e $BGreen "Running Cero" $NOCOLOR
        cero $domain | sed 's/^*.//' | grep -e "\." | anew > $folder/$domain/recon/subdomains/sub_tls.txt;

        # VHosts
        echo -e $BBlue "VHosts" $NOCOLOR
        echo -e $BGreen "Running Hosthunter" $NOCOLOR
        cd $folder/$domain/recon/subdomains/ && python3 ~/tools/HostHunter/hosthunter.py $folder/$domain/recon/ips.txt -f txt -o vhosts.txt;
        cat $folder/$domain/recon/subdomains/*vhosts.txt | grep $domain | tr "," "\n" | sed "s/ //g" | cut -d "[" -f 1 | sort -u > $folder/$domain/recon/subdomains/sub_vhosts.txt;
        rm $folder/$domain/recon/subdomains/vhosts.txt $folder/$domain/recon/subdomains/nessus_vhosts.txt $folder/$domain/recon/subdomains/webapps_vhosts.txt;
        cd $folder;

        # Scraping (JS / Source code)
        echo -e $BBlue "Scraping (JS / Source code)" $NOCOLOR
        echo -e $BGreen "Running Httpx" $NOCOLOR
        cat $folder/$domain/recon/subdomains/sub* | sort -u | httpx -random-agent -retries 2 -no-color -o $folder/$domain/recon/subdomains/probed_tmp_scrap.txt;

        echo -e $BGreen "Running Gospider" $NOCOLOR
        gospider -S $folder/$domain/recon/subdomains/probed_tmp_scrap.txt --js -t 50 -d 3 --sitemap --robots -w -r > $folder/$domain/recon/subdomains/gospider.txt;
        cp $folder/$domain/recon/subdomains/gospider.txt $folder/$domain/recon/crawlling/gospider.txt;
        sed -i '/^.\{2048\}./d' $folder/$domain/recon/subdomains/gospider.txt;
        cat $folder/$domain/recon/subdomains/gospider.txt | grep -Eo 'https?://[^ ]+' | sed 's/]$//' | unfurl -u domains | grep ".$domain$" | sort -u > $folder/$domain/recon/subdomains/scrap_subs.txt;

        echo -e $BGreen "Running Puredns" $NOCOLOR
        puredns resolve $folder/$domain/recon/subdomains/scrap_subs.txt -w $folder/$domain/recon/subdomains/sub_scrap.txt -r /home/drogas/bounty/resolvers.txt;
        rm $folder/$domain/recon/subdomains/probed_tmp_scrap.txt $folder/$domain/recon/subdomains/scrap_subs.txt $folder/$domain/recon/subdomains/gospider.txt;

        # Resolving all subdomains
        echo -e $BBlue "Resolving all subdomains" $NOCOLOR
        echo -e $BGreen "Running Massdns" $NOCOLOR
        cat $folder/$domain/recon/subdomains/sub*.txt | massdns -r /home/drogas/bounty/resolvers.txt -t A -o S -w $folder/$domain/recon/subdomains/sub_resolved.txt --root;
        sed 's/A.*//' $folder/$domain/recon/subdomains/sub_resolved.txt | sed 's/CN.*//' | sed 's/\..$//' | cut -d / -f 3 | cut -d " " -f 1 | sort -u > $folder/$domain/recon/subdomains/subdomains.txt;

        # Web Probing
        echo -e $BBlue "Web Probing" $NOCOLOR
        echo -e $BGreen "Running Unimap" $NOCOLOR
        COMMON_PORTS_WEB="81,300,591,593,832,981,1010,1311,1099,2082,2095,2096,2480,3000,3128,3333,4243,4567,4711,4712,4993,5000,5104,5108,5280,5281,5601,5800,6543,7000,7001,7396,7474,8000,8001,8008,8014,8042,8060,8069,8080,8081,8083,8088,8090,8091,8095,8118,8123,8172,8181,8222,8243,8280,8281,8333,8337,8443,8500,8834,8880,8888,8983,9000,9001,9043,9060,9080,9090,9091,9200,9443,9502,9800,9981,10000,10250,11371,12443,15672,16080,17778,18091,18092,20720,32000,55440,55672";
        wc=$( echo xxxxxxx.$(head -1 $folder/$domain/recon/subdomains/subdomains.txt) | httpx -wc -nc -silent | cut -d ' ' -f 2 | sed 's/\[//g' | sed 's/\]//g')
        lc=$( echo xxxxxxx.$(head -1 $folder/$domain/recon/subdomains/subdomains.txt) | httpx -lc -nc -silent | cut -d ' ' -f 2 | sed 's/\[//g' | sed 's/\]//g')
        # unimap --fast-scan -f $folder/$domain/recon/subdomains/subdomains.txt --ports $COMMON_PORTS_WEB -q -k --url-output > $folder/$domain/recon/subdomains/sub_unimap_commonweb.txt;
        if [ ${#wc} == 0 ]
	then
		cat $folder/$domain/recon/subdomains/subdomains.txt | sort -u | httpx -follow-host-redirects -probe -retries 2 -td -status-code -random-agent -p 80,443 -o $folder/$domain/recon/subdomains/httpx_default.txt;
        cat $folder/$domain/recon/subdomains/subdomains.txt | sort -u | httpx -follow-host-redirects -probe -retries 2 -td -status-code -random-agent -threads 150 -p $COMMON_PORTS_WEB -o $folder/$domain/recon/subdomains/httpx_common.txt;
	else
		cat $folder/$domain/recon/subdomains/subdomains.txt | sort -u | httpx -follow-host-redirects -probe -retries 2 -td -flc $lc -fwc $wc -status-code -random-agent -p 80,443 -o $folder/$domain/recon/subdomains/httpx_default.txt;
        cat $folder/$domain/recon/subdomains/subdomains.txt | sort -u | httpx -follow-host-redirects -probe -retries 2 -td -flc $lc -fwc $wc -status-code -random-agent -threads 150 -p $COMMON_PORTS_WEB -o $folder/$domain/recon/subdomains/httpx_common.txt;
	fi
        cat $folder/$domain/recon/subdomains/httpx_default.txt >> $folder/$domain/recon/subdomains/httpx.txt
        cat $folder/$domain/recon/subdomains/httpx_common.txt >> $folder/$domain/recon/subdomains/httpx.txt
        grep -v "FAILED" $folder/$domain/recon/subdomains/httpx.txt | sort -u > $folder/$domain/recon/subdomains/sub_probed_success.txt
        cat $folder/$domain/recon/subdomains/sub_probed_success.txt | cut -d " " -f 1 | sort -u > $folder/$domain/recon/subdomains/sub_probed.txt
        rm $folder/$domain/recon/subdomains/httpx_default.txt $folder/$domain/recon/subdomains/httpx_common.txt $folder/$domain/recon/subdomains/httpx.txt
    done
    
    # Save screenshots
    echo -e $BGreen "Running Aquatone" $NOCOLOR
    echo $domain | aquatone -ports large -silent -out $folder/$domain/recon/aquatone_screenshots/

else
    echo "Error! File $folder/scope.txt not found."
fi
