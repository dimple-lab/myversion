#!/bin/bash
#Created by Dimple
#This script run on Centos , Ubuntu, Debian and RHEL disribution

# Purpose: Determine if current user is root or not
is_root_user() {
 [ $(id -u) -eq 0 ]
}

# invoke the function
# make decision using conditional logical operators 
is_root_user && echo "You can run this script." || echo "You need to run this script as a root user."
#===============================================================================
### Variables ###
## This section defines global variables used in the script
args=$@
count=0
exit_code=0
me=$(basename $0)
result=Fail
state=0
timestamp=`date "+%T"`
tmp_file="/root/result/Output-$timestamp"
info_file="/root/result/Info-$timestamp"
wait_time="0.25"
progress_update_delay="0.1"
max_running_tests=10
debug=False
trace=False
renice_bool=True
renice_value=5
start_time=$(date +%s.%N)
color=True
test_level=0
#===============================================================================
function system_info {
       echo "####################### OS information ###########################"
       lsb_release -a 2>&1 || hostnamectl 2>&1  
       echo "####################### Kernal Information #######################"
       uname -s && uname -r && uname -v && printf "$@\n" || write_err "Command not working"
       echo "############################# Hostname ###########################"
       cat /etc/hostname
       echo "########################## Network interfaces #####################"
       ifconfig
       echo "########################### Processor information #################"
       processor=`grep -wc "processor" /proc/cpuinfo`
       model=`grep -w "model name" /proc/cpuinfo  | awk -F: '{print $2}'`
       echo "Processor = $processor"
       echo "Model     = $model"
       echo
       echo "######################## Memory information #######################"
       total=`grep -w "MemTotal" /proc/meminfo | awk '{print $2}'`
       free=`grep -w "MemFree" /proc/meminfo | awk '{print $2}'`
       echo "Total memory: $total kB"
       echo "Free memory : $free kB"
 }

#==============================================================================

outputter() {
    write_debug "Formatting and writing results to STDOUT"
    echo
    echo "|-------------------PCI DSS Benchmark v3.2.1 Results--------------------|"
    echo "|-----------------------------------------------------------------------|"
    
    if [ -t 1 -a $color == "True" ]; then
        (
            echo "ID,Description,Scored,Result,Time"
            echo "--,-----------,------,------,------"
            cat $tmp_file
        ) | column -t -s , |\
            sed -e $'s/^[0-9]\s.*$/\\n\e[1m&\e[22m/' \
                -e $'s/^[0-9]\.[0-9]\s.*$/\e[1m&\e[22m/' \
                -e $'s/\sFail\s/\e[31m&\e[39m/' \
                -e $'s/\sPass\s/\e[32m&\e[39m/' \
                -e $'s/^.*\sSkipped\s.*$/\e[2m&\e[22m/'
    else
        (
            echo "ID,Description,Scored,Result,Time"
            cat $tmp_file
        ) | column -t -s , | sed -e '/^[0-9]\ / s/^/\n/'
    fi
    
    tests_total=$(grep -c "Scored" $tmp_file)
    tests_skipped=$(grep -c ",Skipped," $tmp_file)
    tests_ran=$(( $tests_total - $tests_skipped ))
    tests_passed=$(egrep -c ",Pass," $tmp_file)
    tests_failed=$(egrep -c ",Fail," $tmp_file)
    tests_errored=$(egrep -c ",Error," $tmp_file)
    tests_time=$(echo "$(date +%s.%N) - $start_time" | bc)
    
    echo
    echo "Passed $tests_passed of $tests_total tests in $tests_time sec ($tests_skipped Skipped, $tests_errored Errors)"
    echo
    
} ## Prettily prints the results to the terminal
#===============================================================================
write_cache() {
    write_debug "Writing to $tmp_file - $@"
    printf "$@\n" >> $tmp_file
} ## Writes additional rows to the output cache
write_debug() {
    [ $debug == "True" ] && printf "[DEBUG] $(date -Ins) $@\n" >&2
} ## Writes debug output to STDERR
write_err() {
    printf "[ERROR] $@\n" >&2
} ## Writes error output to STDERR
write_result() {
    write_debug "Writing result to $tmp_file - $@"
    echo $@ >> $tmp_file
} ## Writes test results to the output cache
write_info() {
    heading=$1
    echo -e "\e[1;36m=================='$heading'===================\e[0m\n" >> $info_file
    echo "$2" >> $info_file
} ## Writes test info to info file
#===============================================================================
### Benchmark Tests ###
## This section defines the benchmark tests that are called by the script

## Tests used in multiple sections
skip_test() {
    ## This function is a blank for any tests too complex to perform 
    ## or that rely too heavily on site policy for definition
    
    id=$1
    description=$( echo $@ | awk '{$1=$2=""; print $0}' | sed 's/^ *//')
    scored="Skipped"
    result=""

    write_result "$id,$description,$scored,$result,$time"
} 
test_is_enabled() {
    id=$1
    service=$2
    name=$3
    description="Ensure $name service is enabled"
    scored="Scored"
    start=$(date +%s.%N)    

    ## Tests Start ##
    [ $( systemctl is-enabled $service ) == "enabled" ] && result="Pass"
    ## Tests End ##
    
   	duration=$(echo "$(date +%s.%N) - $start" | bc)
	time=`printf "%.2f sec" $duration`
   # duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$result,$time"
}

test_is_installed() {
    id=$1
    pkg=$2
    name=$3
    description="Ensure $name is installed"
    scored="Scored"
    start=$(date +%s.%N)    

    ## Tests Start ##
    [ $(rpm -q $pkg &>/dev/null; echo $?) -eq 0 ] && result="Pass"
    ## Tests End ##
    
	duration=$(echo "$(date +%s.%N) - $start" | bc)
	time=`printf "%.2f sec" $duration`
    #duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$result,$time"
}

test_is_not_installed() {
    id=$1
    pkg=$2
    name=$3
    description="Ensure $name is not installed"
    scored="Scored"
    start=$(date +%s.%N)

    ## Tests Start ##
    [[ $(rpm -q $pkg &>/dev/null; echo $?) -eq 0 ]] || result="Pass"
    ## Tests End ##
    
	duration=$(echo "$(date +%s.%N) - $start" | bc)
	time=`printf "%.2f sec" $duration`

    write_result "$id,$description,$scored,$result,$time"
}

#===============================================================================
#Actual test starts from here


test_1_1() {
    id=$1
    description="Ensure Firewalld is running"
    scored="Scored"

### new script
        start=$(date +%s.%N)
        [ "$(firewall-cmd --state)" == "running" ] && result="Pass" || result="Fail"
       
        write_info "Firewall-cmd --state" "`firewall-cmd --state 2>&1`"

        duration=$(echo "$(date +%s.%N) - $start" | bc)
        time=`printf "%.2f sec" $duration`
        write_cache "1,Requirement 1"
        write_result "$id,$description,$scored,$result,$time"
}


test_1_1_1() {
    id=$1
    description="Ensure IPTABLES rules configured"
    scored="Scored"

### new script
        start=$(date +%s.%N)
         
        [[ -f /etc/sysconfig/iptables ]] && result="Pass" || [[ -f /etc/iptables.up.rules ]] && result="Pass" || result="Fail"
        write_info "IPTABLES _L" "`iptables -L 2>&1`"
        write_info "Iptables file" "$(cat /etc/sysconfig/iptables 2>&1)" 
        write_info "Iptables file" "$(cat /etc/iptables.up.rules 2>&1)" 
        
        duration=$(echo "$(date +%s.%N) - $start" | bc)
        time=`printf "%.2f sec" $duration`
        #write_cache "1.1-a,Ensure egrees and ingress traffic"
        write_result "$id,$description,$scored,$result,$time"
}

test_1_1_4() {
    id=$1
    description="Ensure Firewall Zones available"
    scored="Scored"

### new script
        start=$(date +%s.%N)
        
###start test
write_info "Zones Available" "`firewall-cmd --get-zones 2>&1`"
write_info "Activated Zones" "`firewall-cmd --get-active-zones 2>&1`"

[[ ! `firewall-cmd --get-zones | grep 'dmz'` ]] && result="Fail" || result="Pass"
###end test
        duration=$(echo "$(date +%s.%N) - $start" | bc)
        time=`printf "%.2f sec" $duration`
        #write_cache "1.1-a,Ensure egrees and ingress traffic"
        write_result "$id,$description,$scored,$result,$time"

}

test_1_1_6() {
    id=$1
    description="Ensure ICMP is blocked"
    scored="Scored"

### new script
        start=$(date +%s.%N)

###start test

write_info "list ports in public zone" "`firewall-cmd --zone=public --list-ports 2>&1`"
write_info "ICMP block in public zone" "`firewall-cmd --zone=public --list-icmp-blocks 2>&1`"
write_info "all services running" "`firewall-cmd --list-services 2>&1`"
write_info "Ports have been used" "`sudo lsof -i -P -n 2>&1 | grep LISTEN 2>&1`"

res=`cat /proc/sys/net/ipv4/icmp_echo_ignore_all 2>&1`
[[ "$res" -eq "0" ]] && result="Fail" || result="Pass"

###end test
        duration=$(echo "$(date +%s.%N) - $start" | bc)
        time=`printf "%.2f sec" $duration`
        #write_cache "1.1-a,Ensure egrees and ingress traffic"
        write_result "$id,$description,$scored,$result,$time"
}

test_1_1_6_b() {
    id=$1
    description="Ensure IPv6 is disabled"
    scored="Scored"

### new script
        start=$(date +%s.%N)
###Test Starts
v6=`cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>&1`
[[ "$v6" -eq "0" ]] && result="Fail" || result="Pass"

###Test Ends
        duration=$(echo "$(date +%s.%N) - $start" | bc)
        time=`printf "%.2f sec" $duration`
        write_result "$id,$description,$scored,$result,$time"
}

test_1_1_6_b_2() {
    id=$1
    description="Ensure OS Version is Minimal"
    scored="Scored"

### new script
        start=$(date +%s.%N)

###Start Test
min=`awk '/Minimal/{print}' /etc/os-release 2>&1`
[ ! "$min" ] && result="Fail" || result="Pass"
write_info "OS related Info" "`cat /etc/os-release 2>&1`"
###End Test
        duration=$(echo "$(date +%s.%N) - $start" | bc)
        time=`printf "%.2f sec" $duration`
        write_result "$id,$description,$scored,$result,$time"
}

test_1_1_6_b_3() {
    id=$1
    description="Ensure NFS-server is not running"
    scored="Scored"

### new script
        start=$(date +%s.%N)
###Start Test
[[ "`systemctl is-active nfs-kernel-server 2>&1`" == "active" ]] && result="Fail" || result="Pass"
write_info "nfs-kernel service status" "`systemctl status nfs-kernel-server.service 2>&1`"
###end test
        duration=$(echo "$(date +%s.%N) - $start" | bc)
        time=`printf "%.2f sec" $duration`
        write_result "$id,$description,$scored,$result,$time"
}

test_1_1_6_b_3a() {
    id=$1
    description="Ensure NFS-client is not running"
    scored="Scored"

### new script
        start=$(date +%s.%N)
###Start Test
[[ "`systemctl is-active nfs-common 2>&1`" == "active" ]] && result="Fail" || result="Pass"
write_info "nfs-common service status" "`systemctl status nfs-common.service 2>&1`"
###end test
        duration=$(echo "$(date +%s.%N) - $start" | bc)
        time=`printf "%.2f sec" $duration`
        write_result "$id,$description,$scored,$result,$time"
}

test_1_1_6_b_4() {
    id=$1
    description="Ensure Print service not running"
    scored="Scored"

### new script
        start=$(date +%s.%N)
###Start Test
print=`systemctl is-active cups.service 2>&1`
[[ "$print" == "active"  ]] && result="Fail" || result="Pass"
write_info "CUPS service status" "`systemctl status cups.service 2>&1`"
###end test
        duration=$(echo "$(date +%s.%N) - $start" | bc)
        time=`printf "%.2f sec" $duration`
        write_result "$id,$description,$scored,$result,$time"
}

test_1_1_6_b_5() {
    id=$1
    description="Ensure FTP is not running"
    scored="Scored"

### new script
        start=$(date +%s.%N)
###Start Test
ftp=`systemctl is-active ftp`
[[ "$ftp" == "active"  ]] && result="Fail" || result="Pass"
write_info "FTP service status" "`systemctl status ftp.service 2>&1`"
###end test
        duration=$(echo "$(date +%s.%N) - $start" | bc)
        time=`printf "%.2f sec" $duration`
        write_result "$id,$description,$scored,$result,$time"
}

test_1_1_6_b_6() {
    id=$1
    description="Ensure telent is not running"
    scored="Scored"

### new script
        start=$(date +%s.%N)
###Start Test
tel=`systemctl is-active telnet`
[[ "$tel" == "active"  ]] && result="Fail" || result="Pass"
###end test
        write_info "telnet service status" "`systemctl status telnet.service 2>&1`"
        duration=$(echo "$(date +%s.%N) - $start" | bc)
        time=`printf "%.2f sec" $duration`
        write_result "$id,$description,$scored,$result,$time"
}

test_1_1_6_b_7() {
    id=$1
    description="Ensure NIS service not running"
    scored="Scored"

### new script
        start=$(date +%s.%N)
###Start Test

var1=`systemctl is-active ypsrv ypbind`
[[ "$var1" == "active"  ]] && result="Fail" || result="Pass"
###end test
        write_info "NIS server status" "`systemctl status ypsrv ypbind 2>&1`"
        duration=$(echo "$(date +%s.%N) - $start" | bc)
        time=`printf "%.2f sec" $duration`
        write_result "$id,$description,$scored,$result,$time"
}

test_1_1_6_b_8() {
    id=$1
    description="Ensure SMTP service is not running"
    scored="Scored"

### new script
        start=$(date +%s.%N)
###Start Test
var2=`systemctl is-active sendmail postfix`
[[ "$var2" == "active"  ]] && result="Fail" || result="Pass"
write_info "SMTP service status" "`systemctl status sendmail postfix 2>&1`"
###end test
        duration=$(echo "$(date +%s.%N) - $start" | bc)
        time=`printf "%.2f sec" $duration`
        write_result "$id,$description,$scored,$result,$time"
}

test_1_1_6_b_9() {
    id=$1
    description="Ensure HTTP is not running"
    scored="Scored"

### new script
        start=$(date +%s.%N)
###Start Test
var3=`systemctl is-active http httpd apache`
[[ "$var3" == "active"  ]] && result="Fail" || result="Pass"
###end test
        write_info "HTTP service status" "`systemctl status http httpd 2>&1`"
        duration=$(echo "$(date +%s.%N) - $start" | bc)
        time=`printf "%.2f sec" $duration`
        write_result "$id,$description,$scored,$result,$time"

}

test_1_1_6_b_10() {
    id=$1
    description="Ensure SNMP is not running"
    scored="Scored"

    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
var3=`systemctl is-active snmp snmpd`
 if [ "$var3" == "active" ]; then
  (
    var4=`netstat -natv | grep ':199'`
    [[ ! "$var4"  ]] && result="Pass" || result="Fail"
  )
  fi
    write_info "SNMP service status" "`systemctl status snmp snmpd 2>&1`"
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$time"
}

test_1_1_6_b_11() {
    id=$1
    description="Ensure tftp server is not enabled"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)
    
    ## Tests Start ##
    state=0
    str=$(chkconfig --list 2>&1)
    
    [ "$(chkconfig --list 2>&1 | awk '/tftp/ {print $2}')" == "on" ] && state=1
    
    [ $state -eq 0 ] && result=Pass
    ## Tests End ##
    write_info "TFTP service status" "`systemctl status tftp 2>&1`"
    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$time"
}

test_1_1_6_b_12() {
    id=$1
    description="Ensure Dev tools not installed"
    scored="Scored"

    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
    if [[ ! -z $(yum grouplist 2>&1 | grep "Development Tools") ]] || [[ ! -z $(dnf grouplist 2>&1 | grep "Development Tools") ]]; then
    result="Pass"
    else
    result="Fail"
    fi
    write_info "Developement Tools packages" "`yum grouplist 2>&1 | grep "Development Tools"`"    
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$time"
}

test_1_2_1() {
    id=$1
    description="Ensure default deny firewall policy"
    scored="Scored"

    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
    str=$(iptables -S -w60)
    [ $(echo "$str" | grep -c -- "-P INPUT DROP") != 0 ] || state=1
    [ $(echo "$str" | grep -c -- "-P FORWARD DROP") != 0 ] || state=2
    [ $(echo "$str" | grep -c -- "-P OUTPUT DROP") != 0 ] || state=4
    [ $state -eq 0 ] && result="Pass"
    ###Test Ends
    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$time"
}


test_1_2_1_c() {
    id=$1
    description="Ensure rich rule configured"
    scored="Scored"

    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##   
write_info "firewall-cmd --list-all" "`firewall-cmd --list-all 2>&1`"
 rich=`firewall-cmd --list-rich-rules`
 [[ ! $rich ]] && result="Fail" || result="Pass"

write_info "firewall-cmd --get-services" "`firewall-cmd --get-services 2>&1`"
write_info "firewall-cmd --get-zones" "`firewall-cmd --get-zones 2>&1`"
write_info "firewall-cmd --get-active-zones" "`firewall-cmd --get-active-zones 2>&1`"
write_info "firewall-cmd --list-services" "`firewall-cmd --list-services 2>&1`"
write_info "firewall-cmd --list-forward-ports" "`firewall-cmd --list-forward-ports 2>&1`"
write_info "firewall-cmd --list-icmp-blocks" "`firewall-cmd --list-icmp-blocks 2>&1`"
write_info "firewall-cmd --list-protocols" "`firewall-cmd --list-protocols 2>&1`"
###Test Ends
    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$time"
}

test_1_2_2() {
    id=$1
    description="Ensure Firewalld enabled at boot"
    scored="Scored"

    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
[[ "`systemctl is-enabled firewalld`" == "enabled" ]] && result="Pass" || result="Fail"
    ## Test Ends ##
    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$time"
}

test_1_3_2() {
    id=$1
    description="Emsure DMZ is Active zone"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
    dmz=`firewall-cmd --get-active-zones 2>&1 | grep dmz`
    [ ! $dmz ] && result="Fail" || result="Pass" && echo $dmz >> $info_file  
    ## Tests End ##
write_info "firewall-cmd --zone=dmz --list-ports" "`firewall-cmd --zone=dmz --list-ports 2>&1`"
write_info "firewall-cmd --zone=dmz --list-protocols" "`firewall-cmd --zone=dmz --list-protocols 2>&1`"
write_info "firewall-cmd --zone=dmz --list-services" "`firewall-cmd --zone=dmz --list-services 2>&1`"

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$time"
}

test_1_3_3() {
    id=$1
    description="Ensure Source add. verification exist"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
sad=`cat /proc/sys/net/ipv4/conf/default/rp_filter 2>&1`
[[ "$sad" -eq "0" ]] && result="Fail" || result="Pass" 
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$time"
}

test_1_3_5() {
    id=$1
    description="Ensure only Established conn allowed"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
str=$(iptables -S -w60)
    [ $(echo "$str" | grep -c -- "-A INPUT -m state --state ESTABLISHED -j ACCEPT") != 0 ] || state=1
    [ $(echo "$str" | grep -c -- "-A OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT") != 0 ] || state=2
    [ $state -eq 0 ] && result="Pass"
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$time"
}

test_1_3_7() {
    id=$1
    description="Ensure IP Forwarding enabled"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
ipf=`cat /proc/sys/net/ipv4/ip_forward 2>&1`
[[ "$ipf" -eq "0" ]] && result="Fail" || result="Pass" 

write_info "NAT rules" "`egrep -w 'POSTROUTING|PREROUTING|MASQUERADE|DNAT|SNAT|REDIRECT' /etc/sysconfig/iptables 2>&1`" 
write_info "NAT rules" "`egrep -w 'POSTROUTING|PREROUTING|MASQUERADE|DNAT|SNAT|REDIRECT' /etc/iptables.up.rules 2>&1`" 
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$time"
}

test_1_3_7_a() {
    id=$1
    description="Ensure Proxy used for o/g traffic"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
proxy=`cat /etc/profile 2>&1 | grep http_proxy`
[[ ! $proxy ]] && result="Fail" || result="Pass" 
write_info "Proxy setting" "$proxy"
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$time"
}

test_1_4_a() {
    id=$1
    description="Ensure iptables service is active"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
ip=`systemctl is-active iptables`
[[ "$ip" == "active" ]] && result="Pass" || result="Fail"
    write_info "IPTABLES service status" "`systemctl status iptables 2>&1`"
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$time"
}

test_2_1() {
    
    id=$1
    description="List User account"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)
 
    ## Tests Start ##
   _l="/etc/login.defs"
   _p="/etc/passwd"

## get mini UID limit ##
l=$(grep "^UID_MIN" $_l)

## get max UID limit ##
l1=$(grep "^UID_MAX" $_l)

## use awk to print if UID >= $MIN and UID <= $MAX and shell is not /sbin/nologin   ##

nor=`awk -F':' -v "min=${l##UID_MIN}" -v "max=${l1##UID_MAX}" '{ if ( $3 >= min && $3 <= max  && $7 != "/sbin/nologin" ) print $0 }' "$_p"`
write_info "Normal User Accounts" "$nor"

echo ""

sys=`awk -F':' -v "min=${l##UID_MIN}" -v "max=${l1##UID_MAX}" '{ if ( !($3 >= min && $3 <= max  && $7 != "/sbin/nologin")) print $0 }' "$_p"`
write_info "System User Accounts" "$sys"

## Tests End ##


    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    write_cache "2,Requirement 2"
    write_result "$id,$description,$scored,$result,$time"


}

test_2_2_2() {
    id=$1
    description="Listing services enabled at boot"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
en=`systemctl list-unit-files --state=enabled 2>&1`
[[ ! $en ]] && result="Fail" || result="Pass" 
write_info "Enabled unit files" "$en"
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$time"
}

test_2_2_2_a() {
    id=$1
    description="Listing loded services"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
sr=`systemctl list-units --type service 2>&1`
[[ ! $sr ]] && result="Fail" || result="Pass" 
write_info "Loaded service unit files" "$sr"
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$time"
}

test_2_2_5() {
    id=$1
    description="Listing Installed drivers"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
dr=`find /lib/modules/$(uname -r)/kernel/ -name '*.ko*' 2>&1`
[[ ! $dr ]] && result="Fail" || result="Pass" 
write_info "Installed drivers" "$dr"
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$time"
}

test_2_2_5_a() {
    id=$1
    description="Listing Mounted disks"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
ds=`sudo fdisk -l 2>&1`
[[ ! $ds ]] && result="Fail" || result="Pass" 
write_info "Mounted Disks in system" "$ds"
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$time"
}

test_2_2_5_b() {
    id=$1
    description="Checking size of Cache files"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
ds=`sudo du -sh /var/cache/* 2>&1`
[[ ! $ds ]] && result="Fail" || result="Pass" 
write_info "Cache files size" "$ds"
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$time"
}

test_2_3_a() {
    id=$1
    description="Ensure non-consol telnet is not-active"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
tel=`sudo systemctl is-active telnet 2>&1`
[[ "$tel" == "active" ]] && result="Fail" || result="Pass"
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$time"
}

test_2_3_b() {
    id=$1
    description="Ensure non-console rsh is not-active"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
rsh=`sudo systemctl is-active rsh.socket 2>&1`
[[ "$rsh" == "active" ]] && result="Fail" || result="Pass"
    ## Tests End ##
    write_info "RSH service status" "`sudo systemctl status rsh.socket 2>&1`"
    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$time"
}

test_2_3_c() {
    id=$1
    description="Ensure Non-console rlogin is not active"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
rl=`sudo systemctl is-active rlogin.socket 2>&1`
[[ "$rl" == "active" ]] && result="Fail" || result="Pass"
    ## Tests End ##
    write_info "RLOGIN service status" "`sudo systemctl status rlogin.socket 2>&1`"
    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$time"
}

test_2_3_d() {
    id=$1
    description="Ensure Non-console rpc is not active"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
rpc=`sudo systemctl is-active rpcbind 2>&1`
[[ "$rpc" == "active" ]] && result="Fail" || result="Pass"
    ## Tests End ##
    write_info "RPCBIND service status" "`sudo systemctl status rpcbind 2>&1`"
    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$time"
}

test_2_3_e() {
    id=$1
    description="Ensure Encryption used in ssh"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
encr=`sudo cat /etc/ssh/sshd_config | grep UsePAM | awk '{print $2}' 2>&1`
[[ "$encr" == "yes" ]] && result="Pass" || result="Fail"
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$time"
}

#********************************************************************************

test_4_1_a() {
    id=$1
    description="Trying TLS1.3 handshake"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
tls13=`sudo echo "x" | openssl s_client -connect google.com:443 -tls1_3 2>&1`
[[ ! "$tls13" ]] && result="Fail" || result="Pass"
    write_info "TLS1.3 Handshake" "$tls13"
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    write_cache "4,Requirement 4"
    write_result "$id,$description,$scored,$result,$time"
}

#********************************************************************************

test_4_1_b() {
    id=$1
    description="Trying TLS1.2 handshake"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
tls12=`sudo echo "x" | openssl s_client -connect google.com:443 -tls1_2 2>&1`
[[ ! "$tls12" ]] && result="Fail" || result="Pass"
    write_info "TLS1.2 Handshake" "$tls12"
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$time"
}

#********************************************************************************

test_4_1_c() {
    id=$1
    description="Trying TLS1.1 handshake"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
tls11=`sudo echo "x" | openssl s_client -connect google.com:443 -tls1_1 2>&1`
[[ ! "$tls11" ]] && result="Fail" || result="Pass"
    write_info "TLS1.1 handshake" "$tls11"
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$time"
}

#********************************************************************************

test_4_1_d() {
    id=$1
    description="Trying TLS1 handshake"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
tls1=`sudo echo "x" | openssl s_client -connect google.com:443 -tls1 2>&1`
[[ ! "$tls1" ]] && result="Fail" || result="Pass"
    write_info "TLS1 handshake" "$tls1"
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$time"
}

#********************************************************************************

test_4_1_e() {
    id=$1
    description="Ensure server accept req with NULL cipher"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
tlsnull=`sudo echo "x" |openssl s_client -connect google.com:443 -cipher NULL,LOW 2>&1`
[[ ! "$tlsnull" ]] && result="Fail" || result="Pass"
    write_info "NULL cipher handshake" "$tlsnull"
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$time"
}

#********************************************************************************

test_5_1() {
    id=$1
    description="Ensure ClamAV is installed"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
if [[ $(rpm -qa 2>&1 | egrep -w 'clamav') || $(dpkg -l 2>&1 | egrep 'clamav') ]]; then
result="Pass"
else
result="Fail"
fi
    write_info "CLamAV packages" "$(rpm -qa 2>&1 | grep clamav*) || $(dpkg -l 2>&1 | grep clamav*)" 
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    write_cache "5,Requirement 5"
    write_result "$id,$description,$scored,$result,$time"
}
#********************************************************************************

test_5_2_a() {
    id=$1
    description="Ensure Clamav is enabled at boot"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##

clam1=`systemctl is-enabled clamav 2>&1`
if [[ "$clam1" == "enabled" ]]; then 
result="Pass" 
else result="Fail"
fi

    write_info "ClamAV enable status" "$clam1"
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$time"
}
#********************************************************************************

test_5_2_b() {
    id=$1
    description="Ensure Clamav service is running"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
clam2=`systemctl is-active clamav 2>&1`
clam3=`systemctl status clamav 2>&1`
if [[ "$clam2" == "active" ]]; then 
result="Pass" 
else 
result="Fail"
fi
    write_info "ClamAV active status" "$clam2"
    write_info "ClamAV status" "$clam3"
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$time"
}
#********************************************************************************

test_5_2_c() {
    id=$1
    description="Ensure Cronjob exist for Clamav"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
clam4=`crontab -l 2>&1 | grep *clamav*`
[[ ! "$clam4" ]] && result="Fail" || result="Pass"
    write_info "ClamAV crontab" "$clam4"
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$time"
}
#********************************************************************************

test_5_2_d() {
    id=$1
    description="Ensure Daily Cron exist for Clamav"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
if [[ -f /etc/cron.daily/*clamav* ]]; 
then result="Pass" 
else result="Fail"
fi
    write_info "Daily cron of Clamav" "`cat /etc/cron.daily/*clamav* 2>&1 | grep -v "#"`"
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$time"
}
#********************************************************************************

test_5_2_e() {
    id=$1
    description="Ensure Hourly Cron exist for Clamav"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
if [[ -f /etc/cron.hourly/*clamav* ]]; 
then result="Pass" 
else result="Fail"
fi
    write_info "Hourly Cron for Clamav" "`cat /etc/cron.hourly/*clamav* 2>&1| grep -v "#"`"
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$time"
}

#********************************************************************************

test_5_2_f() {
    id=$1
    description="Ensure Clamav log file exist"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
if [[ -d /var/log/clamav/ ]]; then
result="Fail"
else result="Pass"
fi
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$time"
}

#********************************************************************************

test_5_2_g() {
    id=$1
    description="Ensure Clamscan log file exist"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
if [[ -f /var/log/clamav/*.log ]]; then 
result="Fail"
else result="Pass"
fi
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$time"
}

#********************************************************************************

test_5_3_a() {
    id=$1
    description="Ensure FreshClam service is running"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
fresh=`ps -ef | grep -v grep | grep clamav-freshclam | wc -l 2>&1`
if [[ $fresh -gt 1 ]]; then 
result="Pass"
else result="Fail"
fi
    write_info "FreshClam service running" "`ps -ef | grep -v grep | grep clamav-freshclam 2>&1`"
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$time"
}

#********************************************************************************

test_5_3_b() {
    id=$1
    description="Ensure config for virus-update"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
if [[ -f /etc/clamav/freshclam.conf ]]; then
(
result="Pass"
chk=`grep checks /etc/clamav/freshclam.conf | awk '{ print $2 }' 2>&1`
write_info "Check for virus update below times a day" "$chk"
)
else
(
result="Fail"
)
fi
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$time"
}

#********************************************************************************

test_5_3_c() {
    id=$1
    description="Ensure clamd-scan service is running"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
if [[ `ps -ef | grep -v grep | grep clamd | wc -l 2>&1` -gt 0 ]]; then
(
result="Pass"
clamd=`grep checks /etc/clamav/clamd.conf 2>&1`
write_info "Clamd.conf" "$clamd"
)
else
(
result="Fail"
)
fi
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$time"
}

test_5_3_d() {
    id=$1
    description="Ensure read permission on clamd.conf"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
if [[ -r /etc/clamav/clamd.conf ]]; then
(
result="Pass"
write_info "clam.conf log file permission" "`ls -alth /etc/clamav/clamd.conf 2>&1`"
)
else
(
result="Fail"
)
fi
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$time"
}

test_5_3_e() {
    id=$1
    description="Ensure write permission on clamd.conf"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
if [[ -w /etc/clamav/clamd.conf ]]; then
(
result="Pass"
write_info "clam.conf log file permission" "`ls -alth /etc/clamav/clamd.conf 2>&1`"
)
else
(
result="Fail"
)
fi
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$time"
}

test_5_3_f() {
    id=$1
    description="Ensure read permission on freshclam.conf"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
if [[ -r /etc/clamav/freshclam.conf ]]; then
(
result="Pass"
write_info "freshclam.conf log file permission" "`ls -alth /etc/clamav/freshclam.conf 2>&1`"
)
else
(
result="Fail"
)
fi
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$time"
}

test_5_3_g() {
    id=$1
    description="Ensure write permission on freshclam.conf"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
if [[ -w /etc/clamav/freshclam.conf ]]; then
(
result="Pass"
write_info "freshclam.conf log file permission" "`ls -alth /etc/clamav/freshclam.conf`"
)
else
(
result="Fail"
)
fi
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$time"
}

#****************************************************************************

test_6_1() {
    id=$1
    description="Ensure when kernel updated last time"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
last1=`rpm -q kernel --last 2>&1`
last2=`ls -l /boot/ 2>&1`
if [[ ! -z $last1 ]] || [[ ! -z $last2 ]]; then
result="Pass"
else
result="Fail"
fi
write_info "last update of kernel" "$last1" "$last2"
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    write_cache "6,Requirement 6"
    write_result "$id,$description,$scored,$result,$time"
}


test_6_1_a() {
    id=$1
    description="Ensure all package update date"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
last3=$(rpm -q --last 2>&1)
last4=$(grep upgrade /var/log/dpkg.log 2>&1)
if [[ ! -z $last3 ]] || [[ ! -z $last4 ]]; then
(
result="Pass"
)
else
(
result="Fail"
)
fi
write_info "last update of all packages" "$last3" "$last4"
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$time"
}

test_6_1_b() {
    id=$1
    description="Ensure list of package to update"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
pack1=$(yum list updates 2>&1)
pack2=$(apt list --upgradable 2>&1)
if [[ ! -z $pack1 ]] || [[ ! -z $pack2 ]]; then
result="Pass"
else
result="Fail"
fi
write_info "Packages to be updated are" "$pack1" "$pack2"
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$time"
}

test_6_1_c() {
    id=$1
    description="Ensure log of installed/updated packages"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
pack3=/var/log/yum.log
pack4=/var/log/apt/history.log
if [[ -f /var/log/yum.log ]] || [[ -f /var/log/apt/history.log ]]; then
(
result="Pass"
)
else
(
result="Fail"
)
fi
write_info "Check logs in file" "`cat $pack3 2>&1`" "`cat $pack4 2>&1`"
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$time"
}

test_6_2() {
    id=$1
    description="Ensure when Repo last updated"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
rep1=`sudo yum repolist all 2>&1`
rep2=`sudo grep ^[^#] /etc/apt/sources.list 2>&1 /etc/apt/sources.list.d/* 2>&1`
if [[ -z $rep1 ]] || [[ -z $rep2 ]]; then
(
result="Fail"
)
else
(
result="Pass"
)
fi
write_info "Check repo list" "$rep1" "$rep2"
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$time"
}

test_6_2_a() {
    id=$1
    description="Ensure security updates"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
sec1=`sudo yum check-update --security 2>&1`
sec2=`sudo grep security /etc/apt/sources.list 2>&1`
if [[ ! -z $sec1 ]] || [[ ! -z $sec2 ]]; then
(
result="Pass"
)
else
(
result="Fail"
)
fi
write_info "Check security package update" "$sec1" "$sec2"
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$time"
}

#****************************************************************************

test_7_1() {
    id=$1
    description="Ensure user is part of sudoer"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
sudoer1=$(grep $(whoami) /etc/sudoers 2>&1)
if [[ $? -eq 0 ]]; then
(
result="Pass"
)
else
(
result="Fail"
)
fi
write_info "SUDOERS" "`cat /etc/sudoers | grep -v "#"`"
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    #write_cache "7,Requirement 7"
    write_result "$id,$description,$scored,$result,$time"
}

test_7_2() {
    id=$1
    description="Ensure SELinux is Installed"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
se1=rpm -qa 2>&1 | egrep -w 'selinux-basic|selinux-policy-defualt' 
se2=dpkg -l 2>&1 | grep selinux*
if [[ ! -z $se1 ]] || [[ ! -z $se2 ]]; then
(
result="Pass"
)
else
(
result="Fail"
)
fi
write_info "$se1" "$se2"
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    #write_cache "7,Requirement 7"
    write_result "$id,$description,$scored,$result,$time"
}

test_7_2_a() {
    id=$1
    description="Ensure SELinux is enforced"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
state=`grep SELINUX=enforcing /etc/sysconfig/selinux 2>&1`
if [[ ! $state ]]; then
(
result="Fail"
)
else
(
result="Pass"
)
fi
write_info "SELinux Status" "`grep SELINUX /etc/sysconfig/selinx 2>&1 | awk '{print $2}'`"
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    #write_cache "7,Requirement 7"
    write_result "$id,$description,$scored,$result,$time"
}

test_7_2_b() {
    id=$1
    description="Ensure SELinux is targeted"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
type=`grep SELINUXTYPE=targeted /etc/sysconfig/selinux 2>&1`
if [[ ! $type ]]; then
(
result="Fail"
)
else
(
result="Pass"
)
fi
write_info "SELinuxTYPE Status" "`grep SELINUXTYPE /etc/sysconfig/selinx 2>&1 | awk '{print $2}'`"
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    #write_cache "7,Requirement 7"
    write_result "$id,$description,$scored,$result,$time"
}

test_7_2_c() {
    id=$1
    description="Ensure SEtroubleshoot is not installed"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
tr1=`rpm -q 2>&1 | grep setroubleshoot` 
tr2=`dpkg -l 2>&1 | grep setroubleshoot`
if [[ ! $tr1 ]] || [[ ! $tr2 ]]; then
(
result="Fail"
)
else
(
result="Pass"
)
fi
    ## Tests End ##
    write_info  "setroubleshoot package" "$tr1" "$tr2"
    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    #write_cache "7,Requirement 7"
    write_result "$id,$description,$scored,$result,$time"
}

test_7_2_d() {
    id=$1
    description="Ensure unconfined daemons"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
con=`ps -eZ | egrep "initrc" | egrep -vw "tr|ps|egrep|bash|awk" | tr ':' ' ' | awk '{print $NF}'`
if [[ $? -eq 0 ]]; then
(
result="Pass"
)
else
(
result="Fail"
)
fi
write_info "Unconfined daemon""$con"
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    #write_cache "7,Requirement 7"
    write_result "$id,$description,$scored,$result,$time"
}

test_7_2_e() {
    id=$1
    description="Ensure SELinux Config file exist"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
if [[ -f /etc/selinux/config ]] || [[ -f /etc/sysconfig/selinux ]]; then
(
result="Pass"
)
else
(
result="Fail"
)
fi
write_info "Selinux Config file" "`cat /etc/selinux/config`" "`cat /etc/sysconfig/selinux`"
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    #write_cache "7,Requirement 7"
    write_result "$id,$description,$scored,$result,$time"
}

test_7_2_f() {
    id=$1
    description="Ensure MCS-Translation is not-installed"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)
    
    ## Tests Start ##
    state=0
    
    [ "$(rpm -q mcstrans)" == "package mcstrans is not installed" ] || state=1
    [ $state -eq 0 ] && result="Pass"
    ## Tests End ##
    
    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    write_result "$id,$description,$scored,$result,$time"
}

#*********************************************************************************

test_8_1() {
    id=$1
    description="Ensure root is the only UID 0 acc"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
[ $(awk -F: '$3 == 0' /etc/passwd | wc -l) -eq 1 ] || state=1
    
[ $state -eq 0 ] && result="Pass"
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    write_cache "8,Requirement 8"
    write_result "$id,$description,$scored,$result,$time"
}

test_8_1_1() {
    id=$1
    description="Ensure no duplicate UIDs exist"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
    [ $(cut -f3 -d: /etc/passwd | sort | uniq -c | awk '$1 > 1' | wc -l) -eq 0 ] || state=1
    
    [ $state -eq 0 ] && result="Pass"
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    #write_cache "8,Requirement 8"
    write_result "$id,$description,$scored,$result,$time"
}

test_8_1_1_a() {
    id=$1
    description="Ensure no duplicate GIDs exist"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
    [ $(cut -f3 -d: /etc/group | sort | uniq -c | awk '$1 > 1' | wc -l) -eq 0 ] || state=1
    
    [ $state -eq 0 ] && result="Pass"
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    #write_cache "7,Requirement 7"
    write_result "$id,$description,$scored,$result,$time"
}

test_8_1_1_b() {
    id=$1
    description="Ensure no duplicate user names exist"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
    [ $(cut -f1 -d: /etc/passwd | sort | uniq -c | awk '$1 > 1' | wc -l) -eq 0 ] || state=1
    
    [ $state -eq 0 ] && result="Pass"
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    #write_cache "7,Requirement 7"
    write_result "$id,$description,$scored,$result,$time"
}

test_8_1_1_c() {
    id=$1
    description="Ensure no duplicate group names exist"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
    [ $(cut -f1 -d: /etc/group | sort | uniq -c | awk '$1 > 1' | wc -l) -eq 0 ] || state=1
    
    [ $state -eq 0 ] && result="Pass"
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    #write_cache "7,Requirement 7"
    write_result "$id,$description,$scored,$result,$time"
}

test_8_1_1_d() {
    id=$1
    description="Ensure system accounts are non-login"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
    [ $(egrep -v "^\+" /etc/passwd | awk -F: '($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $3<1000 && $7!="/sbin/nologin" && $7!="/bin/false") {print}' | wc -l) -eq 0 ] && result="Pass"
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    #write_cache "7,Requirement 7"
    write_result "$id,$description,$scored,$result,$time"
}

test_8_1_1_e() {
    id=$1
    description="Ensure access to su is restricted"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
    [ $(egrep -c "^auth\s+required\s+pam_wheel.so\s+use_uid" /etc/pam.d/su) -eq 1 ] || state=1
    
    [ $state -eq 0 ] && result="Pass"
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    #write_cache "7,Requirement 7"
    write_result "$id,$description,$scored,$result,$time"
}

test_8_1_1_f() {
    id=$1
    description="Ensure password fields are not empty"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
    [ $(awk -F: '($2 == "" )' /etc/shadow | wc -l) -eq 0 ] || state=1
    
    [ $state -eq 0 ] && result="Pass"
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    #write_cache "7,Requirement 7"
    write_result "$id,$description,$scored,$result,$time"
}

test_8_1_1_h() {
    id=$1
    description="Ensure users own their own home directories"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
    awk -F: '{ print $1 " " $3 " " $6 }' /etc/passwd | while read user uid dir; do
        if [ $uid -ge 1000 -a -d "$dir" -a $user != "nfsnobody" ]; then 
            owner=$(stat -L -c "%U" "$dir")
            [ "$owner" == "$user" ] || state=1
        fi
    done
    
    [ $state -eq 0 ] && result="Pass"
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    #write_cache "7,Requirement 7"
    write_result "$id,$description,$scored,$result,$time"
}

test_8_1_1_i() {
    id=$1
    description="Ensure same groups exist in both file"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
    for i in $(cut -s -d: -f4 /etc/passwd | sort -u ); do 
        grep -q -P "^.*?:[^:]*:$i:" /etc/group
        [ $? -eq 0 ] || state=1
    done
    
    [ $state -eq 0 ] && result="Pass"
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    #write_cache "7,Requirement 7"
    write_result "$id,$description,$scored,$result,$time"
}

test_8_1_4() {
    id=$1
    description="Ensure inactive acc over 90d are locked"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
inactive=`lastlog -b 90 2>&1 | tail -n+2 | grep '**Never log**' | awk '{print $1}' 2>&1`
if [[ ! $inactive ]] ; then
scored="skipped"
else
( 
   for line in $inactive
   do
   lk=`passwd -S $line | awk '{print $2}' 2>&1`
   if [ "$lk" = "LK" ]; then
   result="Pass" 
     else
   result="Fail"
   fi
   done
)
fi  
    ## Tests End ##
    write_info "INACTIVE USERS over 90d" "$inactive" 
    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    #write_cache "7,Requirement 7"
    write_result "$id,$description,$scored,$result,$time"
}

test_8_1_6() {
    id=$1
    description="Ensure password locked after 6 fail attempt"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
    [[ $(egrep -c "^auth\s+required\s+(pam_faillock.so|pam_tally2.so)\s+deny=6" /etc/pam.d/system-auth 2>&1) -eq 1 ]] || state=1
    [[ $(egrep -c "^auth\s+required\s+(pam_faillock.so|pam_tally2.so)\s+deny=6" /etc/pam.d/password-auth 2>&1) -eq 1 ]] || state=1
#    [[ $(egrep -c "^auth\s+required\s+(pam_faillock.so|pam_tally2.so)\s+deny=6" 2>&1 /etc/pam.d/common-password 2>&1) -eq 1 ]] || state=1
#    [[ $(egrep -c "^auth\s+required\s+(pam_faillock.so|pam_tally2.so)\s+deny=6" 2>&1 /etc/pam.d/common-auth 2>&1) -eq 1 ]] || state=1

[[ $state -eq 0 ]] && result="Pass" || result="Fail"
    ## Tests End ##
    
    write_info "System-auth Config file" "`cat /etc/pam.d/system-auth 2>&1`"
    write_info "password-auth Config file" "`cat /etc/pam.d/password-auth 2>&1`"
    write_info "common-auth Config file" "`cat /etc/pam.d/common-auth 2>&1`"
    write_info "common-password Config file" "`cat /etc/pam.d/common-password 2>&1`"
    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    #write_cache "7,Requirement 7"
    write_result "$id,$description,$scored,$result,$time"
}

test_8_1_7() {
    id=$1
    description="Ensure password is locked for 30 min"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
[ $(egrep -c "^auth\s+required\s+(pam_faillock.so|pam_tally2.so)\s+deny=6\s+unlock_time=1800" /etc/pam.d/system-auth 2>&1) -eq 1 ] || state=1
    [ $(egrep -c "^auth\s+required\s+(pam_faillock.so|pam_tally2.so)\s+deny=6\s+unlock_time=1800" /etc/pam.d/password-auth 2>&1) -eq 1 ] || state=1
#[ $(egrep -c "^auth\s+required\s+(pam_faillock.so|pam_tally2.so)\s+deny=6\s+unlock_time=1800" /etc/pam.d/common-auth 2>&1) -eq 1 ] || state=1
#    [ $(egrep -c "^auth\s+required\s+(pam_faillock.so|pam_tally2.so)\s+deny=6\s+unlock_time=1800" /etc/pam.d/common-password 2>&1) -eq 1 ] || state=1


[[ $state -eq 0 ]] && result="Pass" || result="Fail"
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    #write_cache "7,Requirement 7"
    write_result "$id,$description,$scored,$result,$time"
}

test_8_1_8() {
    id=$1
    description="Ensure session terminate after 15m in idle"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
[[ $(egrep -c "^ClientAliveInterval\s+900" /etc/ssh/sshd_config 2>&1) -eq 1 ]] && result="Pass" || result="Fail"
    ## Tests End ##
    write_info "Sshd_config file" "`cat /etc/ssh/sshd_config`"
    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    #write_cache "7,Requirement 7"
    write_result "$id,$description,$scored,$result,$time"
}

test_8_2() {
    id=$1
    description="Ensure password hashing algorithm SHA-512"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
    [[ $(egrep -c "^password\s+sufficient\s+pam_unix.so.*sha512" /etc/pam.d/system-auth) -eq 1 ]] || state=1
    [[ $(egrep -c "^password\s+sufficient\s+pam_unix.so.*sha512" /etc/pam.d/password-auth) -eq 1 ]] || state=1
#    [[ $(egrep -c "^password\s+sufficient\s+pam_unix.so.*sha512" /etc/pam.d/common-auth) -eq 1 ]] || state=1
#    [[ $(egrep -c "^password\s+sufficient\s+pam_unix.so.*sha512" /etc/pam.d/common-password) -eq 1 ]] || state=1
    [[ $state -eq 0 ]] && result="Pass"
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    #write_cache "7,Requirement 7"
    write_result "$id,$description,$scored,$result,$time"
}

test_8_2_3() {
    id=$1
    description="Ensure password min lenght is 7 character"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
    [[ $(egrep -c "^password\s+requisite\s+(pam_cracklib.so|pam_pwquality.so)\s+*minlen*=7" /etc/pam.d/system-auth 2>&1) -eq 1 ]] || state=1
    [[ $(egrep -c "^password\s+requisite\s+(pam_cracklib.so|pam_pwquality.so)\s+*minlen*=7" /etc/pam.d/password-auth 2>&1) -eq 1 ]] || state=1
#    [[ $(egrep -c "^password\s+requisite\s+(pam_cracklib.so|pam_pwquality.so)\s+*minlen*=7" /etc/pam.d/common-auth 2.&1) -eq 1 ]] || state=1
#    [[ $(egrep -c "^password\s+requisite\s+(pam_cracklib.so|pam_pwquality.so)\s+*minlen*=7" /etc/pam.d/common-password 2>&1) -eq 1 ]] || state=1

    [[ $state -eq 0 ]] && result="Pass"
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    #write_cache "7,Requirement 7"
    write_result "$id,$description,$scored,$result,$time"
}

test_8_2_3_1() {
    id=$1
    description="Ensure password include numbers"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
    [[ $(egrep -c "dcredit=1" /etc/pam.d/system-auth 2>&1) -eq 1 ]] || state=1
    [[ $(egrep -c "dcredit=1" /etc/pam.d/password-auth 2>&1) -eq 1 ]] || state=1
#    [[ $(egrep -c "dcredit=1" /etc/pam.d/common-auth 2>&1) -eq 1 ]] || state=1
#    [[ $(egrep -c "dcredit=1" /etc/pam.d/common-password 2>&1) -eq 1 ]] ||state=1    

    [[ $state -eq 0 ]] && result="Pass"
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    #write_cache "7,Requirement 7"
    write_result "$id,$description,$scored,$result,$time"
}

test_8_2_4() {
    id=$1
    description="Ensure password change in every 90 days"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
ex=`cat /etc/login.defs 2>&1 | grep "^PASS_MAX_DAYS" | awk '{print $2}'`

    [[ "$ex" == "90" ]] && result="Pass" || result="Fail"
    ## Tests End ##
    write_info "login.defs config" "`cat /etc/login.defs`"
    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    #write_cache "7,Requirement 7"
    write_result "$id,$description,$scored,$result,$time"
}

test_8_2_4_1() {
    id=$1
    description="Ensure user get warning before 7d of pass exp"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
wa=`cat /etc/login.defs 2>&1 | grep "^PASS_WARN_AGE" | awk '{print $2}'`

    [[ "$wa" == "7" ]] && result="Pass" || result="Fail"
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    #write_cache "7,Requirement 7"
    write_result "$id,$description,$scored,$result,$time"
}

test_8_2_5_a() {
    id=$1
    description="Ensure user cant use last 4 password"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
[[ $(cat /etc/pam.d/common-auth 2>&1 | grep "remember=4") -eq 0 ]] || state=1
[[ $(cat /etc/pam.d/system-auth 2>&1 | grep "remember=4") -eq 0 ]] || state=1
#[[ $(cat /etc/pam.d/common-password 2>&1 | grep "remember=4") -eq 0 ]] || state=1
#[[ $(cat /etc/pam.d/password-auth 2>&1 | grep "remember=4") -eq 0 ]] || state=1

    [[ $state -eq 0 ]] && result="Pass" || result="Fail"
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    #write_cache "7,Requirement 7"
    write_result "$id,$description,$scored,$result,$time"
}

test_8_2_6() {
    id=$1
    description="Ensure user change password after 1st login"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
[[ $(cat /etc/default/useradd 2>&1 | grep "EXPIRE=0") -eq 0 ]] || state=1

    [[ $state -eq 0 ]] && result="Pass" || result="Fail"
    ## Tests End ##
    write_info "useradd Config file" "`cat /etc/default/useradd`"
    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    #write_cache "7,Requirement 7"
    write_result "$id,$description,$scored,$result,$time"
}

test_8_3() {
    id=$1
    description="Ensure user use multifactor auth"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
[[ $(egrep -w 'pam_google_authenticator.so|pam_yubikey.so' /etc/pam.d/system-auth 2>&1) -eq 0 ]] || state=1
[[ $(egrep -w 'pam_google_authenticator.so|pam_yubikey.so' /etc/pam.d/password-auth 2>&1) -eq 0 ]] || state=1
#[[ $(egrep -w 'pam_google_authenticator.so|pam_yubikey.so' /etc/pam.d/common-auth 2>&1) -eq 0 ]] || state=1
#[[ $(egrep -w 'pam_google_authenticator.so|pam_yubikey.so' /etc/pam.d/common-password 2>&1) -eq 0 ]] || state=1

    [[ $state -eq 0 ]] && result="Pass" || result="Fail"
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    #write_cache "7,Requirement 7"
    write_result "$id,$description,$scored,$result,$time"
}

test_8_3_a() {
    id=$1
    description="Ensure user use radius token for auth"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
[[ $(cat /etc/pam.d/sshd 2>&1 | grep "pam_radius_auth.so") -eq 0 ]] || state=1
[[ $(cat /etc/pam.d/sudo 2>&1 | grep "pam_radius_auth.so") -eq 0 ]] || state=1

    [[ $state -eq 0 ]] && result="Pass" || result="Fail"
    ## Tests End ##
    write_info "pam sshd Config file" "`cat /etc/pam.d/sshd`"
    write_info "pam sudo Config file" "`cat /etc/pam.d/sudo`"
    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    #write_cache "7,Requirement 7"
    write_result "$id,$description,$scored,$result,$time"
}

test_8_3_b() {
    id=$1
    description="Ensure user use TACACS token for auth"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
[[ -f /etc/pam.d/tacacs ]] 2>&1 || state=1
[[ ! -z $(grep pam_tacplus.so /etc/pam.d/tacacs 2>&1) ]] || state=2
[[ ! -z $(grep pam_tacplus.so /etc/pam.d/sudo 2>&1) ]] || state=3

    [[ $state -eq 0 ]] && result="Pass"
    ## Tests End ##
    write_info "pam tacacs Config file" "`cat /etc/pam.d/tacacs 2>&1`"
    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    #write_cache "7,Requirement 7"
    write_result "$id,$description,$scored,$result,$time"
}

#********************************************************************************

test_10_1_a() {
    id=$1
    description="Ensure auditd is installed"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)
    
    ## Tests Start ##
if [[ ! -z $(rpm -qa audit* 2>&1) ]] || [[ ! -z $(dpkg -l 2>&1 | grep audit*) ]]; then
result="Pass"
else
result="Fail"
fi 
    ## Tests End ##
    
    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    write_cache "10,Requirement 10"
    write_result "$id,$description,$scored,$result,$time"
}

test_10_1_b() {
    id=$1
    description="Ensure auditd service is enabled"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)
    
    ## Tests Start ##

[[ "$(systemctl is-enabled auditd 2>&1)" = "enabled" ]] && result="Pass" || result="Fail"
   
    ## Tests End ##
    
    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    #write_cache "10,Requirement 10"
    write_result "$id,$description,$scored,$result,$time"
}

test_10_1_c() {
    id=$1
    description="Ensure auditd service is active"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)
    
    ## Tests Start ##

[[ "$(systemctl is-active auditd 2>&1)" = "active" ]] && result="Pass" || result="Fail"

    ## Tests End ##
    write_info "Auditd service status" "`systemctl status auditd`"
    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    
    #write_cache "10,Requirement 10"
    write_result "$id,$description,$scored,$result,$time"
}

test_10_2() {
    id=$1
    description="Ensure auditd.conf configured"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)
    
    ## Tests Start ##

    [[ -f /etc/audit/auditd.conf ]] && result="Pass" || result="Fail"

    write_info "auditd.conf file config" "`cat /etc/audit/auditd.conf`"
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    
    #write_cache "10,Requirement 10"
    write_result "$id,$description,$scored,$result,$time"
}


test_10_2_a() {
    id=$1
    description="Ensure audit log rules configured"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)
    
    ## Tests Start ##

[[ ! -z $(auditctl -l 2>&1) ]]  && result="Pass" || result="Fail"

    write_info "audit rules" "`auditctl -l`"
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    
    #write_cache "10,Requirement 10"
    write_result "$id,$description,$scored,$result,$time"
}

test_10_2_1() {
    id=$1
    description="Ensure auditd log file exist"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)
    
    ## Tests Start ##

[[ -f /var/log/audit/audit.log ]] && result="Pass" || result="Fail"

    write_info "auditd log file" "`cat /var/log/audit/audit.log 2>&1`"
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    
    #write_cache "10,Requirement 10"
    write_result "$id,$description,$scored,$result,$time"
}

test_10_2_3() {
    id=$1
    description="Ensure audit.log r/w only by root"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)
    
    ## Tests Start ##

[[ "$(ls -alth /var/log/audit/audit.log 2>&1 | awk '{print $3}')" = "root" ]] && [[ "$(ls -alth /var/log/audit/audit.log 2>&1 | awk '{print $1}')" == "-rw-------." ]] && result="Pass" || result="Fail"

    #write_info "auditd log file" "`cat /var/log/audit/audit.log 2>&1`"
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    
    #write_cache "10,Requirement 10"
    write_result "$id,$description,$scored,$result,$time"
}

test_10_2_4_a() {
    id=$1
    description="Ensure user login attempts are logged"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)
    
    ## Tests Start ##

[[ ! $(ausearch -m USER_LOGIN 2>&1) ]] && state=1 || state=0 
        
        [[ $state -eq 0 ]] && result="Pass"
    #write_info "user login attempt" "`ausearch -m USER_LOGIN 2>&1`"
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    
    #write_cache "10,Requirement 10"
    write_result "$id,$description,$scored,$result,$time"
}

test_10_2_4_b() {
    id=$1
    description="Ensure INVALID login attempts are logged"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)
    
    ## Tests Start ##

[[ ! $(ausearch --exit -13 2>&1) ]] && state=1 || state=0 
        
        [[ $state -eq 0 ]] && result="Pass"
    #write_info "user login attempt" "ausearch -m USER_LOGIN"
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    
    #write_cache "10,Requirement 10"
    write_result "$id,$description,$scored,$result,$time"
}

test_10_2_5_c() {
    id=$1
    description="Ensure config chnage is logged"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)
    
    ## Tests Start ##

[[ ! -z $(ausearch -i 2>/dev/null | grep type=CONFIG_CHANGE) ]] && result="Pass" || result="Fail"

    #write_info "config change log" "ausearch -i | grep -i type=CONFIG_CHANGE"
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    
    #write_cache "10,Requirement 10"
    write_result "$id,$description,$scored,$result,$time"
}

test_10_2_6_b() {
    id=$1
    description="Ensure stoping/pausing of service is logged"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)
    
    ## Tests Start ##

[[ ! -z $(ausearch -i 2>&1 | grep "SERVICE_STOP") ]] && result="Pass" || result="Fail"

    #write_info "auditd log file" "cat /var/log/audit/audit.log"
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    
    #write_cache "10,Requirement 10"
    write_result "$id,$description,$scored,$result,$time"
}

#********************************************************************************
test_10_4() {
    id=$1
    description="Ensure chrony is configured"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)
    
    ## Tests Start ##
    state=0
if [[ $( rpm -q chrony &>/dev/null; echo $? ) -eq 0 ]]; then
        egrep "^(server|pool) .*$" /etc/chrony.conf &>/dev/null || state=$(( $state + 1 ))
        
        if [[ -f /etc/sysconfig/chronyd ]]; then
            [[ $( grep -c 'OPTIONS="-u chrony' /etc/sysconfig/chronyd 2>&1 ) -eq 0 ]] && state=$(( $state + 2 ))
        else
            state=$(( $state + 4 ))
        fi
        
        [[ $state -eq 0 ]] && result="Pass"
    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    else
        scored="Skipped"
        result=""
    fi
    ## Tests End ##
    write_info "Chrony Config file" "`cat /etc/chrony.conf 2>&1`"
    write_info "Chronyd Config file" "`cat /etc/sysconfig/chronyd`"
    #write_cache "10,Requirement 10"
    write_result "$id,$description,$scored,$result,$time"
}

test_10_4_1() {
    id=$1
    description="Ensure time synchronisation is in use"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)
    
    ## Tests Start ##
[[ $(rpm -q ntp &>/dev/null; echo $?) -eq 0 ]] || [[ $(rpm -q chrony &>/dev/null; echo $?) -eq 0 ]] && result="Pass"
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    #write_cache "10,Requirement 10"
    write_result "$id,$description,$scored,$result,$time"
}

test_10_4_b() {
    id=$1
    description="Ensure ntp is configured"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)
    
    ## Tests Start ##
if [[ $( rpm -q ntp &>/dev/null; echo $?) -eq 0 ]]; then
        grep "^restrict -4 default kod nomodify notrap nopeer noquery" /etc/ntp.conf &>/dev/null || state=1
        grep "^restrict -6 default kod nomodify notrap nopeer noquery" /etc/ntp.conf &>/dev/null || state=2
        [[ $(egrep -c "^(server|pool) .*$" /etc/ntp.conf 2>/dev/null) -ge 2 ]] || state=4
        [[ -f /etc/systemd/system/ntpd.service ]] && file="/etc/systemd/system/ntpd.service" || file="/usr/lib/systemd/system/ntpd.service"
        [ $(grep -c 'OPTIONS="-u ntp:ntp' /etc/sysconfig/ntpd) -ne 0 -o $(grep -c 'ExecStart=/usr/sbin/ntpd -u ntp:ntp $OPTIONS' $file) -ne 0 ] || state=8
        
        [[ $state -eq 0 ]] && result="Pass"
    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    else
        scored="Skipped"
        result=""
    fi
    ## Tests End ##
    write_info "NTPD Config file" "`cat /etc/sysconfig/ntpd 2>&1`"
    write_info "NTP Config file" "`cat /etc/ntp.conf 2>&1`"
    #write_cache "10,Requirement 10"
    write_result "$id,$description,$scored,$result,$time"
}

test_10_4_2() {
    id=$1
    description="Ensure clock change is logged"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)
    
    ## Tests Start ##

[[ $(auditctl -l 2>&1 | grep "clock_settime") -eq 0 ]] || state=1 
        
        [[ $state -eq 0 ]] && result="Pass"
    #write_info "clock change logs" "auditctl -l | grep '-S clock_settime'"
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    time=`printf "%.2f sec" $duration`
    
    #write_cache "10,Requirement 10"
    write_result "$id,$description,$scored,$result,$time"
}

#********************************************************************************
    system_info

    test_1_1
    test_1_1_1
    test_1_1_4
    test_1_1_6
    test_1_1_6_b
    test_1_1_6_b_2
    test_1_1_6_b_3
    test_1_1_6_b_3a
    test_1_1_6_b_4
    test_1_1_6_b_5
    test_1_1_6_b_6
    test_1_1_6_b_7
    test_1_1_6_b_8
    test_1_1_6_b_9
    test_1_1_6_b_10
    test_1_1_6_b_11
    test_1_1_6_b_12
    test_1_2_1
    test_1_2_1_c
    test_1_3_2
    test_1_3_3
    test_1_3_5
    test_1_3_7
    test_1_3_7_a
    test_1_4_a

    test_2_1 
    test_2_2_2
    test_2_2_2_a
    test_2_2_5
    test_2_2_5_a
    test_2_2_5_b
    test_2_3_a    
    test_2_3_b
    test_2_3_c
    test_2_3_d
    test_2_3_e

    test_4_1_a
    test_4_1_b
    test_4_1_c
    test_4_1_d
    test_4_1_e

    test_5_1
    test_5_2_a
    test_5_2_b
    test_5_2_c
    test_5_2_d
    test_5_2_e
    test_5_2_f
    test_5_2_g
    test_5_3_a
    test_5_3_b
    test_5_3_c
    test_5_3_d
    test_5_3_e
    test_5_3_f
    test_5_3_g

    test_6_1
    test_6_1_a
    test_6_1_b
    test_6_1_c
    test_6_2
    test_6_2_a

    test_7_1
    test_7_2
    test_7_2_a
    test_7_2_b
    test_7_2_c
    test_7_2_d
    test_7_2_e
    test_7_2_f
    
    test_8_1
    test_8_1_1_a
    test_8_1_1_b
    test_8_1_1_c
    test_8_1_1_d
    test_8_1_1_e
    test_8_1_1_f
    test_8_1_1_h
    test_8_1_1_i
    test_8_1_4
    test_8_1_6
    test_8_1_7
    test_8_1_8
    test_8_2
    test_8_2_3
    test_8_2_3_1
    test_8_2_4
    test_8_2_4_1
    test_8_2_5_a
    test_8_2_6
    test_8_3
    test_8_3_a
    test_8_3_b

    test_10_1_a
    test_10_1_b
    test_10_1_c
    test_10_2
    test_10_2_a    
    test_10_2_3
    test_10_2_4_a
    test_10_2_4_b
    test_10_2_5_c
    test_10_2_6_b
    test_10_4
    test_10_4_b
    test_10_4_1
    test_10_4_2


    outputter 

