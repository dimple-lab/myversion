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
    echo "|-------------------PCI DSS Benchmark v3.2.1 Results----------------|"
    echo "|-------------------------------------------------------------------|"
    
    if [ -t 1 -a $color == "True" ]; then
        (
            echo "ID,Description,Scored,Result,Execution_time"
            echo "--,-----------,------,------,--------------"
            cat $tmp_file
        ) | column -t -s , |\
            sed -e $'s/^[0-9]\s.*$/\\n\e[1m&\e[22m/' \
                -e $'s/^[0-9]\.[0-9]\s.*$/\e[1m&\e[22m/' \
                -e $'s/\sFail\s/\e[31m&\e[39m/' \
                -e $'s/\sPass\s/\e[32m&\e[39m/' \
                -e $'s/^.*\sSkipped\s.*$/\e[2m&\e[22m/'
    else
        (
            echo "ID,Description,Scored,Result,Execution_time"
            cat $tmp_file
        ) | column -t -s , | sed -e '/^[0-9]\ / s/^/\n/'
    fi
    
    tests_total=$(grep -c "Scored" $tmp_file)
    tests_skipped=$(grep -c ",Skipped," $tmp_file)
    tests_ran=$(( $tests_total - $tests_skipped ))
    tests_passed=$(egrep -c ",Pass," $tmp_file)
    tests_failed=$(egrep -c ",Fail," $tmp_file)
    tests_errored=$(egrep -c ",Error," $tmp_file)
    tests_execution_time=$(echo "$(date +%s.%N) - $start_time" | bc)
    
    echo
    echo "Passed $tests_passed of $tests_total tests in $tests_execution_time seconds ($tests_skipped Skipped, $tests_errored Errors)"
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
    echo -e "\e[34m---------------'$heading'------------------\e[0m" >> $info_file
    echo "$@\n" >> $info_file
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

    write_result "$id,$description,$scored,$result,$execution_time"
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
	execution_time=`printf "%.2f seconds" $duration`
   # duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$result,$execution_time"
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
	execution_time=`printf "%.2f seconds" $duration`
    #duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$result,$execution_time"
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
	execution_time=`printf "%.2f seconds" $duration`

    write_result "$id,$description,$scored,$result,$execution_time"
}

#===============================================================================
#Actual test starts from here

echo "Here we start" > $info_file
echo "Requirement 1: Install and maintain a firewall configuration to protect cardholder data" >> $info_file
write_cache "1,Requirement 1"

test_1_1() {
    id=$1
    description="Firewalld is activated and running"
    scored="Scored"

### new script
        start=$(date +%s.%N)
        [ "$(firewall-cmd --state)" == "running" ] && result="Pass" || result="Fail"
        duration=$(echo "$(date +%s.%N) - $start" | bc)
        execution_time=`printf "%.2f seconds" $duration`
        #write_cache "1.1,Check firewall Configuration"
        write_result "$id,$description,$scored,$result,$execution_time"
}


test_1_1_1() {
    id=$1
    description="IPTABLES rules configured"
    scored="Scored"

### new script
        start=$(date +%s.%N)
        write_info IPTABLES _L "`iptables -L`"  
        [[ -f /etc/sysconfig/iptables ]] && result="Pass" || [[ -f /etc/iptables.up.rules ]] && result="Pass" || result="Fail"
        duration=$(echo "$(date +%s.%N) - $start" | bc)
        execution_time=`printf "%.2f seconds" $duration`
        #write_cache "1.1-a,Checking egrees and ingress traffic"
        write_result "$id,$description,$scored,$result,$execution_time"
}

test_1_1_4() {
    id=$1
    description="Firewall Zones available"
    scored="Scored"

### new script
        start=$(date +%s.%N)
        
###start test
echo "###################### Zones Available #######################" >> $info_file
firewall-cmd --get-zones >> $info_file

echo "###################### Activated Zones #######################" >> $info_file
firewall-cmd --get-active-zones >> $info_file

[[ ! `firewall-cmd --get-zones | grep 'dmz'` ]] && result="Fail" || result="Pass"
###end test
        duration=$(echo "$(date +%s.%N) - $start" | bc)
        execution_time=`printf "%.2f seconds" $duration`
        #write_cache "1.1-a,Checking egrees and ingress traffic"
        write_result "$id,$description,$scored,$result,$execution_time"

}

test_1_1_6() {
    id=$1
    description="ICMP is blocked"
    scored="Scored"

### new script
        start=$(date +%s.%N)

###start test

echo "################## list ports in public zone #################" >> $info_file
firewall-cmd --zone=public --list-ports  >> $info_file 2>&1
echo "################## ICMP block in public zone #################" >> $info_file
firewall-cmd --zone=public --list-icmp-blocks >> $info_file 2>&1
echo "###################### all services running ##################" >> $info_file
firewall-cmd --list-services  >> $info_file 2>&1
echo "###################### Ports have been used ##################" >> $info_file
sudo lsof -i -P -n 2>&1 | grep LISTEN  >> $info_file 2>&1

res=`cat /proc/sys/net/ipv4/icmp_echo_ignore_all 2>&1`
[[ "$res" -eq "0" ]] && result="Fail" || result="Pass"

###end test
        duration=$(echo "$(date +%s.%N) - $start" | bc)
        execution_time=`printf "%.2f seconds" $duration`
        #write_cache "1.1-a,Checking egrees and ingress traffic"
        write_result "$id,$description,$scored,$result,$execution_time"
}

test_1_1_6_b() {
    id=$1
    description="IPv6 is disabled"
    scored="Scored"

### new script
        start=$(date +%s.%N)
###Test Starts
v6=`cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>&1`
[[ "$v6" -eq "0" ]] && result="Fail" || result="Pass"

###Test Ends
        duration=$(echo "$(date +%s.%N) - $start" | bc)
        execution_time=`printf "%.2f seconds" $duration`
        write_result "$id,$description,$scored,$result,$execution_time"
}

test_1_1_6_b_2() {
    id=$1
    description="OS Version is Minimal"
    scored="Scored"

### new script
        start=$(date +%s.%N)

###Start Test
min=`awk '/Minimal/{print}' /etc/os-release 2>&1`
[ ! "$min" ] && result="Fail" || result="Pass"
###End Test
        duration=$(echo "$(date +%s.%N) - $start" | bc)
        execution_time=`printf "%.2f seconds" $duration`
        write_result "$id,$description,$scored,$result,$execution_time"
}

test_1_1_6_b_3() {
    id=$1
    description="Checking NFS-server is not running"
    scored="Scored"

### new script
        start=$(date +%s.%N)
###Start Test
[[ "`systemctl is-active nfs-kernel-server`" == "active" ]] && result="Fail" || result="Pass"
###end test
        duration=$(echo "$(date +%s.%N) - $start" | bc)
        execution_time=`printf "%.2f seconds" $duration`
        write_result "$id,$description,$scored,$result,$execution_time"
}

test_1_1_6_b_4() {
    id=$1
    description="Checking Print service not running"
    scored="Scored"

### new script
        start=$(date +%s.%N)
###Start Test
print=`systemctl is-active cups.service`
[[ "$print" == "active"  ]] && result="Fail" || result="Pass"
###end test
        duration=$(echo "$(date +%s.%N) - $start" | bc)
        execution_time=`printf "%.2f seconds" $duration`
        write_result "$id,$description,$scored,$result,$execution_time"
}

test_1_1_6_b_5() {
    id=$1
    description="Checking FTP is not running"
    scored="Scored"

### new script
        start=$(date +%s.%N)
###Start Test
ftp=`systemctl is-active ftp`
[[ "$ftp" == "active"  ]] && result="Fail" || result="Pass"
###end test
        duration=$(echo "$(date +%s.%N) - $start" | bc)
        execution_time=`printf "%.2f seconds" $duration`
        write_result "$id,$description,$scored,$result,$execution_time"
}

test_1_1_6_b_6() {
    id=$1
    description="Checking telent is not running"
    scored="Scored"

### new script
        start=$(date +%s.%N)
###Start Test
tel=`systemctl is-active telnet`
[[ "$tel" == "active"  ]] && result="Fail" || result="Pass"
###end test
        duration=$(echo "$(date +%s.%N) - $start" | bc)
        execution_time=`printf "%.2f seconds" $duration`
        write_result "$id,$description,$scored,$result,$execution_time"
}

test_1_1_6_b_7() {
    id=$1
    description="Checking NIS service not running"
    scored="Scored"

### new script
        start=$(date +%s.%N)
###Start Test

var1=`systemctl is-active ypsrv ypbind`
[[ "$var1" == "active"  ]] && result="Fail" || result="Pass"
###end test
        duration=$(echo "$(date +%s.%N) - $start" | bc)
        execution_time=`printf "%.2f seconds" $duration`
        write_result "$id,$description,$scored,$result,$execution_time"
}

test_1_1_6_b_8() {
    id=$1
    description="Checking SMTP service is not running"
    scored="Scored"

### new script
        start=$(date +%s.%N)
###Start Test
var2=`systemctl is-active sendmail postfix`
[[ "$var2" == "active"  ]] && result="Fail" || result="Pass"

###end test
        duration=$(echo "$(date +%s.%N) - $start" | bc)
        execution_time=`printf "%.2f seconds" $duration`
        write_result "$id,$description,$scored,$result,$execution_time"
}

test_1_1_6_b_9() {
    id=$1
    description="Checking HTTP is not running"
    scored="Scored"

### new script
        start=$(date +%s.%N)
###Start Test
var3=`systemctl is-active http httpd apache`
[[ "$var3" == "active"  ]] && result="Fail" || result="Pass"
###end test
        duration=$(echo "$(date +%s.%N) - $start" | bc)
        execution_time=`printf "%.2f seconds" $duration`
        write_result "$id,$description,$scored,$result,$execution_time"

}

test_1_1_6_b_10() {
    id=$1
    description="Checking SNMP is not running"
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

    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    execution_time=`printf "%.2f seconds" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$execution_time"
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
    
    duration=$(echo "$(date +%s.%N) - $start" | bc)
    execution_time=`printf "%.2f seconds" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$execution_time"
}

test_1_1_6_b_12() {
    id=$1
    description="Checking Dev tools not installed"
    scored="Scored"

    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
    yum grouplist 2>&1 | grep "Development Tools" >> $info_file || dnf grouplist 2>&1 | grep "Development Tools" >> $info_file || pacman -Sg Developement Tools >> $info_file 2>&1 || tasksel --task-desc "Development Tools" >> $info_file 2>&1 || zypper info pattern "Development Tools" >> $info_file 2>&1
    [ ! $@ ] && result="Fail" || result="Pass"
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    execution_time=`printf "%.2f seconds" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$execution_time"
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
    execution_time=`printf "%.2f seconds" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$execution_time"
}


test_1_2_1_c() {
    id=$1
    description="Checking rich rule configured"
    scored="Scored"

    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
 echo "========================================================================" >>$info_file   
 echo "firewall-cmd --list-all" >> $info_file
 `firewall-cmd --list-all` >> $info_file 2>&1
 rich=`firewall-cmd --list-rich-rules`
 [[ ! $rich ]] && result="Fail" || result="Pass"
 echo "========================================================================" >>$info_file
 echo "firewall-cmd --get-services" >> $info_file
 `firewall-cmd --get-services` >> $info_file 2>&1
 echo "========================================================================" >>$info_file
 echo "firewall-cmd --get-zones" >> $info_file
 `firewall-cmd --get-zones` >> $info_file 2>&1
 echo "========================================================================" >>$info_file
 echo "firewall-cmd --get-active-zones" >> $info_file
 `firewall-cmd --get-active-zones` >> $info_file 2>&1
 echo "========================================================================" >>$info_file
 echo "firewall-cmd --list-services" >> $info_file
 firewall-cmd --list-services >> $info_file 2>&1
echo "========================================================================" >>$info_file
 echo "firewall-cmd --list-forward-ports" >> $info_file
 `firewall-cmd --list-forward-ports` >> $info_file 2>&1
echo "========================================================================" >>$info_file
 echo "firewall-cmd --list-icmp-blocks" >> $info_file
 `firewall-cmd --list-icmp-blocks` >> $info_file 2>&1
echo "========================================================================" >>$info_file
 echo "firewall-cmd --list-protocols" >> $info_file
 `firewall-cmd --list-protocols` >> $info_file 2>&1
###Test Ends
    duration=$(echo "$(date +%s.%N) - $start" | bc)
    execution_time=`printf "%.2f seconds" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$execution_time"
}

test_1_2_2() {
    id=$1
    description="firewalld enabled at boot"
    scored="Scored"

    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
[[ "`systemctl is-enabled firewalld`" == "enabled" ]] && result="Pass" || result="Fail"
    ## Test Ends ##
    duration=$(echo "$(date +%s.%N) - $start" | bc)
    execution_time=`printf "%.2f seconds" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$execution_time"
}

test_1_3_2() {
    id=$1
    description="DMZ Active"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
    dmz=`firewall-cmd --get-active-zones 2>&1 | grep dmz`
    [ ! $dmz ] && result="Fail" || result="Pass" && echo $dmz >> $info_file  
    ## Tests End ##
    echo "=======================================================================" >> $info_file
    echo "firewall-cmd --zone=dmz --list-ports" >> $info_file
    firewall-cmd --zone=dmz --list-ports  >> $info_file 2>&1
echo "======================================================================="
 >> $info_file
    echo "firewall-cmd --zone=dmz --list-protocols" >> $info_file
    firewall-cmd --zone=dmz --list-protocols >> $info_file 2>&1
echo "======================================================================="
 >> $info_file
    echo "firewall-cmd --zone=dmz --list-services" >> $info_file
    firewall-cmd --zone=dmz --list-services >> $info_file 2>&1

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    execution_time=`printf "%.2f seconds" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$execution_time"
}

test_1_3_3() {
    id=$1
    description="Source add. verification exist"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
sad=`cat /proc/sys/net/ipv4/conf/default/rp_filter 2>&1`
[[ "$sad" -eq "0" ]] && result="Fail" || result="Pass" && echo "Source address verification enabled" >> $info_file
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    execution_time=`printf "%.2f seconds" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$execution_time"
}

test_1_3_5() {
    id=$1
    description="Established conn config exist"
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
    execution_time=`printf "%.2f seconds" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$execution_time"
}

test_1_3_7() {
    id=$1
    description="IP Forwarding enabled"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
ipf=`cat /proc/sys/net/ipv4/ip_forward 2>&1`
[[ "$ipf" -eq "0" ]] && result="Fail" || result="Pass" && echo "IP Forwarding enabled" >> $info_file
echo "NAT rules in firewall/iptable config" >> $info_file
egrep -w 'POSTROUTING|PREROUTING|MASQUERADE|DNAT|SNAT|REDIRECT' /etc/sysconfig/iptables  >>$info_file 2>&1 || egrep -w 'POSTROUTING|PREROUTING|MASQUERADE|DNAT|SNAT|REDIRECT' /etc/iptables.up.rules >> $info_file 2>&1 
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    execution_time=`printf "%.2f seconds" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$execution_time"
}

test_1_3_7_a() {
    id=$1
    description="Proxy used for o/g traffic"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
proxy=`cat /etc/profile 2>&1 | grep http_proxy`
[[ ! $proxy ]] && result="Fail" || result="Pass" && echo "Proxy setting configued as $proxy\n" >> $info_file 
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    execution_time=`printf "%.2f seconds" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$execution_time"
}

test_1_4_a() {
    id=$1
    description="iptables service is running"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
ip=`systemctl is-active iptables`
[[ "$ip" == "active" ]] && result="Pass" || result="Fail"
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    execution_time=`printf "%.2f seconds" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$execution_time"
}
   
echo "Requirement 2: Do not use vendor-supplied defaults for system passwords and other security parameters" >> $info_file


test_2_1() {
    
    id=$1
    description="User account"
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
echo "----------[ Normal User Accounts ]---------------" >> $info_file
awk -F':' -v "min=${l##UID_MIN}" -v "max=${l1##UID_MAX}" '{ if ( $3 >= min && $3 <= max  && $7 != "/sbin/nologin" ) print $0 }' "$_p" >>   $info_file
echo ""
echo "----------[ System User Accounts ]---------------" >>   $info_file
awk -F':' -v "min=${l##UID_MIN}" -v "max=${l1##UID_MAX}" '{ if ( !($3 >= min && $3 <= max  && $7 != "/sbin/nologin")) print $0 }' "$_p" >>   $info_file
## Tests End ##


    duration=$(echo "$(date +%s.%N) - $start" | bc)
    execution_time=`printf "%.2f seconds" $duration`
    write_cache "2,Requirement 2"
    write_result "$id,$description,$scored,$result,$execution_time"


}

test_2_2_2() {
    id=$1
    description="Listing services enabled at boot"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
en=`systemctl list-unit-files --state=enabled 2>&1`
[[ ! $en ]] && result="Fail" || result="Pass" && echo "$en"  >> $info_file
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    execution_time=`printf "%.2f seconds" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$execution_time"
}

test_2_2_2_a() {
    id=$1
    description="Listing loded services"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
sr=`systemctl list-units --type service 2>&1`
[[ ! $sr ]] && result="Fail" || result="Pass" && echo "$sr"  >> $info_file
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    execution_time=`printf "%.2f seconds" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$execution_time"
}

test_2_2_5() {
    id=$1
    description="Listing Installed drivers"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
dr=`find /lib/modules/$(uname -r)/kernel/ -name '*.ko*' 2>&1`
[[ ! $dr ]] && result="Fail" || result="Pass" && echo "$dr"  >> $info_file
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    execution_time=`printf "%.2f seconds" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$execution_time"
}

test_2_2_5_a() {
    id=$1
    description="Listing Mounted disks"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
ds=`sudo fdisk -l 2>&1`
[[ ! $ds ]] && result="Fail" || result="Pass" && echo "$ds"  >> $info_file
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    execution_time=`printf "%.2f seconds" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$execution_time"
}

test_2_2_5_b() {
    id=$1
    description="Checking size of Cache files"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
ds=`sudo du -sh /var/cache/* 2>&1`
[[ ! $ds ]] && result="Fail" || result="Pass" && echo "$ds"  >> $info_file
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    execution_time=`printf "%.2f seconds" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$execution_time"
}

test_2_3_a() {
    id=$1
    description="Non-console telnet is not active"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
tel=`sudo systemctl is-active telnet 2>&1`
[[ "$tel" == "active" ]] && result="Fail" || result="Pass"
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    execution_time=`printf "%.2f seconds" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$execution_time"
}

test_2_3_b() {
    id=$1
    description="Non-console rsh is not active"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
rsh=`sudo systemctl is-active rsh.socket 2>&1`
[[ "$rsh" == "active" ]] && result="Fail" || result="Pass"
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    execution_time=`printf "%.2f seconds" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$execution_time"
}

test_2_3_c() {
    id=$1
    description="Non-console rlogin is not active"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
rl=`sudo systemctl is-active rlogin.socket 2>&1`
[[ "$rl" == "active" ]] && result="Fail" || result="Pass"
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    execution_time=`printf "%.2f seconds" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$execution_time"
}

test_2_3_d() {
    id=$1
    description="Non-console rpc is not active"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
rpc=`sudo systemctl is-active rpcbind 2>&1`
[[ "$rpc" == "active" ]] && result="Fail" || result="Pass"
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    execution_time=`printf "%.2f seconds" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$execution_time"
}

test_2_3_e() {
    id=$1
    description="Encryption used in ssh"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
encr=`sudo cat /etc/ssh/sshd_config | grep UsePAM | awk '{print $2}' 2>&1`
[[ "$encr" == "yes" ]] && result="Pass" || result="Fail"
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    execution_time=`printf "%.2f seconds" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$execution_time"
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
    write_info $tls13
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    execution_time=`printf "%.2f seconds" $duration`
    write_cache "4,Requirement 4"
    write_result "$id,$description,$scored,$result,$execution_time"
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
    write_info $tls12
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    execution_time=`printf "%.2f seconds" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$execution_time"
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
    write_info $tls11
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    execution_time=`printf "%.2f seconds" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$execution_time"
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
    write_info $tls1
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    execution_time=`printf "%.2f seconds" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$execution_time"
}

#********************************************************************************

test_4_1_e() {
    id=$1
    description="Checking server accept with NULL cipher"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
tlsnull=`sudo echo "x" |openssl s_client -connect google.com:443 -cipher NULL,LOW 2>&1`
[[ ! "$tlsnull" ]] && result="Fail" || result="Pass"
    write_info $tlsnull
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    execution_time=`printf "%.2f seconds" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$execution_time"
}

#********************************************************************************

test_5_1() {
    id=$1
    description="Check ClamAV is installed or not"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
if [[ $(rpm -qa 2>&1 | egrep -w 'clamav') || $(dpkg -l 2>&1 | egrep 'clamav') ]]; then
result="Pass"
else
result="Fail"
fi
    #write_info $(rpm -qa 2>&1 | grep clamav*) || $(dpkg -l 2>&1 | grep clamav*) 
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    execution_time=`printf "%.2f seconds" $duration`
    write_cache "5,Requirement 5"
    write_result "$id,$description,$scored,$result,$execution_time"
}
#********************************************************************************

test_5_2_a() {
    id=$1
    description="Clamav is enabled at boot"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##

clam1=`systemctl is-enabled clamav 2>&1`
if [[ "$clam1" == "enabled" ]]; then 
result="Pass" 
else result="Fail"
fi

    #write_info $clam1
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    execution_time=`printf "%.2f seconds" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$execution_time"
}
#********************************************************************************

test_5_2_b() {
    id=$1
    description="Clamav service is running"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
clam2=`systemctl is-active clamav 2>&1`
#clam3=`systemctl status clamav`
if [[ "$clam2" == "active" ]]; then 
result="Pass" 
else 
result="Fail"
fi
    #write_info $clam2
    #write_info $clam3
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    execution_time=`printf "%.2f seconds" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$execution_time"
}
#********************************************************************************

test_5_2_c() {
    id=$1
    description="Checking Cronjob for Clamav"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
clam4=`crontab -l 2>&1 | grep *clamav*`
[[ ! "$clam4" ]] && result="Fail" || result="Pass"
    #write_info $clam4
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    execution_time=`printf "%.2f seconds" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$execution_time"
}
#********************************************************************************

test_5_2_d() {
    id=$1
    description="Checking Daily Cron for Clamav"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
if [[ -f /etc/cron.daily/*clamav* ]]; 
then result="Pass" 
else result="Fail"
fi
    #write_info "`cat /etc/cron.daily/*clamav*| grep -v "#"`"
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    execution_time=`printf "%.2f seconds" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$execution_time"
}
#********************************************************************************

test_5_2_e() {
    id=$1
    description="Checking Hourly Cron for Clamav"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
if [[ -f /etc/cron.hourly/*clamav* ]]; 
then result="Pass" 
else result="Fail"
fi
    #write_info "`cat /etc/cron.hourly/*clamav* | grep -v "#"`"
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    execution_time=`printf "%.2f seconds" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$execution_time"
}

#********************************************************************************

test_5_2_f() {
    id=$1
    description="Checking Clamav log file exist"
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
    execution_time=`printf "%.2f seconds" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$execution_time"
}

#********************************************************************************

test_5_2_g() {
    id=$1
    description="Checking Clamscan log file exist"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
if [[ -f /var/log/clamav/*.log ]]; then 
result="Fail"
else result="Pass"
fi
    #write_info "`cat $log1`"
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    execution_time=`printf "%.2f seconds" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$execution_time"
}

#********************************************************************************

test_5_3_a() {
    id=$1
    description="Checking FreshClam service is running"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
fresh=`ps -ef | grep -v grep | grep clamav-freshclam | wc -l 2>&1`
if [[ $fresh -gt 0 ]]; then 
result="Pass"
else result="Fail"
fi
    #write_info "`ps -ef | grep -v grep | grep clamav-freshclam 2>&1`"
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    execution_time=`printf "%.2f seconds" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$execution_time"
}

#********************************************************************************

test_5_3_b() {
    id=$1
    description="Checking config in freshclam for virus-update"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
if [[ -f /etc/clamav/freshclam.conf ]]; then
(
result="Pass"
chk=`grep checks /etc/clamav/freshclam.conf | awk '{ print $2 }' 2>&1`
#write_info "Freshclam config exist. checks update below times a day" "$chk"
)
else
(
result="Fail"
)
fi
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    execution_time=`printf "%.2f seconds" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$execution_time"
}

#********************************************************************************

test_5_3_c() {
    id=$1
    description="Checking clamd scan service is running"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
if [[ `ps -ef | grep -v grep | grep clamd | wc -l 2>&1` -gt 0 ]]; then
(
result="Pass"
clamd=`grep checks /etc/clamav/clamd.conf 2>&1`
#write_info "Clamd.conf" "$clamd"
)
else
(
result="Fail"
)
fi
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    execution_time=`printf "%.2f seconds" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$execution_time"
}

test_5_3_d() {
    id=$1
    description="Checking read permission on clamd.conf file"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
if [[ -r /etc/clamav/clamd.conf ]]; then
(
result="Pass"
#write_info "clam.conf log file permission" "`ls -alth /etc/clamav/clamd.conf`"
)
else
(
result="Fail"
)
fi
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    execution_time=`printf "%.2f seconds" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$execution_time"
}

test_5_3_e() {
    id=$1
    description="Checking write permission on clamd.conf file"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
if [[ -w /etc/clamav/clamd.conf ]]; then
(
result="Pass"
#write_info "clam.conf log file permission" "`ls -alth /etc/clamav/clamd.conf`"
)
else
(
result="Fail"
)
fi
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    execution_time=`printf "%.2f seconds" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$execution_time"
}

test_5_3_f() {
    id=$1
    description="Checking read permission on freshclam.conf file"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
if [[ -r /etc/clamav/freshclam.conf ]]; then
(
result="Pass"
#write_info "freshclam.conf log file permission" "`ls -alth /etc/clamav/freshclam.conf`"
)
else
(
result="Fail"
)
fi
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    execution_time=`printf "%.2f seconds" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$execution_time"
}

test_5_3_g() {
    id=$1
    description="Checking write permission on freshclam.conf file"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
if [[ -w /etc/clamav/freshclam.conf ]]; then
(
result="Pass"
#write_info "freshclam.conf log file permission" "`ls -alth /etc/clamav/freshclam.conf`"
)
else
(
result="Fail"
)
fi
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    execution_time=`printf "%.2f seconds" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$execution_time"
}

#****************************************************************************

test_6_1() {
    id=$1
    description="Checking when kernel updated last time"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
last1=`rpm -q kernel --last 2>&1`
last2=`ls -l /boot/ 2>&1`
if [[ ! -z $last1 ]] || [[ ! -z $last2 ]]; then
result="Pass"
#write_info "last update of kernel" "$last1 \n $last2"
else
result="Fail"
fi
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    execution_time=`printf "%.2f seconds" $duration`
    write_cache "6,Requirement 6"
    write_result "$id,$description,$scored,$result,$execution_time"
}


test_6_1_a() {
    id=$1
    description="Checking all package update date"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
last3=$(rpm -q --last 2>&1)
last4=$(grep upgrade /var/log/dpkg.log 2>&1)
if [[ ! -z $last3 ]] || [[ ! -z $last4 ]]; then
(
result="Pass"
#write_info "last update of all packages" "$last3 \n $last4"
)
else
(
result="Fail"
)
fi
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    execution_time=`printf "%.2f seconds" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$execution_time"
}

test_6_1_b() {
    id=$1
    description="Checking package to update"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
pack1=$(yum list updates 2>&1)
pack2=$(apt list --upgradable 2>&1)
if [[ ! -z $pack1 ]] || [[ ! -z $pack2 ]]; then
(
result="Pass"
#write_info "Packages to be updated are" "$pack1 \n $pack2"
)
else
(
result="Fail"
)
fi
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    execution_time=`printf "%.2f seconds" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$execution_time"
}

test_6_1_c() {
    id=$1
    description="Checking log of installed/updated packages"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
#pack3=/var/log/yum.log
#pack4=/var/log/apt/history.log
if [[ -f /var/log/yum.log ]] || [[ -f /var/log/apt/history.log ]]; then
(
result="Pass"
#write_info "Check logs in file" "`cat $pack3` \n `cat $pack4`"
)
else
(
result="Fail"
)
fi
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    execution_time=`printf "%.2f seconds" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$execution_time"
}

test_6_2() {
    id=$1
    description="Checking when Repo last updated"
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
#write_info "Check repo list" "$rep1 \n $rep2"
)
fi
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    execution_time=`printf "%.2f seconds" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$execution_time"
}

test_6_2_a() {
    id=$1
    description="Checking security updates"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
sec1=`sudo yum check-update --security`
sec2=`sudo grep security /etc/apt/sources.list 2>&1`
if [[ ! -z $sec1 ]] || [[ ! -z $sec2 ]]; then
(
result="Pass"
#write_info "Check security package update" "$sec1 \n $sec2"
)
else
(
result="Fail"
)
fi
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    execution_time=`printf "%.2f seconds" $duration`
    #write_cache "1.2,User Access"
    write_result "$id,$description,$scored,$result,$execution_time"
}

#****************************************************************************

test_7_1() {
    id=$1
    description="Checking user is part of sudoer"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
sudoer1=$(grep $(whoami) /etc/sudoers 2>&1)
if [[ $? -eq 0 ]]; then
(
result="Pass"
#write_info "SUDOERS" "`cat /etc/sudoers | grep -v "#"`"
)
else
(
result="Fail"
)
fi
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    execution_time=`printf "%.2f seconds" $duration`
    #write_cache "7,Requirement 7"
    write_result "$id,$description,$scored,$result,$execution_time"
}

test_7_2() {
    id=$1
    description="SELinux is Installed"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
se1=rpm -qa 2>&1 | egrep -w 'selinux-basic|selinux-policy-defualt' 
se2=dpkg -l 2>&1 | grep selinux*
if [[ ! -z $se1 ]] || [[ ! -z $se2 ]]; then
(
result="Pass"
#write_info "$se1 \n $se2"
)
else
(
result="Fail"
)
fi
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    execution_time=`printf "%.2f seconds" $duration`
    #write_cache "7,Requirement 7"
    write_result "$id,$description,$scored,$result,$execution_time"
}

test_7_2_a() {
    id=$1
    description="SELinux is enforced"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
state=`grep SELINUX=enforcing /etc/sysconfig/selinux 2>&1`
if [[ ! $state ]]; then
(
result="Fail"
#write_info "SELinux Status" "`grep SELINUX /etc/sysconfig/selinx 2>&1 | awk '{print $2}'`"
)
else
(
result="Pass"
)
fi
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    execution_time=`printf "%.2f seconds" $duration`
    #write_cache "7,Requirement 7"
    write_result "$id,$description,$scored,$result,$execution_time"
}

test_7_2_b() {
    id=$1
    description="SELinux is targeted"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
type=`grep SELINUXTYPE=targeted /etc/sysconfig/selinux 2>&1`
if [[ ! $type ]]; then
(
result="Fail"
#write_info "SELinuxTYPE Status" "`grep SELINUXTYPE /etc/sysconfig/selinx 2>&1 | awk '{print $2}'`"
)
else
(
result="Pass"
)
fi
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    execution_time=`printf "%.2f seconds" $duration`
    #write_cache "7,Requirement 7"
    write_result "$id,$description,$scored,$result,$execution_time"
}

test_7_2_c() {
    id=$1
    description="SELinux troubleshoot package is not installed"
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
#write_info "$tr1 \n $tr2"
)
fi
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    execution_time=`printf "%.2f seconds" $duration`
    #write_cache "7,Requirement 7"
    write_result "$id,$description,$scored,$result,$execution_time"
}

test_7_2_d() {
    id=$1
    description="Checking unconfined daemons"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
con=`ps -eZ | egrep "initrc" | egrep -vw "tr|ps|egrep|bash|awk" | tr ':' ' ' | awk '{print $NF}'`
if [[ $? -eq 0 ]]; then
(
result="Pass"
#write_info "$con"
)
else
(
result="Fail"
)
fi
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    execution_time=`printf "%.2f seconds" $duration`
    #write_cache "7,Requirement 7"
    write_result "$id,$description,$scored,$result,$execution_time"
}

test_7_2_e() {
    id=$1
    description="Checking SELinux Config file exist"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
if [[ -f /etc/selinux/config ]] || [[ -f /etc/sysconfig/selinux ]]; then
(
result="Pass"
#write_info "Selinux Config file" "`cat /etc/selinux/config` \n `cat /etc/sysconfig/selinux`"
)
else
(
result="Fail"
)
fi
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    execution_time=`printf "%.2f seconds" $duration`
    #write_cache "7,Requirement 7"
    write_result "$id,$description,$scored,$result,$execution_time"
}

test_7_2_f() {
    id=$1
    description="Ensure MCS-Translation(mcstrans) is not installed"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)
    
    ## Tests Start ##
    state=0
    
    [ "$(rpm -q mcstrans)" == "package mcstrans is not installed" ] || state=1
    [ $state -eq 0 ] && result="Pass"
    ## Tests End ##
    
    duration=$(echo "$(date +%s.%N) - $start" | bc)
    execution_time=`printf "%.2f seconds" $duration`
    write_result "$id,$description,$scored,$result,$execution_time"
}

#*********************************************************************************

test_8_1() {
    id=$1
    description="Ensure root is the only UID 0 account"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
[ $(awk -F: '$3 == 0' /etc/passwd | wc -l) -eq 1 ] || state=1
    
[ $state -eq 0 ] && result="Pass"
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    execution_time=`printf "%.2f seconds" $duration`
    write_cache "8,Requirement 8"
    write_result "$id,$description,$scored,$result,$execution_time"
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
    execution_time=`printf "%.2f seconds" $duration`
    #write_cache "8,Requirement 8"
    write_result "$id,$description,$scored,$result,$execution_time"
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
    execution_time=`printf "%.2f seconds" $duration`
    #write_cache "7,Requirement 7"
    write_result "$id,$description,$scored,$result,$execution_time"
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
    execution_time=`printf "%.2f seconds" $duration`
    #write_cache "7,Requirement 7"
    write_result "$id,$description,$scored,$result,$execution_time"
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
    execution_time=`printf "%.2f seconds" $duration`
    #write_cache "7,Requirement 7"
    write_result "$id,$description,$scored,$result,$execution_time"
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
    execution_time=`printf "%.2f seconds" $duration`
    #write_cache "7,Requirement 7"
    write_result "$id,$description,$scored,$result,$execution_time"
}

test_8_1_1_e() {
    id=$1
    description="Ensure access to the su command is restricted"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
    [ $(egrep -c "^auth\s+required\s+pam_wheel.so\s+use_uid" /etc/pam.d/su) -eq 1 ] || state=1
    
    [ $state -eq 0 ] && result="Pass"
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    execution_time=`printf "%.2f seconds" $duration`
    #write_cache "7,Requirement 7"
    write_result "$id,$description,$scored,$result,$execution_time"
}

test_8_1_1_f() {
    id=$1
    description="Ensure access to the su command is restricted"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
    [ $(egrep -c "^auth\s+required\s+pam_wheel.so\s+use_uid" /etc/pam.d/su) -eq 1 ] || state=1
    
    [ $state -eq 0 ] && result="Pass"
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    execution_time=`printf "%.2f seconds" $duration`
    #write_cache "7,Requirement 7"
    write_result "$id,$description,$scored,$result,$execution_time"
}

test_8_1_1_g() {
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
    execution_time=`printf "%.2f seconds" $duration`
    #write_cache "7,Requirement 7"
    write_result "$id,$description,$scored,$result,$execution_time"
}

test_8_1_1_h() {
    id=$1
    description="Ensure all users' home directories exist"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
    [ $(egrep -c "^auth\s+required\s+pam_wheel.so\s+use_uid" /etc/pam.d/su) -eq 1 ] || state=1
    
    [ $state -eq 0 ] && result="Pass"
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    execution_time=`printf "%.2f seconds" $duration`
    #write_cache "7,Requirement 7"
    write_result "$id,$description,$scored,$result,$execution_time"
}

test_8_1_1_i() {
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
    execution_time=`printf "%.2f seconds" $duration`
    #write_cache "7,Requirement 7"
    write_result "$id,$description,$scored,$result,$execution_time"
}

test_8_1_1_j() {
    id=$1
    description="Ensure all groups in /etc/passwd exist in /etc/group"
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
    execution_time=`printf "%.2f seconds" $duration`
    #write_cache "7,Requirement 7"
    write_result "$id,$description,$scored,$result,$execution_time"
}

test_8_1_4() {
    id=$1
    description="Ensure inactive user over 90 days are disable/lock"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
inactive=`lastlog -b 90 2>&1 | tail -n+2 | grep -v '**Never log**' | awk '{print $1}' 2>&1`
if [[ $inactive -eq 0 ]] && [[ ! $inactive ]] ; then
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

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    execution_time=`printf "%.2f seconds" $duration`
    #write_cache "7,Requirement 7"
    write_result "$id,$description,$scored,$result,$execution_time"
}

test_8_1_6() {
    id=$1
    description="Ensure password is locked after 6 fail attempt"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
inactive=`lastlog -b 90 2>&1 | tail -n+2 | grep -v '**Never log**' | awk '{print $1}' 2>&1`
if [[ $inactive -eq 0 ]] && [[ ! $inactive ]] ; then
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

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    execution_time=`printf "%.2f seconds" $duration`
    #write_cache "7,Requirement 7"
    write_result "$id,$description,$scored,$result,$execution_time"
}


test_8_2() {
    id=$1
    description="Ensure password hashing algorithm is SHA-512"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)

    ## Tests Start ##
    [ $(egrep -c "^password\s+sufficient\s+pam_unix.so.*sha512" /etc/pam.d/system-auth) -eq 1 ] || state=1
    [ $(egrep -c "^password\s+sufficient\s+pam_unix.so.*sha512" /etc/pam.d/password-auth) -eq 1 ] || state=1
    
    [ $state -eq 0 ] && result="Pass"
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    execution_time=`printf "%.2f seconds" $duration`
    #write_cache "7,Requirement 7"
    write_result "$id,$description,$scored,$result,$execution_time"
}

#********************************************************************************

test_10_1() {
    id=$1
    description="Ensure chrony is configured"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)
    
    ## Tests Start ##
    state=0
if [ $( rpm -q chrony &>/dev/null; echo $? ) -eq 0 ]; then
        egrep "^(server|pool) .*$" /etc/chrony.conf &>/dev/null || state=$(( $state + 1 ))
        
        if [ -f /etc/sysconfig/chronyd ]; then
            [ $( grep -c 'OPTIONS="-u chrony' /etc/sysconfig/chronyd ) -eq 0 ] && state=$(( $state + 2 ))
        else
            state=$(( $state + 4 ))
        fi
        
        [ $state -eq 0 ] && result="Pass"
    duration=$(echo "$(date +%s.%N) - $start" | bc)
    execution_time=`printf "%.2f seconds" $duration`
    else
        scored="Skipped"
        result=""
    fi
    ## Tests End ##

    write_cache "10,Requirement 10"
    write_result "$id,$description,$scored,$result,$execution_time"
}

test_10_1_a() {
    id=$1
    description="Ensure time synchronisation is in use"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)
    
    ## Tests Start ##
[ $(rpm -q ntp &>/dev/null; echo $?) -eq 0 -o $(rpm -q chrony &>/dev/null; echo $?) -eq 0 ] && result="Pass"
    ## Tests End ##

    duration=$(echo "$(date +%s.%N) - $start" | bc)
    execution_time=`printf "%.2f seconds" $duration`
    #write_cache "10,Requirement 10"
    write_result "$id,$description,$scored,$result,$execution_time"
}

test_10_1_b() {
    id=$1
    description="Ensure ntp is configured"
    scored="Scored"
    ### new script
    start=$(date +%s.%N)
    
    ## Tests Start ##
if [ $( rpm -q ntp &>/dev/null; echo $?) -eq 0 ]; then
        grep "^restrict -4 default kod nomodify notrap nopeer noquery" /etc/ntp.conf &>/dev/null || state=1
        grep "^restrict -6 default kod nomodify notrap nopeer noquery" /etc/ntp.conf &>/dev/null || state=2
        [ $(egrep -c "^(server|pool) .*$" /etc/ntp.conf 2>/dev/null) -ge 2 ] || state=4
        [ -f /etc/systemd/system/ntpd.service ] && file="/etc/systemd/system/ntpd.service" || file="/usr/lib/systemd/system/ntpd.service"
        [ $(grep -c 'OPTIONS="-u ntp:ntp' /etc/sysconfig/ntpd) -ne 0 -o $(grep -c 'ExecStart=/usr/sbin/ntpd -u ntp:ntp $OPTIONS' $file) -ne 0 ] || state=8
        
        [ $state -eq 0 ] && result="Pass"
    duration=$(echo "$(date +%s.%N) - $start" | bc)
    execution_time=`printf "%.2f seconds" $duration`
    else
        scored="Skipped"
        result=""
    fi
    ## Tests End ##
    
    #write_cache "10,Requirement 10"
    write_result "$id,$description,$scored,$result,$execution_time"
}


#********************************************************************************
    write_info system_info

    test_1_1
    test_1_1_1
    test_1_1_4
    test_1_1_6
    test_1_1_6_b
    test_1_1_6_b_2
    test_1_1_6_b_3
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
    test_8_1_1_g
    test_8_1_1_h
    test_8_1_1_i
    test_8_1_1_j
    test_8_1_4
    test_8_2

    test_10_1
    test_10_1_a
    test_10_1_b

    outputter 

