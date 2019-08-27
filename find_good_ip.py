#!/usr/bin/env python
import sys
import re

def truthy(ip):
    bad_flag = 0
    split_ip = ip.split('.')

    for octet in split_ip:
        #print(octet)
        if int(octet) > 255:
            bad_flag += 1
        if bad_flag > 0:
            return False

    return True

def remove_zero_invalid(ip):
    split_ip = ip.split('.')
    for octet in split_ip:
        if len(octet) == 3:
            if octet[0] == '0' or octet[0] == '0' and octet[1] == '0' and octet[2] == '0' or octet[0] == '0' and octet[1] == '0' and octet[2] == '0' or octet[0] == '0' and int(octet[1]) > 0 or octet[0] == '0' and octet[1] == '0' and int(octet[2]) > 0:
                return False  

        elif len(octet) == 2:
            if octet[0] == '0' or octet[0] == '0' and octet[1] == '0':
                return False

        elif len(octet) == 1:
            if octet[0] == '0':
                return False

        else:
            return False


    return True

def main():
    
    myfile = open(sys.argv[1], 'r')
    contents = myfile.read().split('\n')
    ip_match = []
    ipPattern = re.compile('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
    
    for line in contents:
        ip_match += re.findall(ipPattern, line)
    #print(ip_match)
    

    ip_dict = {}
    for ip in ip_match:
        where_is_ip_in_list = 0

        if ip == "...":
            continue
        if remove_zero_invalid(ip):
            ip_match.pop(where_is_ip_in_list)

        
        if not ip in ip_dict:
            ip_dict[ip] = 1
        else:
            ip_dict[ip] += 1
        where_is_ip_in_list += 1

    #print(ip_dict)

    sorted_dict = sorted(ip_dict.items(), key=lambda kv: (kv[1], kv[0])) 

    #print(sorted_dict)
    count = 0
    for tuples in sorted_dict:
        count += 1
        if count == len(sorted_dict):
            print("(%03d) %5s: %14s **" % (tuples[1], truthy(tuples[0]), tuples[0]))
        else:
            print("(%03d) %5s: %14s *" % (tuples[1], truthy(tuples[0]), tuples[0]))

main()



