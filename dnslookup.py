import dns.resolver
import dns.reversename
import sys
import tldextract


def ip_to_host(ip):
    hostname = dns.reversename.from_address(ip)
    try:
        answers = dns.resolver.query(hostname, 'PTR')
        answers = answers.rrset[0].to_text()[:-1]
        domain = tldextract.extract(answers).registered_domain
    except:
        domain = ''

    return domain


def dns_records(domain):
    dns_data = {}
    dns_records = ['A', 'NS', 'CNAME', 'SOA', 'MX', 'TXT']

    for record in dns_records:
        try:
            answers = dns.resolver.query(domain, record)
            for rdata in answers:
                if record in dns_data.keys():
                    dns_data[record] = dns_data[record].replace(
                        '"', '') + ',' + rdata.to_text().replace('"', '')
                else:
                    dns_data[record] = rdata.to_text()

            if ',' in dns_data[record]:
                dns_data[record] = dns_data[record].split(',')

        except:
            dns_data[record] = 'Not Found'

    # Remove dot(.) at the end of string from NS Record
    try:
        if isinstance(dns_data['NS'], list):
            temp_list = []
            for ns in dns_data['NS']:
                temp_list.append(ns[:-1])

            dns_data['NS'] = temp_list
        else:
            if dns_data['NS'] != 'Not Found':
                dns_data['NS'] = [dns_data['NS'][:-1]]
            else:
                dns_data['NS'] = 'Not Found'

    except:
        pass

    # MX Record
    try:
        if isinstance(dns_data['MX'], list):
            temp_list = []
            for mx in dns_data['MX']:
                temp_list.append(mx[:-1])

            dns_data['MX'] = temp_list
        else:
            if dns_data['MX'] != 'Not Found':
                dns_data['MX'] = [dns_data['MX'][:-1]]
            else:
                dns_data['MX'] = 'Not Found'
    except:
        pass

    # Filter out SPF record from TXT Record
    try:
        if isinstance(dns_data['TXT'], list):
            for txt_record in dns_data['TXT']:
                if 'v=spf' in txt_record:
                    dns_data['SPF'] = txt_record
                    break
                else:
                    dns_data['SPF'] = 'Not Found'
            dns_data.pop('TXT')

        elif 'v=spf' in dns_data['TXT']:
            dns_data['SPF'] = dns_data['TXT'].replace('"', '')
            dns_data.pop('TXT')

    except:
        pass

    # Remove SOA Record
    try:
        dns_data.pop('SOA')
    except:
        pass

    return dns_data


if __name__ == '__main__':
    query = sys.argv[1]
    input_type = sys.argv[2]

    if input_type == 'domain':
        print(dns_records(query))
    elif input_type == 'ipv4':
        query = ip_to_host(query)
        data = dns_records(query)
        if query != '':
            data['Domain'] = query
        print(data)
    else:
        print("{'Error': 'Invalid Input'}")
