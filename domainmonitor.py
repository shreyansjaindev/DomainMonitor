from dnslookup import dns_records
from whois_web_scraping import whois
from httpstatus import httpstatus
import threading
import csv
import os
from datetime import datetime, timedelta

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def changeValidator(data):
    date = datetime.now()
    timestamp = date.strftime("%d-%m-%Y %H:%M:%S")
    today = date.strftime("%d-%m-%Y")
    yesterday = date - timedelta(days=1)
    yesterday = yesterday.strftime("%d-%m-%Y")
    temp_today = []
    temp_yesterday = []
    path = os.path.join(BASE_DIR, 'DomainMonitor/')

    if os.path.exists(path + f'Reports/Domain_Monitor_Report_{today}.csv') and os.path.exists(path + f'Reports/Domain_Monitor_Report_{yesterday}.csv'):
        with open(path + f'Reports/Domain_Monitor_Report_{today}.csv', 'r') as file:
            reader = csv.reader(file)
            header = next(reader)
            if header != None:
                for row in reader:
                    temp_today.append(row)

        with open(path + f'Reports/Domain_Monitor_Report_{yesterday}.csv', 'r') as file:
            reader = csv.reader(file)
            header = next(reader)
            if header != None:
                for row in reader:
                    temp_yesterday.append(row)

        for idx in range(len(temp_today)):
            try:
                if temp_today[idx][2] != temp_yesterday[idx][2] or temp_today[idx][3] != temp_yesterday[idx][3] or temp_today[idx][4] != temp_yesterday[idx][4]:
                    with open(path + f'Changes/Domain_Monitor_Report_Changes_{today}.csv', 'a', newline='') as file:
                        writer = csv.writer(file)
                        writer.writerow(temp_today[idx])
            except:
                with open(path + f'Changes/Domain_Monitor_Report_Changes_{today}.csv', 'a', newline='') as file:
                    writer = csv.writer(file)
                    writer.writerow(temp_today[idx])

    return data


def readCSV():
    data = []
    path = os.path.join(BASE_DIR, 'DomainMonitor/domains.csv')
    with open(path, 'r') as file:
        reader = csv.reader(file)
        header = next(reader)

        if header != None:
            for row in reader:
                data.append(row[0])

    return data


def writeCSV(data):
    timestamp = datetime.now().strftime("%d-%m-%Y %H:%M:%S")
    date = datetime.now().strftime("%d-%m-%Y")
    path = os.path.join(
        BASE_DIR, f'DomainMonitor/Reports/Domain_Monitor_Report_{date}.csv')
    # Check if File Exists
    if os.path.exists(path):
        print('File Already Exists')
    else:
        print('Output File Creation Successful')
        with open(path, 'a', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(["Timestamp", "Domain", "WHOIS", "MX", "A"])

    print('File Update Successful')
    with open(path, 'a', newline='') as file:
        writer = csv.writer(file)
        for domain, domain_data in data.items():
            writer.writerow([timestamp, domain, domain_data.get('WHOIS', 'Not Found'), domain_data['DNS'].get(
                'MX', 'Not Found'), domain_data['DNS'].get('A', 'Not Found')])


def getDNSRecords(domain):
    data = {}

    temp = dns_records(domain).get('MX', None)
    if temp != None:
        data['MX'] = temp
    else:
        data['MX'] = 'Not Found'

    temp = dns_records(domain).get('A', None)
    if temp != None:
        data['A'] = temp
    else:
        data['A'] = 'Not Found'

    return data


def getWHOIS(domain):
    data = {}
    temp = whois(domain).split('\n')
    for line in temp:
        # Get Registrar Name
        if 'Registrar: ' in line:
            data['Registrar'] = line.split('Registrar: ')[1]
        # Get Registrant Name
        if 'Registrant Name: ' in line:
            data['Registrant Name'] = line.split('Registrant Name: ')[1]
        # Get Registrant Organization
        if 'Registrant Organization: ' in line:
            data['Registrant Organization'] = line.split(
                'Registrant Organization: ')[1]
        # Get Registrant Country
        if 'Registrant Country: ' in line:
            data['Registrant Country'] = line.split('Registrant Country: ')[1]

    if data == {}:
        data = 'Not Found'

    return data


def getHTTPStatus(domain):
    return httpstatus(domain)


def collector(domains, data):
    for domain in domains:
        data[domain] = {'WHOIS': getWHOIS(domain)}
        data[domain]['DNS'] = getDNSRecords(domain)
        data[domain]['HTTP Status'] = getHTTPStatus(domain)


if __name__ == '__main__':
    path = os.path.join(BASE_DIR, 'DomainMonitor/domains.csv')
    if os.path.exists(path):
        domains = readCSV()
        print('File "domains.csv" Loaded Sucessfully')
    else:
        print('File "domains.csv" Not Found')

    threads = len(domains)
    
    jobs = []
    data = {}
    for i in range(0, threads):
        thread = threading.Thread(target=collector(domains, data))
        jobs.append(thread)

    # Start the threads (i.e. calculate the random number lists)
    for j in jobs:
        j.start()

    # Ensure all of the threads have finished
    for j in jobs:
        j.join()

    print(data)

    """ # Collect Data
    data = collector(domains)
    # Write Data to File
    writeCSV(data)
    changeValidator(data) """
