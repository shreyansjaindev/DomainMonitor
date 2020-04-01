import requests
import sys
import os
from bs4 import BeautifulSoup


def whois(domain):

    url = 'https://www.whois.com/whois/' + domain
    response = requests.get(url)
    soup = BeautifulSoup(response.content, 'html.parser')

    try:
        whois_data = soup.find('pre', attrs = {'id':'registrarData'}).text.strip()
    except:
        whois_data = ''

    return whois_data


if __name__ == "__main__":

    print(whois(sys.argv[1]))
