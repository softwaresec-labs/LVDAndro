import requests
from bs4 import BeautifulSoup


def get_api_key(server):
    url_to_call = server+"/api_docs"

    response = requests.get(url_to_call, headers={'User-Agent': 'Mozilla/5.0'})
    response_code = response.status_code

    if response_code != 200:
        print("Some Error")
        return

    else:
        html_content = response.content
        dom = BeautifulSoup(html_content, 'html.parser')
        api_key = str(dom.select("p.lead")[0]).split("REST API Key: <strong><code>")[1].split("</code>")[0]
        return api_key
