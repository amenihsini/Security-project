from flask import Flask, render_template, request
import requests

app = Flask(__name__)

nvd_api_url = 'https://services.nvd.nist.gov/rest/json/cves/1.0'


def get_website_info(url):
    response = requests.get(url)
    server_type = response.headers.get('Server')
    if server_type is None:
        server_type = 'No server information found'

    vulnerabilities = search_vulnerabilities(server_type)

    website_info = {
        'url': url,
        'server_type': server_type,
        'vulnerabilities': vulnerabilities
    }
    return website_info


def search_vulnerabilities(server_type):
    query = {
        'keyword': server_type,
        'resultsPerPage': 10
    }
    response = requests.get(nvd_api_url, params=query)
    data = response.json()
    vulnerabilities = []
    if 'result' in data and 'CVE_Items' in data['result']:
        for item in data['result']['CVE_Items']:
            cve_id = item['cve']['CVE_data_meta']['ID']
            vulnerabilities.append(cve_id)
    return vulnerabilities


def report_vulnerabilities(website_info):
    return render_template('vulns.html', **website_info)


def scan_website(url):
    website_info = get_website_info(url)
    return report_vulnerabilities(website_info)


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        url = request.form.get('url')
        if url:
            return scan_website(url)
        else:
            return 'URL not found in form data!'
    else:
        return render_template('index.html')


if __name__ == '__main__':
    app.run(debug=True)
