#!/usr/bin/python3

import re
import json
import time
import urllib.parse
import os.path
import requests
import argparse
from bs4 import BeautifulSoup

class Formatting:
    """ Give formatting to text: bold, underline, ... and fg and bg colors

    Reset all formatting with Formatting.reset
    Give fg color with: Formatting.fgcolor.<colorname>
    Give bg color with: Formatting.bgcolor.<colorname>

    Usage:
        print(formatting.bgcolor.green, "SKk", formatting.fgcolor.red, "Amartya")"""

    reset = '\033[0m'
    bold = '\033[01m'
    disable = '\033[02m'
    underline = '\033[04m'
    reverse = '\033[07m'
    strike_through = '\033[09m'
    invisible = '\033[08m'

    class fgcolor:
        black = '\033[30m'
        blue = '\033[34m'
        green = '\033[32m'
        light_green = '\033[92m'
        light_grey = '\033[37m'
        dark_grey = '\033[90m'
        red = '\033[31m'
        orange = '\033[33m'
        purple = '\033[35m'
        cyan = '\033[36m'
        light_red = '\033[91m'
        yellow = '\033[93m'
        light_blue = '\033[94m'
        pink = '\033[95m'
        light_cyan = '\033[96m'

    class bgcolor:
        black = '\033[40m'
        red = '\033[41m'
        green = '\033[42m'
        orange = '\033[43m'
        blue = '\033[44m'
        purple = '\033[45m'
        cyan = '\033[46m'
        lightgrey = '\033[47m'

class Vulnfetcher:
    """A class to lookup (currently only a dpkg generated file 'dpkg -l > file') modules
    for known vulnerabilities"""

    def __init__(self, filename, parse=True, output=True, print_report=True, short_report=False, print_exploits=False, search_engine='', use_proxy_burp=False):
        """When initializing the class, a path to a file is provided
        I do a line count on the file (This was to implement a progressbar, which isn't done yet)
        I then start processing the file"""
        self.db = {}
        self.db_sorted = {}
        self.db_search = {}
        self.db_module = {}
        self.db_exploits = {}
        self.db_result = {}
        self.db_results = {}
        self.db_result_detail = {}
        self.db_score = {}
        self.file_line_count = 0
        self.searchengine_links = []

        # Websites that count as an interesting find:
        self.trusted_sources = ["https://vulmon.com/", "https://www.exploit-db.com", "https://www.cvedetails.com",
                                "https://www.rapid7.com", "https://nvd.nist.gov/vuln/"]
        self.cve_details_url = "https://www.cvedetails.com/cve/"
        self.exploit_db_exploit_url = "https://www.exploit-db.com/exploits/"
        self.exploit_db_exploit_title_class = "card-title"
        # get the n first search results
        self.get_top_n = 8

        self.version_complete_match_score_weight = 2
        self.cvedetails_summary = "cvedetailssummary"
        self.cvedetails_scores_and_types_id = "cvssscorestable"
        self.cvedetails_gained_access_th = "Gained Access"
        self.cvedetails_gained_access_admin_string = "Admin"
        self.cvedetails_references_id = "vulnrefstable"
        # TODO There is also "th Vulnerability Type(s)	--> Gain privileges", example: https://www.cvedetails.com/cve/CVE-2011-3628/
        self.cvedetails_gained_access_score_weight = 3
        self.exploit_available_score_weight = 2

        self.search_engine = search_engine
        self.short_report = short_report
        self.use_proxy_burp = use_proxy_burp

        #reporting
        self.print_exploits = print_exploits
        self.print_exploits_character_limit = 57

        self.header_user_agent = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Referer': 'https://duckduckgo.com/',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Upgrade-Insecure-Requests': '1'}
        # self.header_user_agent = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.61 Safari/537.36'}
        if self.search_engine == 'google':
            self.search_engine_delay = 5
        else:
            self.search_engine_delay = 0
        self.file_name = filename
        #self.count_lines_in_file()
        if parse:
            print(Formatting.bold)
            print("Starting vulnfetcher" + Formatting.reset + " (https://github.com/gnothiseautonlw/vulnfetcher)")
            print("Detecting filetype: ", end='')
            self.file_identifier = self.identify_file(filename)
            if self.file_identifier == 'single_search':
                print("file not found. Treating it as a single-search for the term: " + filename)
                #We don't want any outputfiles to be generated
                output = False
                #Reduce the processed search results
                self.get_top_n = 5
                self.process_single_search(filename)
            else:
                self.output_file = filename + ".vulnfetcher"
                if self.file_identifier == "nmap":
                    print("found an xml file. Treating it as nmap xml.")
                    print()
                    self.process_nmap(filename)
                elif self.file_identifier == 'tab':
                    print("found text file. Treating it as tab-separated file.")
                    print()
                    self.process_tab(filename)
                else:
                    print("found text file. Treating it as a dpkg-dump.")
                    print()
                    self.process_dpkg(filename)
        if output:
            print(Formatting.bold)
            print("Writing files... " + Formatting.reset)
            f = self.store_output()
            print('Raw json-data dumped to: ' + f)
            f = self.store_report()
            print('Report written to: ' + f)
        if print_report:
            self.print_report()

    def count_lines_in_file(self):
        """Count the number of lines in the file"""
        with open(self.file_name) as f:
            for i, l in enumerate(f):
                pass
        self.file_line_count = i + 1
    
    def parse_dpkg(self, line):
        """Parse a dpkg file. For each line, get the module name and version"""
        module_version_mayor_minor = '???'
        module_version_complete = '???'

        line = line.rstrip("\n").strip()  # remove newline at the end of the read line

        try:
            # regex for module name
            module_name = re.search('(?<=ii  )(\S*)', line, flags=re.DOTALL).group(0).strip()
            # regex for Mayor - dot - minor.
            # Find a whitespaces, then select either
            #     numbers followed by dot, followed by one number
            #     numbers followed by ':', followed by numbers, followed by '.', followed by one number
            #     number followed by numbers
            # There are basically three versions-formats I've seen so far:
            #     'normal version numbers': 1.15.2 (here I would select only 1.1)
            #     and version numbers in the format: 1:1.15.2 (here I would select 1:1.1)
            #     all numbers: 20091524
            module_version_mayor_minor = re.search('(?<=\s)(\d*\.\d|\d*:\d*\.\d|\d\d*)', line, flags=re.DOTALL).group(
                0).strip()
            # taking the above 3 formats in mind, here I try to take the complete version number
            module_version_complete = re.search('(?<=\s)\d+([\.:]\d+)*', line, flags=re.DOTALL).group(0).strip()
        except:
            self.db_score = {}
            self.db_module = {}
            self.db_search = {}
            self.db_result = {}
            self.db_result_detail = {}
            self.db_score['total'] = 0
            self.db_score['total_string'] = "00"
            self.db_module['raw_name'] = line
            self.db_module['name'] = line
            self.db_module['version_mayor_minor'] = module_version_mayor_minor
            self.db_module['version_complete'] = module_version_complete
            self.db_search['status_code'] = '???'
            self.db_search['url'] = ''
            return 0
        else:
            self.db_module['raw_name'] = line
            self.db_module['name'] = module_name
            self.db_module['version_mayor_minor'] = module_version_mayor_minor
            self.db_module['version_complete'] = module_version_complete
            return 1

    def get_duckduck_links(self):
        """Search duckduckgo and return a result array, containing a dictionary with title,
        url and description """
        search_term = '"' + self.db_module['name'] + '" "' + self.db_module['version_mayor_minor'] + '" exploit'
        self.db_search['term'] = urllib.parse.quote_plus(search_term)
        self.db_search['url'] = "https://duckduckgo.com/html/?q=" + self.db_search['term']

        try:
            data = {
                'q': '"' + self.db_module['name'] + '" "' + self.db_module['version_mayor_minor'] + '" exploit',
                'b': '',
                'kl': '',
                'df': ''
            }
            if self.use_proxy_burp:
                proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
                page = requests.post("https://duckduckgo.com/html/", headers=self.header_user_agent, data=data, proxies=proxies, verify=False)
            else:
                page = requests.post("https://duckduckgo.com/html/", headers=self.header_user_agent, data=data)

            #page = requests.get(self.db_search['url'], headers=self.header_user_agent, proxies=proxies, verify=False)
            #page = requests.get(self.db_search['url'], headers=self.header_user_agent)

            time.sleep(self.search_engine_delay)
        except requests.exceptions.ProxyError as err:
            print("Proxy Error. Is it running? Please check configuration.")
            self.db_search['status_code'] = '???'
            return []
        except Exception as e:
            self.db_search['status_code'] = '???'
            return []
        else:
            self.db_search['status_code'] = page.status_code
            if self.db_search['status_code'] == 200:
                soup = BeautifulSoup(page.content, 'html.parser')

                links_counter = 0
                results = []

                # navigate through the dom and get the tags I'm interested in
                for i in soup.find_all('div', {'class': 'result__body'}):
                    try:
                        title = i.h2.a.text
                        description = i.find('a', {'class': 'result__snippet'}).text
                        url = i.h2.a.get('href')
                        results.append(dict(title=title, description=description, url=url))
                    except Exception as e:
                        #in duckduckgo: if no results are found, then one result with the message 'no result'
                        # is given, this throws off the above parsing, so it gives exception, but it's actually
                        # normal behaviour, so let this one error pass, otherwise something went wrong
                        if i.find_all('div', class_='no-results'):
                            pass
                        else:
                            print("Couldn't parse duckduckgo page: ", e)
                    else:
                        links_counter += 1
                    if links_counter > self.get_top_n:
                        break
                return results
            else:
                # sometimes I get other status codes, like 429 -> 'too many requests, a temporary ban
                return []

    def get_google_links(self):
        """Search google and return a result array, containing a dictionary with title,
        url and description """

        # Use the format "module-name"+"module-version"+"exploit" (the '"' are used to enforce that google
        # has to include it, and can't leave it out... gives a bunch of false positives otherwise that are irrelevant
        search_term = '%22' + self.db_module['name'] + '%22+%22' + self.db_module['version_mayor_minor'] + '%22+exploit'
        self.db_search['term'] = search_term
        self.db_search['url'] = "https://www.google.com/search?q=" + search_term

        try:
            page = requests.get(self.db_search['url'], headers=self.header_user_agent)
            time.sleep(self.search_engine_delay)
        except:
            self.db_search['status_code'] = '???'
            return None
        else:
            if page.status_code == 200:
                self.db_search['status_code'] = page.status_code
                soup = BeautifulSoup(page.content, 'lxml')

                links_counter = 0
                results = []
                # navigate through the dom and get the tags I'm interested in
                for i in soup.find_all('div', {'class': 'rc'}):
                    try:
                        title = i.find('div', {'class': 'r'}).a.h3.text
                        description = i.find('div', {'class': 's'}).div.text
                        url = i.find('div', {'class': 'r'}).a.get('href')
                        results.append(dict(title=title, description=description, url=url))
                    except Exception as e:
                        print("Couldn't parse google page: ", e)
                    links_counter += 1
                    if links_counter > self.get_top_n:
                        break

                return results
            else:
                # sometimes I get other status codes, like 429 -> 'too many requests, a temporary ban
                self.db_search['status_code'] = page.status_code
                return []

    def get_exploit_db_exploit_details(self, result_url):
        try:
            exploit_db_exploit_details_page = requests.get(result_url, headers=self.header_user_agent)
            soup = BeautifulSoup(exploit_db_exploit_details_page.content, 'html.parser')
        except Exception as e:
            print("Error trying to open page: " + result_url + " (", e, ")")
            return False
        else:
            if exploit_db_exploit_details_page.status_code == 200:
                try:
                    exploit_title = soup.find('h1', class_=self.exploit_db_exploit_title_class).text.replace('\n', '').strip()
                except Exception as e:
                    print("Error trying to parse page: " + result_url + " (", e, ")")
                else:
                    # replace google snippet by the site summary
                    self.db_result['snippet'] = exploit_title
            else:
                print("Got status code:", exploit_db_exploit_details_page.status_code, "for page: " + result_url)

    def get_cve_details(self, result_url):
        """Visit a https://www.cvedetails.com/cve/ page and get some details of the vulnerability
        since we are on a local machine and looking for privesc, I attribute extra score if I find
        a vulnerability that indicates privilege escalation"""

        try:
            cve_details_page = requests.get(result_url, headers=self.header_user_agent)
            cve_details_soup = BeautifulSoup(cve_details_page.content, 'lxml')
        except Exception as e:
            print("Error trying to open page: " + result_url + " (", e, ")")
            return False
        else:
            if cve_details_page.status_code == 200:
                try:
                    cve_details_summary = cve_details_soup.find(class_=self.cvedetails_summary).text.replace('\n', '').replace('\t', '')
                    # Navigate through the dom to find the tags we're interested in
                    cve_details_table = cve_details_soup.find(id=self.cvedetails_scores_and_types_id)
                    cve_details_tablerows = cve_details_table.find_all('tr')
                except Exception as e:
                    print("Error trying to parse page: " + result_url + " (", e, ")")
                else:
                    # replace google snippet by the site summary
                    self.db_result['snippet'] = cve_details_summary
                    # go over the details table
                    for cve_details_tablerow in cve_details_tablerows:
                        try:
                            cve_details_tablerow_title = cve_details_tablerow.find_all('th')[0].text
                            cve_details_tablerow_content = cve_details_tablerow.find_all('td')[0].text.split("\n")[0]
                        except Exception as e:
                            print("Unable to parse results for page: " + result_url + " (", e, ")")
                        else:
                            self.db_result_detail[cve_details_tablerow_title] = cve_details_tablerow_content
                            if cve_details_tablerow_title == self.cvedetails_gained_access_th:
                                if cve_details_tablerow_content == self.cvedetails_gained_access_admin_string:
                                    self.db_score['gained_access'] += self.cvedetails_gained_access_score_weight
                try:
                    cve_details_references = cve_details_soup.find('table', id=self.cvedetails_references_id)
                    cve_details_references = cve_details_references.find_all('td')
                except Exception as e:
                    print("Error trying to parse references-table: " + result_url + " (", e, ")")
                else:
                    for cve_details_reference in cve_details_references:
                        try:
                            cve_details_reference_link = cve_details_reference.a.get('href')
                            cve_details_reference_link_text = cve_details_reference.a.text
                        except Exception as e:
                            print("Unable to parse references-table links: " + result_url + " (", e, ")")
                        else:
                            #If a reference to an exploit is found, append it to our searchengine links, so
                            #that we process and score this link as well
                            if self.exploit_db_exploit_url in cve_details_reference_link:
                               test = self.searchengine_links
                               self.searchengine_links.append({'url': cve_details_reference_link,
                                                               'title': cve_details_reference_link,
                                                               'description': cve_details_reference_link_text})
            else:
                print("Got status code:", cve_details_page.status_code, "for page: " + result_url)

    def calculate_score(self):
        """Calculates the total score of the search: it iterates over all 'score-keys' (except the total-key)
        and sums them all up. Since I use the score for easy sorting of the outputfile, I make sure that for
        all scores below 10, I add an extra zero before it"""
        self.db_score['total'] = 0

        for key in self.db_score:
            if key != 'total':
                self.db_score['total'] += self.db_score[key]

        # convert to string that allows for easy sorting
        if self.db_score['total'] < 10:
            self.db_score['total_string'] = '0' + str(self.db_score['total'])
        else:
            self.db_score['total_string'] = str(self.db_score['total'])

    def sort_dict(self, item: dict):
        """
        Sort nested dict
        Example:
             Input: {'a': 1, 'c': 3, 'b': {'b2': 2, 'b1': 1}}
             Output: {'a': 1, 'b': {'b1': 1, 'b2': 2}, 'c': 3}
        """
        return {k: self.sort_dict(v) if isinstance(v, dict) else v for k, v in sorted(item.items(), reverse=True)}

    def extract_exploits_from_db(self, db):
        """Run over each module. For each result of that module, check if that result is an URL that leads to
        an exploit. If it does, store it in an array
        For all exploits in that array, group them by exploit, but keep track of what modules that exploit
        applies to"""
        self.db_exploits = {}
        db_exploits_no_score = {}
        exploits = []
        #extract all exploit-url's
        for module_id in db:
            for result_id in db[module_id]['results']:
                if self.exploit_db_exploit_url in result_id:
                    exploits.append({'title': db[module_id]['results'][result_id]['snippet'],
                                     'url': db[module_id]['results'][result_id]['url'],
                                     'module': {'name': db[module_id]['module']['name'],
                                                'version_complete': db[module_id]['module']['version_complete'],
                                                'score_total': db[module_id]['score']['total']},
                                     'modules': [],
                                     'score': 0})
        #Group by exploit-url
        for exploit in exploits:
            if not exploit['url'] in db_exploits_no_score:
                db_exploits_no_score[exploit['url']] = exploit
            db_exploits_no_score[exploit['url']]['modules'].append(
                exploit['module']['name'] + ' ' + exploit['module']['version_complete'])
            db_exploits_no_score[exploit['url']]['score'] += exploit['module']['score_total']

        #Contruct final db
        for exploit_id in db_exploits_no_score:
            if db_exploits_no_score[exploit_id]['score'] < 10:
                db_exploits_no_score[exploit_id]['score_string'] = '0' + str(self.db_score['total'])
            else:
                db_exploits_no_score[exploit_id]['score_string'] = str(db_exploits_no_score[exploit_id]['score'])

            self.db_exploits[db_exploits_no_score[exploit_id]['score_string'] + ' - ' + exploit_id] = db_exploits_no_score[exploit_id]

    def print_report(self):
        """Prints a report to the commandline
        The argument '-sr' or '--short-report' forces a short report, showing only the name, score,
        search URL and a list of found exploits
        Without the argument '-sr', the standard report is printed
        The argument '-nr' or '--no-report' suppresses any report to be output to the command line"""
        #Give a report, sorted on score
        db = self.db_sorted

        if self.short_report == False:
            for module_id in db:
                if db[module_id]['score']['total'] > 0:
                    print(Formatting.bold, Formatting.underline)
                    print(db[module_id]['module']['name'] + " " + db[module_id]['module']['version_complete'] +
                          Formatting.reset + ' ( ' + Formatting.fgcolor.blue + db[module_id]['search'][
                              'url'] + Formatting.reset + ' )')
                    print(Formatting.bold + 'Score: ' + db[module_id]['score']['total_string'] + Formatting.reset)
                    url_counter = 1
                    for result_id in db[module_id]['results']:
                        print(str(url_counter) + ')' + Formatting.fgcolor.blue,
                              db[module_id]['results'][result_id]['url'] + Formatting.reset)
                        print(db[module_id]['results'][result_id]['snippet'])
                        url_counter += 1
                        try:
                            for details_id in db[module_id]['results'][result_id]['details']:
                                print('   ' + details_id + ": " +
                                      db[module_id]['results'][result_id]['details'][details_id])
                        except:
                            pass

        self.extract_exploits_from_db(db)
        db = self.sort_dict(self.db_exploits)
        print(Formatting.bold, Formatting.underline)
        print("Exploit(s) summary" + Formatting.reset)
        if len(db) == 0:
            print("No public exploits found")
        for exploit_id in db:
            title_needed = True
            print(Formatting.bold, Formatting.underline)
            print("Score: " + db[exploit_id]['score_string'] + ' - ' +
                  self.limit_characters(db[exploit_id]['title'], '+10') + " " +
                  Formatting.reset + ' ( ' + Formatting.fgcolor.blue +
                  db[exploit_id]['url'] + Formatting.reset + ' )')
            for module in db[exploit_id]['modules']:
                if title_needed:
                    print("Found for: ", end='')
                    title_needed = False
                else:
                    print(", ", end='')
                print(module, end='')
        print()
        #This can never execute, but it's an alternateformatting that may I may use somehow
        if 'alternatereport' == 'nope':
            for module_id in db:
                title_needed = True
                for result_id in db[module_id]['results']:
                    if self.exploit_db_exploit_url in result_id:
                        if title_needed:
                            print(Formatting.bold, Formatting.underline)
                            print(db[module_id]['module']['name'] + " " +
                                  db[module_id]['module']['version_complete'] +
                                  Formatting.reset + Formatting.bold +
                                  ' - Score: ' + db[module_id]['score']['total_string'] +
                                  Formatting.reset + ' ( ' + Formatting.fgcolor.blue +
                                  db[module_id]['search']['url'] + Formatting.reset + ' )')
                            title_needed = False
                        print(db[module_id]['results'][result_id]['snippet'] + ": ", end='')
                        print(Formatting.fgcolor.blue, db[module_id]['results'][result_id]['url'] + Formatting.reset)
            print()

    def starwrap(self, title, f=None):
        """used for the reporting: it wraps a title in asterisks"""
        # if no file handler is given, we'll want to output to screen
        if f == None:
            for i in title:
                print("*", end='')
            print()
            print(title)
            for i in title:
                print("*", end='')
            print()
        else:
            for i in title:
                f.write("*")
            f.write('\n')
            f.write(title)
            f.write('\n')
            for i in title:
                f.write("*")
            f.write('\n')

    def store_report(self, filename=''):
        """Prints a report to an output file

        Return value: filename"""

        if filename == '':
            filename = self.output_file + '.report'

        with open(filename, 'w') as f:
            for module_id in self.db_sorted:
                if self.db[module_id]['score']['total'] > 0:
                    title = self.db[module_id]['module']['name'] + " " + self.db[module_id]['module']['version_complete'] + ' ( ' + self.db[module_id]['search']['url'] + ' )'
                    f.write('\n')
                    self.starwrap(title, f)
                    f.write('Score: ' + self.db[module_id]['score']['total_string'] + '\n')
                    url_counter = 1
                    for result_id in self.db[module_id]['results']:
                        f.write('\n' + str(url_counter) + ')' + self.db[module_id]['results'][result_id]['url'] + '\n')
                        f.write('- ' + self.db[module_id]['results'][result_id]['snippet'] + '\n')
                        url_counter += 1
                        try:
                            for details_id in self.db[module_id]['results'][result_id]['details']:
                                f.write('   ' + details_id + ": " +
                                        self.db[module_id]['results'][result_id]['details'][details_id] + '\n')
                        except:
                            pass

            self.extract_exploits_from_db(self.db_sorted)
            db = self.sort_dict(self.db_exploits)
            f.write('\n')
            self.starwrap("Exploit(s) summary", f)
            if len(db) == 0:
                f.write("No public exploits found" + '\n')
            for exploit_id in db:
                title_needed = True
                f.write('\n')
                f.write("Score: " + db[exploit_id]['score_string'] + ' - ' +
                      self.limit_characters(db[exploit_id]['title'], '+10') + ' ( ' + db[exploit_id]['url'] + ' )' + '\n')
                for module in db[exploit_id]['modules']:
                    if title_needed:
                        f.write("Found for: ")
                        title_needed = False
                    else:
                        f.write(", ")
                    f.write(module)
            f.write('\n')

        return filename

    def limit_characters(self, string, limit=0):
        """Feed it a string and it limits the characters to a certain length. If the initial string was
        longer then the limit, the string is truncated and appended with '...', otherwise the original
        string is returned.
        You always get a string in return that's no longer than your requested limit"""
        if limit == 0:
            limit = self.print_exploits_character_limit
        if isinstance(limit, str):
            if limit[0:1] == '+':
                limit = self.print_exploits_character_limit + int(limit[1:])
            else:
                raise ValueError("Can't parse the argument: you gave a string as 'limit', I expected the first character to be a '+', but it was something else.")
        if len(string) > limit:
            return string[0:limit] + '...'
        else:
            return string

    def print_status(self):
        """While the search is running, this function outputs a short status-report for each search
        to the command line"""
        # with a status bar, I could only limit the output to results with a score,
        # significant enough to show:
        # if db_score['total'] > round(self.get_top_n / 2):
        status_code_message = "Status: " + str(self.db_search['status_code'])
        if self.db_search['status_code'] == 200:
            print(Formatting.fgcolor.green + status_code_message + Formatting.reset, end='')
        else:
            print(Formatting.fgcolor.red + status_code_message + Formatting.reset, end='')

        score_message = " - Score: " + str(self.db_score['total'])
        if round(self.get_top_n / 2) < self.db_score['total'] <= self.get_top_n:
            print(Formatting.fgcolor.green + score_message + Formatting.reset, end='')
        elif self.db_score['total'] > self.get_top_n:
            print(Formatting.fgcolor.purple + score_message + Formatting.reset, end='')
        else:
            print(score_message, end='')
        print(" - " + self.db_module['name'] + " " + self.db_module['version_complete'] + " - ", end='')
        print(Formatting.fgcolor.blue + self.db_search['url'] + Formatting.reset)

        if self.print_exploits:
            header_printed = False
            for result_id in self.db_results:
                if self.exploit_db_exploit_url in result_id:
                    exploit_snippet = self.limit_characters(self.db_results[result_id]['snippet'])

                    if header_printed:
                        print(", " + exploit_snippet, end='')
                    else:
                        print("(" + exploit_snippet, end='')
                        header_printed = True
            if header_printed:
                print(")")

    def identify_file(self, filename):
        """Function that tries to make sense of whatever file you feed it. Currently it's simple:
        if you feed it a file with an xml extension, it supposes a nmap-xml
        If you feed it something that has no xml extension, it supposes you feed it a dpkg-dump"""
        
        #file doesn't exist
        if not os.path.exists(os.path.join(os.getcwd(), filename)):
            return "single_search"
        
        #file with extension .xml
        extension = os.path.splitext(filename)[1]
        if extension == ".xml":
            return "nmap"
        else:
            test_counter = 0
            dpkg_counter = 0
            tab_counter = 0
            with open(filename) as file:
                for line in file:
                    test = line.split('\t')
                    if len(test) == 2:
                        try:
                            #Try to verify the presence of version numbers in the second column
                            test2 = re.search('(\d*\.\d|\d*:\d*\.\d|\d\d*)', test[1], flags=re.DOTALL).group(0).strip()
                        except:
                            #if you can't find them, this is probably a dpkg
                            dpkg_counter += 1
                        else:
                            #if you can find them, this is probably a tab-separated file
                            tab_counter += 1
                    else:
                        #increase dpkg counter
                        dpkg_counter += 1
                    test_counter += 1

                    #don't do the entire file, just take a sample of 5 lines
                    if test_counter > 5:
                        break
            #test the result
            if dpkg_counter > tab_counter:
                return "dpkg"
            else:
                return "tab"

    def fetch_vulnerabilities(self):
        """Do a search on a searchengine, parse the results and give it a score"""
        self.db_score = {}
        self.db_score['gained_access'] = 0
        self.db_score['version_complete_match'] = 0
        self.db_score['trusted_count'] = 0
        self.db_score['exploit_available'] = 0
        self.db_score['exploit_available_but_no_name_match'] = 0
        self.db_score['exploit_available_but_no_version_mayor_minor_match'] = 0
        # then get the search results for this module-name and version number
        if self.search_engine == '':
            if self.file_identifier == 'tab' or self.file_identifier == 'dpkg':
                self.searchengine_links = self.get_duckduck_links()
            else:
                self.searchengine_links = self.get_google_links()
        else:
            if self.search_engine == 'google':
                self.searchengine_links = self.get_google_links()
            else:
                self.searchengine_links = self.get_duckduck_links()
        # For each link, iterate over it
        for link in self.searchengine_links:
            self.db_result = {}
            # iterate over all trusted sources
            for trusted_source in self.trusted_sources:
                # if our link is a trusted source, and the description contains the name of the module
                if trusted_source in link['url']:
                    self.db_result['url'] = link['url']
                    self.db_result['snippet'] = link['description']

                    self.db_result_detail = {}
                    if self.exploit_db_exploit_url in link['url']:
                        self.db_score['exploit_available'] += self.exploit_available_score_weight
                        self.get_exploit_db_exploit_details(link['url'])
                        if not self.db_module['name'] in self.db_result['snippet']:
                            self.db_score['exploit_available_but_no_name_match'] -= 1
                        if self.db_module['version_complete'] == '' or not self.db_module['version_mayor_minor'] in self.db_result['snippet']:
                            self.db_score['exploit_available_but_no_version_mayor_minor_match'] -= 1

                    if self.cve_details_url in link['url']:
                        # grab details
                        self.get_cve_details(link['url'])
                        self.db_result['details'] = self.db_result_detail

                    self.db_results[link['url']] = self.db_result

                    if not self.db_module['version_complete'] == '' and self.db_module['version_complete'] in self.db_result['snippet']:
                        self.db_score['version_complete_match'] += self.version_complete_match_score_weight
                    self.db_score['trusted_count'] += 1
        self.calculate_score()

    def parse_tab(self, line):
        array = line.split('\t')
        if len(array) == 2:
            try:
                self.db_module['version_complete'] = re.search('\d+([\.:]\d+)*', array[1], flags=re.DOTALL).group(0).strip()
                self.db_module['version_mayor_minor'] = re.search('(\d*\.\d|\d*:\d*\.\d|\d\d*)', array[1], flags=re.DOTALL).group(0).strip()
            except:
                self.db_module['version_complete'] = ''
                self.db_module['version_mayor_minor'] = ''
            finally:
                if array[0].strip() == '':
                    return False
                else:
                    self.db_module['raw_name'] = array[0]
                    self.db_module['name'] = array[0]
                    return True

    def process_single_search(self, filename):
        """

        :param filename:
        :return:
        """

        self.db_search = {}
        self.db_results = {}
        self.db_module = {}
        array = filename.split('^')
        if len(array) == 1:
            self.db_module['version_complete'] = ''
            self.db_module['version_mayor_minor'] = ''
        else:
            self.db_module['version_complete'] = array[1]
            try:
                self.db_module['version_mayor_minor'] = re.search('(^\d*\.\d|^\d*:\d*\.\d|^\d\d*)', array[1],
                                                flags=re.DOTALL).group(0).strip()
            except:
                self.db_module['version_mayor_minor'] = ''

        if array[0].strip() == '':
            # If a service doesn't have a name, it may be a closed or filtered port, either way, there
            # is no point looking for something
            return False
        self.db_module['raw_name'] = array[0]
        self.db_module['name'] = array[0]
        self.fetch_vulnerabilities()

        self.db[self.db_score['total_string'] + ' - ' + self.db_module['name'] + " " + self.db_module[
            'version_complete']] = {"module": self.db_module, "score": self.db_score, "search": self.db_search,
                                    "results": self.db_results}

        self.print_status()

        self.db_sorted = self.sort_dict(self.db)

    def process_tab(self, filename):
        """Read all servicenames and version numbers from a tab-separated file, then do an online search
        for vulnerabilities"""

        with open(filename) as file:
            for line in file:
                self.db_search = {}
                self.db_results = {}
                self.db_module = {}
                # If I successfully parsed the current line in the input-file
                if self.parse_tab(line):
                    self.fetch_vulnerabilities()
                else:
                    continue

                self.db[self.db_score['total_string'] + ' - ' + self.db_module['name'] + " " + self.db_module[
                    'version_complete']] = {"module": self.db_module, "score": self.db_score,
                                            "search": self.db_search,
                                            "results": self.db_results}

                self.print_status()
            # if the entire file is processes, create a sorted database
            self.db_sorted = self.sort_dict(self.db)

    def process_nmap(self, filename):
        """Read all servicenames and version numbers from an nmap file, then do an online search
        for vulnerabilities"""
        with open(filename) as file:
            contents = file.read()
            soup = BeautifulSoup(contents, 'xml')
            services = soup.find_all('service')
            for service in services:
                self.db_search = {}
                self.db_results = {}
                self.db_module = {}
                name = service.get('product')
                version_complete = service.get('version')
                if name == None:
                    #If a service doesn't have a name, it may be a closed or filtered port, either way, there
                    #is no point looking for something, just skip this record
                    continue
                if version_complete == None:
                    version_complete = ''
                    version_mayor_minor = ''
                else:
                    version_mayor_minor = re.search('(^\d*\.\d|^\d*:\d*\.\d|^\d\d*)', version_complete, flags=re.DOTALL).group(0).strip()
                self.db_module['raw_name'] = name
                self.db_module['name'] = name
                self.db_module['version_complete'] = version_complete
                self.db_module['version_mayor_minor'] = version_mayor_minor
                self.fetch_vulnerabilities()

                self.db[self.db_score['total_string'] + ' - ' + self.db_module['name'] + " " + self.db_module[
                    'version_complete']] = {"module": self.db_module, "score": self.db_score, "search": self.db_search,
                                            "results": self.db_results}

                self.print_status()
            # if the entire file is processes, create a sorted database
            self.db_sorted = self.sort_dict(self.db)

    def process_dpkg(self, filename):
        """For each line, extract the module name and version number, the do an online search
        and retrieve relevant information"""
        line_counter = 0
        with open(filename) as file:
            for line in file:
                self.db_search = {}
                self.db_results = {}
                self.db_module = {}
                line_counter += 1
                # If I successfully parsed the current line in the input-file
                if self.parse_dpkg(line):
                    self.fetch_vulnerabilities()

                self.db[self.db_score['total_string'] + ' - ' + self.db_module['name'] + " " + self.db_module[
                    'version_complete']] = {"module": self.db_module, "score": self.db_score, "search": self.db_search,
                                            "results": self.db_results}

                self.print_status()
        # if the entire file is processes, create a sorted database
        self.db_sorted = self.sort_dict(self.db)

    def store_output(self, filename="", sort_order="d"):
        """Store all results in a json output file. There's a choice between sorting ascending or descending"""
        if filename == "":
            filename = self.output_file + '.json'

        if sort_order == "d":
            with open(filename, 'w') as outfile:
                json.dump(self.db, outfile, sort_keys=True, indent=4)
        else:
            with open(filename, 'w') as outfile:
                json.dump(self.db_sorted, outfile, indent=4)

        return filename

parser = argparse.ArgumentParser()
parser.add_argument("input", type=str,
                    help="The file you want to process. Both nmap xml files and files coming from the "
                         "command 'dpkg -l > file' are supported")
parser.add_argument("-no", "--no-output", action="store_true",
                    help="By default a json file with all raw results and a readable report is generated. Use this option if you don't want to generate these files")
parser.add_argument("-nr", "--no-report", action="store_true",
                    help="By default a report is printed to the commandline. Use this option "
                         "if you don't want to print one")
parser.add_argument("-sr", "--short-report", action="store_true",
                    help="By default an extensive report is printed to the command line. Use this flag to print a short report that shows only the found exploits")
parser.add_argument("-se", "--show-exploits", action="store_true",
                    help="By default exploits aren't listed in the command line status report (the output during the search). Use this flag if you want to show them in the report during search")
parser.add_argument("-fg", "--force-google", action="store_true",
                    help="By default the duckduckgo searchengine is used for longer lists (and google is used for short searches). You can force to use google in all cases. Just know that google will probably ban yo ass after about 150 searches: they don't like that you crawl their website")
parser.add_argument("-fd", "--force-duckduckgo", action="store_true",
                    help="By default the google searchengine is used for short searches (and duckduckgo for longer lists). You can force to use duckduckgo as searchengine in all cases. Just be mindful about the fact that using duckduckgo still carries a bug. Be sure to run the 'benchmark' before you use this")
parser.add_argument("-pb", "--proxy-burp", action="store_true",
                    help="By default no proxy is used. If you want to use the burpsuite proxy, use this argument")
args = parser.parse_args()
input_file = args.input

search_engine = ''
if args.force_google:
    search_engine = 'google'
if args.force_duckduckgo:
    search_engine = 'duckduckgo'

vulnfetcher = Vulnfetcher(input_file, True, not args.no_output, not args.no_report, args.short_report, args.show_exploits, search_engine, args.proxy_burp)
