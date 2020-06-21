# Vulnfetcher
> An enumeration tool that can be chained to nmap, or take list of installed packages or services and search the web for known vulnerabilities.

> It's similar to searchsploit, but differs in that it uses searchengines, is able to process large lists unattended in the background and it plays well with nmap.

> It performs basic searches, scores the results and highlights what sticks out.

> ![Vulnfetcher Nmap Demo](/demo/vulnfetcher_nmap_chain.gif)

## Install dependencies
```
pip3 install requests
pip3 install beautifulsoup4
pip3 install lxml
```
## Install
```
cd /opt
git clone https://github.com/gnothiseautonlw/vulnfetcher.git
```
### Verify everything works
```
cd /opt/vulnfetcher
python3 vulnfetcher.py benchmark
```
> You should get an output similar to:
```
Status: 200 - Score: 7 - JAMES smtpd  2.3.2 - https://duckduckgo.com/html/?q=%22JAMES+smtpd+%22+%222.3%22+exploit
Status: 200 - Score: 7 - JAMES pop3d  2.3.2 - https://duckduckgo.com/html/?q=%22JAMES+pop3d+%22+%222.3%22+exploit
Status: 200 - Score: 18 - libpam-modules  1.1.0 - https://duckduckgo.com/html/?q=%22libpam-modules+%22+%221.1%22+exploit 
```
> If you receive scores that are below 3 for any of these, you are encountering a known bug. Please report. Unless fixed you can not use this tool reliably

## Usage
### nmap chaining
```
nmap -sC -sV -oA scan <CHANGE_THIS_TO_TARGET_HOST> && python3 /opt/vulnfetcher/vulnfetcher.py -sr scan.xml
```
### dpkg
> The goal of the debian packages-list support is to give you a fighting change to reduce a list of 200 installed packages to a handful of potentially vulnerable targets, sorted on probability of vulnerability:
```
dpkg -l > file
python3 /opt/vulnfetcher/vulnfetcher.py file
```
> v![Vulnfetcher Dpkg Demo](/demo/vulnfetcher_dpkg_optimized.gif)
### tab-separated file
> Create a tab-separated file with the structure:
```
<package_or_service_name_1> <tab> <version>
<package_or_service_name_2> <tab> <version>
<package_or_service_name_N> <tab> <version>
```
> Then run
```
python3 /opt/vulnfetcher/vulnfetcher.py file
```
## Output
Appart from the onscreen report while scanning and afterwards, the tool writes two files in the same folder as the input file:
* <input_file>.vulnfetcher.json
   * A sorted json file, containing all information the tool found and that it used to score the findings
* <input_file>.vulnfetcher.report
   * A sorted textfile containing the report that's printed on screen after the search is done

## Help
```
python3 /opt/vulnfetcher/vulnfetcher.py -h
```
## How it works
### Parsing:
* It takes the input file, tries to make sense of the module names and module version numbers
* For the search term, it takes the 'mayor' - 'dot' - 'first number of minor'. So "libpam-modules 1.15.2", becomes "1.1"
* Then goes out on the web, looking with the search term: '"module_name"+"module_version"+exploit'. So in our example, it will look for '"libpam-modules"+"1.1"+"exploit"'
* If it finds exact CVE numbers, it will go fetch those details and bring them to you
* If it finds a public exploit reference on for example the cvedetails website, it will reference to that exploit. In other words, it doesn't only use searchengine pages, it also fetches information of cvedetails pages and exploit-db pages
### Scoring:
* For each trusted site that returns a result, it get's one point.
* If names or version numbers aren't found, it penelizes the score.
* If an exact match for the complete version number is found, it adds to the score. So in our example if '1.15.2' would be found, this would result in a higher score
* If an exact cve-number is found, the details of that cve are fetched. If those details contain indications of a severe vulnerability, resulting in a higher score

## Error reporting
* This is still in beta: I have one error that sometimes throws off searches. It seems to have something to do with the useragent, but I have a hard time tracking the bug down. 
* If the tool doesn't find a vulnerability that you were able to find manually, please report an issue. Provide a sample of the file you used as input and a page where you eventually found the vulnerability.

## Suggested Development Roadmap
If a real coder would like to pick this up, here's a suggested roadmap:
* Currently I use duckduckgo as searchengine and crawl those results
   * Maybe there are better solutions, like maybe a non-profit google-api-key?
* Adding a progress bar when searching.
   * It would allow to display only results with a higher score and keep the output more condenced when the search is running
* Extensive testing
* Support for more input formats
* Improving the scoring algorithm 
   * could be improved by doing more testing
* Make code more beautiful.
   * I actually learned python to write this program, so I expect the code can be improved a lot
