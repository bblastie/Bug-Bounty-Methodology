# Step 1a - Automated Recon
## Identify TLDs 
- HackerOne/Bugcrowd/Custom Scope

## Automated Recon
- Run ars0n for automated enumeration to cover most beginning steps
    - https://github.com/R-s0n/ars0n-framework 

# Step 1b - Additional TLDs and Manual Recon
- Acquisitions
    - https://www.crunchbase.com/
    - https://pitchbook.com/profiles/company/10377-37
- Google
    - site:targetdomain.com -site:www.targetdomain.com 
    - TO DO: find more dorks
- Manual search of crt.sh 
- check_mdi.py -d `target.com`
- Look for ASNs
    - https://bgp.he.net/
    - https://dnschecker.org 
- Port Scan ASN IP Ranges and IPs in ars0n
    - Naabu + ASNmap
        - `echo AS394161 | asnmap -silent | naabu -silent -nmap-cli 'nmap -sV'`
    - ars0n data set 
        - `python3 ip-parser.py` 
        - `cat ../temp/floqast.app.txt | naabu -top-ports 1000  -silent -nmap-cli 'nmap -sV'`
- Shodan Passive Anaylsis
    - Karmav2 
        - `bash karma_v2 -d tesla.com --limit -1 -deep |tee karmav2.txt`
    - Shosubgo
        - `shosubgo -d tesla.com -s YOURAPIKEY`
    - smap
        - passive shodan port scans (does not touch target)
        - `smap tesla.com`
- Ad / Analytics Relationships
    - relations.sh 
        - `bash ~/Tools/relations.sh -d tesla.com`
- Perform DNS recon on interesting subs
    - `dnsrecon -t axfr -d domain`
- Favicon?

# Step 3 - Subdomains 
- Review subdomains in ars0n
- Review CVE and Nuclei results 
- Review Screenshots of subdomains (ars0n Enumeration tab) for interesting responses

# Step 4 - Github Enumeration
- Find Users with public repos that may be relevant
    - `python3 github-users.py -k floqast`
- Run github_brute-dork.py 
    - `python3 github_brutedork.py -u blackblastie -t <gh-pat> -o <organization>`
    - Paste results to ars0n in Recon tab for easy review
- Dora
    - https://github.com/sdushantha/dora#example-use-cases 
- Run Trufflehog against interesting users and/or repos
    - `curl -L -H "Accept: application/vnd.github+json" -H "Authorization: Bearer <gh-pat>" -H "X-GitHub-Api-Version: 2022-11-28" https://api.github.com/users/<USERNAME>/repos?per_page=100 | jq .[].git_url -r | sed 's/git:/https:/' | sudo xargs -I % trufflehog github --repo=%`
- Check any found secrets for validity
    - https://github.com/streaak/keyhacks
    - https://github.com/gwen001/keyhacks.sh 

# Step 5 - Cloud
- Run fire-cloud.py
- Gather IPs from Wildfire.py scan and run through ip2provider.py
    - ip-parser.py
    - Run Masscan 
- Manually run cloud-enum
    - https://github.com/initstring/cloud_enum 
- AADInternals as Outsider
    - Run on Windows/Powershell
    - `import-module AADInternals`
    - `Invoke-AADIntReconAsOutsider -Domain "floqast.com" | format-table`
- Review findings and interesting endpoints

# Step 6 - Hands On Testing
### Take all interesting endpoints and manually test them
### Application Analysis

- What stack/languages are used?

- What server is running the application?
 
- Is there a WAF?
 
-  What additional libraries are used? Are there known exploits for these libraries?  Custom JS Llbraries?
 
- Is there Authentication? 
 
- What Objects are used?
 
- How is session established?
 
- Are there useful comments?
 
- What common features are present?
 
- How is a user identified?
 
- Are there multiple user roles?
 
- Is there an API?
 
- Is there an Content Management System?
 
- Is there a Content Security Policy?
 
- Is CORS implemented?
 
- How does the app pass data?
 
- Are WebSockets used?
 
- How/where does the app talk about users?
 
- Does the site have multi-tenancy?
 
- Is the source code publicly available?
 
- Does the site have a unique threat model?  
 
- Has there been past security research and vulns?
 
- How does the app handle common vuln classes?
 
- Where does the app store data?


### Ask yourself these questions for EVERY page

1. What part of CRUD?
2. What HTTP request methods can be used? (GET/POST/PUT/DELETE/etc.)
3. What parameters can be used?

#### Tech Profile  
- Web Server: 
- Database:   
- Cloud Provider: 
- WAF:
- CMS:
- Framework: 
- Programming Language: 
- Other: 

### Content Discovery
- Try to locate `/robots.txt` , `/crossdomain.xml` `/clientaccesspolicy.xml` `/sitemap.xml` and `/.well-known/`
- In Content Discovery, we are looking for - Endpoints, parameters, routes, secrets, domains
- Burp driven 
    - Step 1 - Click through the app 
    - Step 2 - Burp Crawl
    - Step 3 - `Discover Content` in Burp (Right click on target in Target tab)
    - Step 4 - Intruder fuzzing with small raft payload list
- Directory discovery
    - Fuzz for directories
        - https://www.acceis.fr/ffuf-advanced-tricks/
    - Use tech specific wordlists
        - wordlists.assetnote.io
        - SecLists
        - https://github.com/six2dez/OneListForAll
    - Determine if they are running OSS or COTS
        - Local install if OSS to find what paths to look for
        - For paid/COTS, try to get a demo version
        - Check dockerhub for instances of the software
        - Look at devs Github's to look for what they may be installing/modifying
    - Waymore to look for historical content
        - https://github.com/xnl-h4ck3r/waymore 
    - XNLinkFinder
        - Include waymore results
        - https://github.com/xnl-h4ck3r/xnLinkFinder 
    - Use GF to look for vulnerable URLs 
        - https://github.com/1ndianl33t/Gf-Patterns
    - Recursively brute force paths that return 401, 403
        - `ffuf -recursion -recursion-depth 1 -u http://192.168.10.10/FUZZ -w /opt/useful/SecLists/Discovery/Web-Content/raft-small-directories-lowercase.txt`
- JavaScript Analysis
    - GAP Burp extension
        - https://github.com/xnl-h4ck3r/GAP-Burp-Extension
    - For packed or obfuscated JS try 
        - http://deobfuscate.io/
        - https://spaceraccoon.github.io/webpack-exploder/ 
    - Use JS Miner Burp extension
        - https://portswigger.net/bappstore/0ab7a94d8e11449daaf0fb387431225b 
    - Jsluice
        - https://github.com/BishopFox/jsluice 
        - Endpoint extraction from JS file
            - Add `function jsurls { jsluice urls <(curl -sk "$1"); }` to .bashrc/.zshrc
            - `jsurls {link to js file}`
        - https://github.com/BishopFox/jsluice/tree/main/cmd/jsluice 
        - https://www.youtube.com/watch?v=BnQBp83YbqY
    - DOM Invader
        - https://portswigger.net/burp/documentation/desktop/tools/dom-invader 
- Web Fuzzing 
    - Dynamic scanning - the process of injecting payloads into one parameter or value to see if we can trigger a vuln type
    - Burp Param Miner
    - Burp Active Scan
    - Backslash powered scanner (burp ext)
    - Scan Defined Insertion Points in burp intruder
    - If you want to scan with your own wordlists in intruder
        - Payloadallthethings
        - SecLists

### Client Side Testing
- Fuzz all request parameters
- Identify all reflected data
    - Burp scan with only these two issues enabled
        - `Input returned in response (reflected)`
        - `Suspicious input transformation`
- Reflected XSS 
    - Scan w/ Dalfox
        - https://github.com/hahwul/dalfox
    - https://pentestbook.six2dez.com/enumeration/web/xss
    - Use custom burp scan w/ only xss audits enabled
    - XSS Polyglots
        - https://github.com/TyrantSec/Fuzzing/blob/master/XSS-Polyglots/99-XSS-Polyglots.txt 
- Client Side Prototype Pollution
    - TO DO: Build Methodology
    - ars0n custom Nuclei scans
- Client Side Template Injection
    - https://github.com/Hackmanit/TInjA
    - TO DO: Build Methodology
- PostMessage Vulnerabilities
    - TO DO: Build Methodology
- WebSockets Vulnerabilities
    - TO DO: Build Methodology
- Insecure Data Storage 
    - TO DO: Build Methodology
- DOM Open Redirect 
    - https://pentestbook.six2dez.com/enumeration/web/open-redirects
- Content/Code Injection 
    - Content Injection (`<h1>six2dez</h1>` on stored param)
    - Script injection
    - File Inclusion
    - XPath injection
    - XXE in any request, change content-type to text/xml 
        - https://pentestbook.six2dez.com/enumeration/web/xxe
- Try to discover hidden parameters 
    - https://github.com/s0md3v/Arjun

#### Server Side Testing
- Command Injection
    - TO DO: Build Methodology
- RCE
    - via Referer Header
- Stored XSS 
    - https://pentestbook.six2dez.com/enumeration/web/xss 
    - Find places users can store data and try injecting payloads
- Path traversal, LFI and RFI 
    - Look for endpoints/params that take a path
    - Look for file uploads
    - https://pentestbook.six2dez.com/enumeration/web/lfi-rfi
- Server Side Prototype Pollution
    - ars0n custom Nuclei scans
    - TO DO: Build Methodology
- Insecure Deserialization
    - TO DO: Build Methodology
- SSRF 
    - https://pentestbook.six2dez.com/enumeration/web/ssrf
    - TIP: some companies auto drop collaborator payloads, look into your own infra if needed
    - Look for paths or URLs passed as values
    - Look for these params
        - dest
        - redirect
        - uri
        - path
        - continue
        - url
        - window
        - next
        - data
        - reference
        - site
        - html
        - val
        - validate
        - domain
        - callback
        - return
        - page
        - feed
        - host
        - port
        - to
        - out
        - view
        - dir
        - show
        - navigation
        - open
    - Also check 
        - webhooks
        - XML 
        - DOC uploads
        - headers
    - Spray and pray
        - https://iamaakashrathee.medium.com/ssrf-methodology-by-aakash-rathee-f175665e2ea 
    - Cloud metadata endpoints
        - https://gist.github.com/jhaddix/78cece26c91c6263653f31ba453e273b
    - SSRF Payloads and bypasses
        - https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Request%20Forgery/README.md
- Open Redirect
    - Look for paths or URLs passed as values
- SQL Injection 
    - https://pentestbook.six2dez.com/enumeration/web/sqli 
    - Look for these params
        - id
        - select
        - report
        - role
        - update
        - query
        - user
        - name
        - sort
        - where
        - search
        - params
        - process
        - row
        - view
        - table
        - from
        - sel
        - results
        - sleep
        - fetch
        - order
        - keyword
        - column
        - field
        - delete
        - string
        - number
        - filter 
    - Tools
        - Burp Scanner
        - SQLmap
        - Ghauri
            - https://github.com/r0oth3x49/ghauri
        - Fuzzing headers for Blind SQLi 
            - https://github.com/SAPT01/HBSQLI
    - SQLi cheat sheets
        - https://portswigger.net/web-security/sql-injection/cheat-sheet
        - https://pentestmonkey.net/category/cheat-sheet/sql-injection
        - https://www.invicti.com/blog/web-security/sql-injection-cheat-sheet/
- NoSQL Injection 
    - https://pentestbook.six2dez.com/enumeration/webservices/nosql-and-and-mongodb
    - To Do: Build Methodology
- File upload
    - Look for integrations w/ other services that include uploading files to 'smuggle' in payloads
    - Look for Content-Types
        - Multipart-forms
            - Shell, injections
        - Content type XML
            - XXE
            - XXE payloads
                - https://github.com/payloadbox/xxe-injection-payload-list
        - Content Type json
            - API vulns
    - In depth methodology
        - https://docs.google.com/presentation/d/1-YwXl9rhzSvvqVvE_bMZo2ab-0O5wRNTnzoihB9x6jI/edit#slide=id.gaf2d2dfef3_0_13
        - https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html
    - Upload bypasses
        - https://pentestbook.six2dez.com/enumeration/web/upload-bypasses
    - https://github.com/portswigger/upload-scanner
- APIs
    - Web Sec Academy GraphQL
    - Find methods and fuzz for different methods
    - Fuzz params and fuzz for hidden params
    - Look for access control violations
- Server-Side Template Injection
    - https://github.com/Hackmanit/TInjA
    - TO DO: Build Methodology

### Error Handling
- Access custom pages like /whatever_fake.php (.aspx,.html,.etc)
- Add multiple parameters in GET and POST request using different values
- Add "[]", "]]", and "[[" in cookie values and parameter values to create errors
- Generate error by giving input as "/~randomthing/%s" at the end of URL
- Use Burp Intruder "Fuzzing Full" List in input to generate error codes
- Try different HTTP Verbs like PATCH, DEBUG or wrong like FAKE

### Access Control / User Management
- https://pentestbook.six2dez.com/enumeration/web/idor
- Look for these params
    - id
    - user
    - account
    - number
    - order
    - no 
    - doc 
    - key
    - email
    - group 
    - profile
    - edit
    - REST numeric paths
- Autorize 
    - https://www.youtube.com/watch?v=2WzqH6N-Gbc 
    - https://www.youtube.com/watch?v=3K1-a7dnA60 
- Insecure access control methods (request parameters, Referer header, etc)
    - With privileged user perform privileged actions, try to repeat with unprivileged user cookie.
    - Try to access things of higher privilege
    - Try to access other users info/account
    - Try to find ways to access other parts of the app the user should not
    - `Access Controls are often applied to the client based on the individual user (accessing a profile page), the user's session (accessing authenticated pages), and the user's role (accessing an admin panel).`
- After register, logout, clean cache, go to home page and paste your profile url in browser, check for "login?next=accounts/profile" for open redirect or XSS with "/login?next=javascript:alert(1);//"
2FA/MFA Bypass
- Duplicate registration (try with uppercase, +1@..., dots in name, etc)
- Overwrite existing user (user takeover)
- Usename unqiueness bypass
- Insufficient email verification 
    - https://pentestbook.six2dez.com/enumeration/web/email-attacks
- Add only spaces password
- Corrupt authentication and session defects: Sign up, don't verify, request change password, change, check if account is active.
- Try to re-register repeating same request with same password and different password to
- If JSON request, add comma {“email”:“victim@mail.com”,”hacker@mail.com”,“token”:”xxxxxxxxxx”}
- Check OAuth with social media registration 
    - look at Oauth methodology
- Try to capture integration url leading integration takeover
- Check redirections in register page after login 

### Authentication
- Account recovery function
- Forgot Password function
    - Host Header Injection
        - https://portswigger.net/web-security/host-header/exploiting
        - https://medium.com/@salman_bugskipper/1-250-worth-of-host-header-injection-96563a2ac7e8
        - https://infosecwriteups.com/fun-with-header-and-forget-password-with-a-twist-af095b426fb2
- "Remember me" function
- Multi-stage mechanisms (Burp labs)
- Lack of password confirmation on change email, password or 2FA (try change response)
- Test response tampering in SAML authentication 
    - https://pentestbook.six2dez.com/enumeration/webservices/onelogin-saml-login
- MFA
    - Bypass MFA
        - build methodology
    - In OTP check guessable codes and race conditions
    - OTP, check response manipulation for bypass
- Oauth account takeover
    - Look at [Oauth methodology](./tech-specific-methodologies/Oauth-Methodology.md)
- SAML Misconfiguration
    - to do: build methodology
- Google Firebase IAM Misconfig
    - to do: build methodology
- Keycloack Misconfig
    - to do: build methodology

### Forgot/reset password
- Invalidate session on Logout and Password reset
- Uniqueness of forget password reset link/code
- Find user id or other sensitive fields in reset link and tamper them
- Request 2 reset passwords links and use the older
- Check if many requests have sequential tokens
- Use username@burp_collab.net and analyze the callback
- Host header injection for token leakage
    - To Do: Host Header Methodology
- Add X-Forwarded-Host: evil.com to receive the reset link with evil.com
- Email crafting like victim@gmail.com@target.com
- IDOR in reset link
- Capture reset token and use with other email/userID
- No TLD in email parameter
- User carbon copy email=victim@mail.com%0a%0dcc:hacker@mail.com
- Check encryption in reset password token
- Token leak in referer header
- Append second email param and value
- Understand how token is generated (timestamp, username, birthdate,...)
- Response manipulation

### Session
- If JWT, check common flaws 
    - https://pentestbook.six2dez.com/enumeration/webservices/jwt
- Session fixation (login, log out, resend requests generated before log out)
- CSRF 
    - https://pentestbook.six2dez.com/enumeration/web/csrf 
- Cookie scope
- Decode cookie
- Check httpOnly and Secure flags
- Effectiveness of controls using multiple accounts
- https://github.com/dub-flow/sessionprobe 
- Path traversal on cookies

### Reverse Proxy Testing
- HTTP header injection in GET & POST (X Forwarded Host) 
    - https://pentestbook.six2dez.com/enumeration/web/header-injections
    - To Do: Build Methodology
- Abusing Hop Headers
    - Check for X-Forwarded-Host, X-Forwarded-For, X-Forwarded-Proto, X-Forwarded-Port, X-Forwarded-Server, X-Forwarded-URI, X-Forwarded-Host, X-Forwarded-For, X-Forwarded-Proto, X-Forwarded-Port, X-Forwarded-Server, X-Forwarded-URI, X-Forwarded-Host, X-Forwarded-For, X-Forwarded-Proto, X-Forwarded-Port, X-Forwarded-Server, X-Forwarded-URI, X-Forwarded-Host, X-Forwarded-For, X-Forwarded-Proto, X-Forwarded-Port, X-Forwarded-Server, X-Forwarded-URI
    - https://book.hacktricks.xyz/pentesting-web/abusing-hop-by-hop-headers
- Web Cache Poisoning
    - To Do: Build Methodology
- HTTP Request Smuggling 
    - https://pentestbook.six2dez.com/enumeration/web/request-smuggling
    - To Do: Build Methodology