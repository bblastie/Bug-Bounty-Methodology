# Step 1 - TLDs
Identify TLDs 
- HackerOne/Bugcrowd/Custom Scope
- Crunchbase
- Google
    - site:targetdomain.com -site:www.targetdomain.com 
    - TO DO: find more dorks
- Manual search of crt.sh 
- Shodan
    - org: "company name"
    - net: "CIDR"
    - port: 80,443

### TLDs to target
- 
- 
- 

# Step 2 - Automated Recon
- Run ars0n for automated enumeration to cover most beginning steps
    - https://github.com/R-s0n/ars0n-framework 

# Step 3 - Subdomains 
1. Review subdomains in ars0n
2. Review CVE and Nuclei results 
3. Review Screenshots of subdomains for interesting responses
4. Perform DNS recon on interesting subs
    - `dnsrecon -t axfr -d domain`

### Interesting Subdomains to target
- 
- 
- 

# Step 4 - Check Nuclei + CVE results for low hanging fruit and pointers

### Interesting Nuclei + CVE results
- 
- 
- 

# Step 5 - Employee Enumeration
## Github
- Find Users with public repos that may be relevant
    - `python3 github-users.py -k floqast`
- Run github_brute-dork.py 
    - `python3 github_brutedork.py -u blackblastie -t <gh-pat> -o <organization>`
- Run Trufflehog against interesting users and/or repos
    - `curl -L -H "Accept: application/vnd.github+json" -H "Authorization: Bearer <gh-pat>" -H "X-GitHub-Api-Version: 2022-11-28" https://api.github.com/users/<USERNAME>/repos?per_page=100 | jq .[].git_url -r | sed 's/git:/https:/' | sudo xargs -I % trufflehog github --repo=%`
    

# Step 6 - Cloud
- Run fire-cloud.py
- Gather IPs from Wildfire.py scan and run through ip2provider.py
    - ip-parser.py
    - Run Masscan 
    - TO DO: Add details from Jhaddix course 
    - TO DO: Figure out how to make use of Cloud Recon 
- Manually run cloud-enum
    - https://github.com/initstring/cloud_enum 
- AADInternals as Outsider
    - Run on Windows/Powershell
    - `import-module AADInternals`
    - `Invoke-AADIntReconAsOutsider -Domain "floqast.com" | format-table`
- Review findings and interesting endpoints

### Interesting Cloud Findings
- 
- 
- 

# Step 7 - Manual Testing
### Take all interesting endpoints and manually test them
### Application Analysis

- What stack/languages are used?
- What server is running the application?
- Is there a WAF?
-  What additional libraries are used? Are there known exploits for these libraries?  Custom JS Llbraries?
- Is there Authentication? 
    - OAuth through Google/Facebook
- What Objects are used?
- How is session established?
- Are there useful comments?
- How does it handle special characters?
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


#### Analysis notes
- 
- 
- 

#### Tech Profile  
- Web Server: 
- Database: Mongo?  
- Cloud Provider: Azure and AWS
- WAF:
- CMS:
- Framework: React
- Programming Language: JS
- Other: Lodash (proto pollution)

### Manual Recon
- Identify web server, technology, and database
- Try to locate /robots.txt , /crossdomain.xml /clientaccesspolicy.xml /sitemap.xml and /.well-known/
- Review comments on source code (Burp Engagement Tools)
- Content Discovery
    - Step 1 - Click through the app 
    - Step 2 - Burp Crawl
    - Step 3 - `Discover Content` in Burp (Right click on target in Target tab)
    - Step 4 - Intruder fuzzing with small raft payload list
- Web Fuzzing 
    - Burp Param Miner
    - https://github.com/six2dez/OneListForAll
    - To Do: Learn more about how and where to fuzz
- Identify WAF 
    - https://github.com/Ekultek/WhatWaf
- Use GF to look for vulnerable URLs 
    - https://github.com/1ndianl33t/Gf-Patterns
- Scan for XSS 
    - https://github.com/hahwul/dalfox
- Try locate admin panel
- Analyze JS files via burp 
    - https://github.com/xnl-h4ck3r/xnLinkFinder
- Content Discovery via walking the app

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

#### Interesting Reverse Proxy Testing finds
- 
- 
- 

### Client Side Testing
- Fuzz all request parameters
- Identify all reflected data
- Reflected XSS 
    - https://pentestbook.six2dez.com/enumeration/web/xss
    - To Do: Build Methodology
- Client Side Prototype Pollution
    - TO DO: Build Methodology
    - ars0n custom Nuclei scans
- Client Side Template Injection
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

#### Interesting Client Side Testing finds
- 
- 
- 

#### Server Side Testing
- Command Injection
    - TO DO: Build Methodology
- Stored XSS 
    - https://pentestbook.six2dez.com/enumeration/web/xss 
- Other Stored attacks
- Path traversal, LFI and RFI 
    - https://pentestbook.six2dez.com/enumeration/web/lfi-rfi
- Server Side Prototype Pollution
    - ars0n custom Nuclei scans
    - TO DO: Build Methodology
- Insecure Deserialization
    - TO DO: Build Methodology
- SSRF in previously discovered open ports 
    - https://pentestbook.six2dez.com/enumeration/web/ssrf
    - TO DO: Build Methodology
- RCE via Referer Header
- SQL Injection 
    - https://pentestbook.six2dez.com/enumeration/web/sqli 
    - SQL injection via User-Agent Header
    - Fuzz other params
    - To Do: Build Methodology
- NoSQL Injection 
    - https://pentestbook.six2dez.com/enumeration/webservices/nosql-and-and-mongodb
    - To Do: Build Methodology
- GraphQL Injection
    - To Do: Build Methodology
- File upload: eicar, No Size Limit, File extension, Filter Bypass, burp extension, RCE
    - TODO: Build methodology
    - https://pentestbook.six2dez.com/enumeration/web/upload-bypasses
    - https://secure.eicar.org/eicar.com.txt 
    - https://github.com/portswigger/upload-scanner
    - Web shell via file upload
- Server-Side Template Injection
    - TO DO: Build Methodology

#### Interesting Server Side Testing finds
- 
- 
- 

### Error Handling
- Access custom pages like /whatever_fake.php (.aspx,.html,.etc)
- Add multiple parameters in GET and POST request using different values
- Add "[]", "]]", and "[[" in cookie values and parameter values to create errors
- Generate error by giving input as "/~randomthing/%s" at the end of URL
- Use Burp Intruder "Fuzzing Full" List in input to generate error codes
- Try different HTTP Verbs like PATCH, DEBUG or wrong like FAKE

#### Interesting Error Handling finds
- 
- 
- 

### Authentication
- Account recovery function
- "Remember me" function
- Multi-stage mechanisms (Burp labs)
- SQL injection 
    - https://pentestbook.six2dez.com/enumeration/web/sqli
- Lack of password confirmation on change email, password or 2FA (try change response)
- Test response tampering in SAML authentication 
    - https://pentestbook.six2dez.com/enumeration/webservices/onelogin-saml-login
- In OTP check guessable codes and race conditions
- OTP, check response manipulation for bypass
- If JWT, check common flaws 
    - https://pentestbook.six2dez.com/enumeration/webservices/jwt
- After register, logout, clean cache, go to home page and paste your profile url in browser, check for "login?next=accounts/profile" for open redirect or XSS with "/login?next=javascript:alert(1);//"
2FA/MFA Bypass
    - To Do: Build Methodology
- Oauth account takeover
    - Look at [Oauth methodology](./tech-specific-methodologies/Oauth-Methodology.md)
- SAML Misconfiguration
    - to do: build methodology
- Google Firebase IAM Misconfig
    - to do: build methodology
- Keycloack Misconfig
    - to do: build methodology

#### Interesting Authentication finds
- 
- 
- 

### Session
- Session fixation (login, log out, resend requests generated before log out)
- CSRF 
    - https://pentestbook.six2dez.com/enumeration/web/csrf 
- Cookie scope
- Decode cookie
- Check httpOnly and Secure flags
- Effectiveness of controls using multiple accounts
- Insecure access control methods (request parameters, Referer header, etc)
    - TO DO: build methodology via burp labs
- Path traversal on cookies
- With privileged user perform privileged actions, try to repeat with unprivileged user cookie.

#### Interesting Session finds
- 
- 
- 

### User Management
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

#### Interesting User Management finds
- 
- 
- 

### Profile/Account Details
- Find parameter with user id and try to tamper in order to get the details of other users
- Create a list of features that are pertaining to a user account only and try CSRF
- Change email id and update with any existing email id. Check if its getting validated on server or not.
- Check any new email confirmation link and what if user doesn't confirm.
- CSV import/export: Command Injection, XSS, macro injection
- Check profile picture URL and find email id/user info or EXIF Geolocation Data
    - https://github.com/exiftool/exiftool
- Imagetragick in picture profile upload
- Metadata of all downloadable files (Geolocation, usernames)
- Account deletion option and try to reactivate with "Forgot password" feature
- Try bruteforce enumeration when change any user unique parameter.
- Try parameter pollution to add two values of same field
- Check different roles policy

#### Interesting Account/Profile finds
-
- 
-  

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

#### Interesting Forgot Password finds
- 
- 
- 


### Application Logic Testing
- IDOR 
    - https://pentestbook.six2dez.com/enumeration/web/idor
- Access Controls
    - Try to access things of higher privilege
    - Try to access other users info/account
    - Try to find ways to access other parts of the app the user should not
    - `Access Controls are often applied to the client based on the individual user (accessing a profile page), the user's session (accessing authenticated pages), and the user's role (accessing an admin panel).`

#### Interesting Application Logic finds
- 
- 
- 