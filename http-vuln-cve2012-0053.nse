local http = require "http"
local nmap = require "nmap"
local string = require "string"
local shortport = require "shortport"
local vulns = require "vulns"

description = [[
Attempts to exploit CVE-2012-0053 on Apache web servers by
sending a Cookie header with a very very large cookie. The best
description of the vulnerability i've found in public space is at
http://security.stackexchange.com/questions/93670/httponly-cookies
]]

---
-- @usage
-- nmap --script http-vuln-cve2012-0053 -p <port> <host>
--
author = "Kravlin"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"safe", "vuln"}

portrule = shortport.http



local function checkVuln(host, port)
	local result
	cookieFilling = string.rep("j54ac0u0nV3ChmWOIOhl1LiTGWfzQA", 2000)
	local options = {cookies = "test="..cookieFilling }
	local path = "/"
	
	result = http.get(host, port, path, options)
	return http.response_contains(result, "Cookie: test=j54ac0u0nV3ChmWOIOhl1LiTGWfzQA", false)
end

action = function(host, port)

	local vuln = {
		title = "Apache httpOnly Cookie Disclosure",
		state = vulns.STATE.NOT_VULN,
		IDS   = { CVE = 'CVE-2012-0053' },
		description = [[
Apache before version 2.2.22 is vulnerable to information 
disclosure when sent an HTTP header long enough to exceed 
the server limit. This causes the web server to respond with 
an HTTP 400. By default, this includes the HTTP header, which
can include information such as httpOnly cookies.]],
		references = {
			"http://security.stackexchange.com/questions/93670/httponly-cookies",
			"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-0053",
			"http://www.securityfocus.com/bid/51706"
		}
	}
	
	local report = vulns.Report:new(SCRIPT_NAME, host, port)

	if checkVuln(host, port) then
		vuln.state = vulns.STATE.VULN
	else
		vuln.state = vulns.STATE.NOT_VULN
	end

	return report:make_output(vuln)
end
