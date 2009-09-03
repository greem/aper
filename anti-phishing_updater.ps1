####################################
#  Exchange 2007 Powershell script to import/filter known Phishers
#  Version 1.2
#
# About:
#	The best way I could think of to put the list of known phishers to use was to import the email addresses
#	into Active Directory as mail contacts and add them to a dynamic distribution list that is then added
#	to Transport Rules to filter the messages as desired.  My rules append to the subject line for identification then
#	redirect the messages to the postmaster	mailbox to track effectiveness and where user education may be needed.
#
# Disclaimer:
#	This script is provided as is with no warranty either express or implied.  The author of this script is
#	not responsible	for any loss of business, downtime or data loss.  Anyone choosing to use this Powershell
#	script should have a basic understanding of Exchange 2007, Powershell and Windows Administration.
#
# Pre-Config:
#	1. Create an OU to hold the mail contacts (the script is assuming "EDU Phishing" and can be a sub OU wherever desired)
#	2. Create a Dynamic Distribution Group (recommend "eduphishing") and filter on Custom Attribute 1 for "EDU Phishing"
#	3. On the Hub Server, create two Transport Rules as follows (modify as desired):
#		a. EDU Phishing Filter - Send
#		   Rule Comments: Transport rule to detect messages sent to known phishing addresses.
#		    Apply rule to messages
#			from users Inside the organization
#			    and sent to a member of EDU Phishing
#		    prepend the subject with User reply to phishing:
#			and redirect the message to Postmaster
#
#		b. EDU Phishing Filter - Receive
#		   Rule Comments: Transport rule to detect messages from known phishing addresses.
#		    Apply rule to messages
#			from a member of EDU Phishing
#			   and sent to users Inside the organization
#		    prepend the subject with Message from known phisher: 
#			   and redirect the message to Postmaster
#	4. Create a folder on the server called "C:\Admin"
#	5. Save this Powershell script as "C:\Admin\Anti-Phish.ps1"
#	6. Create a scheduled task to run the script at a desired interval (e.g. 4 hours)
#
# Known Issues:
#	HUB Transport servers cache the membership of all distribution lists for four hours.  Any updates done during
#	this interval will not take effect unless the Exchange Transport service is manually restarted or the update
#	interval has passed.  It is possible to change the Microsoft default on the cache update (not recommended).
#
# Revision History:
#	03-18-2009: added code to remove cleared addresses
#	05-04-2009: changed starting line for phishing_reply_addresses due to new type E
#
####################################
$error.clear()
$erroractionpreference = "SilentlyContinue"
Add-PSSnapin *exchange*
$clnt = New-Object System.Net.WebClient
$replyurl = "http://anti-phishing-email-reply.googlecode.com/svn/trunk/phishing_reply_addresses"
$replyfile = "c:\admin\phishing_reply_addresses"
$clearedurl = "http://anti-phishing-email-reply.googlecode.com/svn/trunk/phishing_cleared_addresses"
$clearedfile = "c:\admin\phishing_cleared_addresses"
$clnt.DownloadFile($replyurl,$replyfile)
$clnt.DownloadFile($clearedurl,$clearedfile)
Start-Sleep -seconds 10
$tempreplyfile = Get-Content $replyfile
$tempclearedfile = Get-Content $clearedfile
Clear-Content $replyfile
Clear-Content $clearedfile
Add-Content -Path $replyfile -Value 'Address,Type,Date'
Add-Content -Path $clearedfile -Value 'Address,Date'
Add-Content -Path $replyfile -value $tempreplyfile[47..$tempreplyfile.length]
Add-Content -Path $clearedfile -value $tempclearedfile[18..$tempclearedfile.length]
$replydata = Import-Csv $replyfile
$cleareddata = Import-Csv $clearedfile
$ou = "EDU Phishing"
foreach ($i in $replydata)
	{
		new-mailcontact -name $i.address -externalemailaddress $i.address -organizationalunit $ou
		set-mailcontact -identity $i.address -customattribute1 $ou -customattribute2 $i.type -customattribute3 $i.date -HiddenFromAddressListsEnabled:$true
	}
foreach ($i in $cleareddata)
	{
		remove-mailcontact -identity $i.address -confirm:$false
	}