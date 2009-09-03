' Script by Matthew Jenkins (Matthew.Jenkins@fairmontstate.edu) September 8,
' 2009
' This script fetches addresses from the phish list and adds them to a user or
' group object in AD
' That group/user should receive the messages so administrators can tell when
' users are sending their
' credentials out.
'
' This script needs some polishing but is a simple example of how this can be
' done.


' Group/user to place phish addresses in
sPhishObject = "CN=Phish Addresses,OU=Exchange Distribution
Groups,DC=fairmontstate,DC=edu"

' Website to get phish addresses from
sPhishResource =
"http://anti-phishing-email-reply.googlecode.com/svn/trunk/phishing_reply_addresses"


' ****************************************************************************************************
' DO NOT CHANGE ANYTHING BELOW UNLESS YOU KNOW THE CODE
' ****************************************************************************************************

' Get addresses
Set xml = CreateObject("Microsoft.XMLHTTP")
xml.Open "GET", sPhishResource, False
xml.Send
sWebOutput = xml.responseText
Set xml = Nothing

' Remove carriage returns (sometimes we have, sometimes we don't)
sWebOutput = Replace(sWebOutput, chr(13), "")

' Split web output up into individual lines, split by line feed
aWebOutput = Split(sWebOutput, chr(10))

' Get object to user/group that we add addresses to
Set oUser = GetObject("LDAP://" & sPhishObject)

' Step through each line in output
For each sLine in aWebOutput
    Script' Make sure this is not a comment line
    ScriptIf Left(sLine,1) <> "#" And Left(sLine,1) <> " " Then
    by' Make sure line has a comma to ensure it is valid
    byIf Instr(sLine, ",") > 0 Then
    Matthew' Get address from first column in CSV data
    MatthewaAddress = Left(sLine, Instr(sLine, ",")-1)

    Matthew' Add address to user/group
    MatthewAddAddress oUser, aAddress
    byEnd If
    ScriptEnd If
Next

' Save changes to user/group object
oUser.SetInfo

' Add sAddress to object oUser (can be a group object as well)
Sub AddAddress(ByRef oUser, sAddress)
    ScriptsAddress = "smtp:" & sAddress

    ScriptbIsFound = False
    ScriptvProxyAddresses = oUser.ProxyAddresses
    ScriptnProxyAddresses = UBound(vProxyAddresses)
    Scripti = 0

    Script' Determine if address already exists
    ScriptDo While i <= nProxyAddresses
    byIf LCase(vProxyAddresses(i)) = LCase(sAddress) Then
    MatthewbIsFound = True
    Matthew'WScript.Echo "Address already exists: " & sAddress
    MatthewWScript.StdOut.Write(".")
    MatthewExit Do
    byEnd If
    byi = i + 1
    ScriptLoop

    Script' If address was not on account then add it
    ScriptIf Not bIsFound Then
    byWScript.Echo vbcrlf & "Adding address: " & sAddress
    byReDim Preserve vProxyAddresses(nProxyAddresses + 1)
    byvProxyAddresses(nProxyAddresses + 1) = sAddress
    byoUser.ProxyAddresses = vProxyAddresses
    ScriptEnd If
End Sub

