control "V-8327" do
  title "Windows services that are critical for directory server operation must
be configured for automatic startup."
  desc  "Active Directory (AD) is dependent on several Windows services.  If
one or more of these services is not configured for automatic startup, AD
functions may be partially or completely unavailable until the services are
manually started.  This could result in a failure to replicate data or to
support client authentication and authorization requests."
  impact 0.5
  tag "severity": nil
  tag "gtitle": 'Prerequisite OS Services Startup'
  tag "gid": 'V-8327'
  tag "rid": 'SV-51184r2_rule'
  tag "stig_id": 'WN12-AD-000010-DC'
  tag "fix_id": 'F-44341r1_fix'
  tag "cci": ["CCI-000366"]
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": 'ECTM-1, ECTM-2'
  tag "check:" "Run \"services.msc\" to display the Services console.

Verify the Startup Type for the following Windows services:
- Active Directory Domain Services
- DFS Replication
- DNS Client
- DNS server
- Group Policy Client
- Intersite Messaging
- Kerberos Key Distribution Center
- NetLogon
- Windows Time (not required if another time synchronization tool is
implemented to start automatically)

If the Startup Type for any of these services is not Automatic, this is a
finding."
  tag "fix:" "Ensure the following services that are critical for directory
server operation are configured for automatic startup.

- Active Directory Domain Services
- DFS Replication
- DNS Client
- DNS server
- Group Policy Client
- Intersite Messaging
- Kerberos Key Distribution Center
- NetLogon
- Windows Time (not required if another time synchronization tool is
implemented to start automatically)"

domain_role = command('wmic computersystem get domainrole | Findstr /v DomainRole').stdout.strip
 if domain_role == '4' || domain_role == '5'
  list_of_services = [
  "NTDS",
  "DFSR",
  "DnsCache",
  "DNS",
  "gpsvc",
  "IsmServ",
  "Kdc",
  "NetLogon",
  "W32Time"
]
 list_of_services.each do |service|
  service = "\"#{service}\""
  status = json( command: "Get-WmiObject -Class Win32_Service | Where-Object {$_.Name -eq #{service}} | Select StartMode | ConvertTo-Json").params
    describe "#{service} is Set to Automatic" do
      subject { status }
      its(['StartMode']) { should cmp "Auto" }
    end
  end
 else
    describe 'Server is a Member Server or Standalone, Control V-8327 is NA' do
      skip 'Server is a Member Server or Standalone, Control V-8327 is NA'
    end
 end
end
