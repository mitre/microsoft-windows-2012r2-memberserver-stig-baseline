control "V-3472" do
  title "The time service must synchronize with an appropriate DoD time source."
  desc  "The Windows Time Service controls time synchronization settings.  Time
  synchronization is essential for authentication and auditing purposes.  If the
  Windows Time Service is used, it must synchronize with a secure, authorized
  time source.   Domain-joined systems are automatically configured to
  synchronize with domain controllers.  If an NTP server is configured, it must
  synchronize with a secure, authorized time source."
  impact 0.3
  tag "gtitle": "Windows Time Service - Configure NTP Client"
  tag "gid": "V-3472"
  tag "rid": "SV-52919r3_rule"
  tag "stig_id": "WN12-CC-000069"
  tag "fix_id": "F-87335r1_fix"
  tag "cci": ['CCI-001891']
  tag "cce": ['CCE-23563-0']
  tag "nist": ['AU-8 (1) (a)', 'Rev_4']
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Open \"Windows PowerShell\" or an elevated \"Command Prompt\"
  (run as administrator).

  Enter \"W32tm /query /configuration\".

  Domain-joined systems are automatically configured with a \"Type\" of \"NT5DS\"
  to synchronize with domain controllers and would not be a finding.

  If systems are configured with a \"Type\" of \"NTP\", including standalone
  systems and the forest root domain controller with the PDC Emulator role, and
  do not have a DoD time server defined for \"NTPServer\", this is a finding.
  (See V-8557 in the Active Directory Forest STIG for the time source requirement
  of the forest root domain PDC emulator.)

  If an alternate time synchronization tool is used and is not enabled or not
  configured to synchronize with a DoD time source, this is a finding.

  The US Naval Observatory operates stratum 1 time servers, identified at
  http://tycho.usno.navy.mil/ntp.html. Time synchronization will occur through a
  hierarchy of time servers down to the local level. Clients and lower-level
  servers will synchronize with an authorized time server in the hierarchy."
  tag "fix": "If the system needs to be configured to an NTP server, configure
  the system to point to an authorized time server by setting the policy value
  for Computer Configuration >> Administrative Templates >> System >> Windows
  Time Service >> Time Providers >> \"Configure Windows NTP Client\" to
  \"Enabled\", and configure the \"NtpServer\" field to point to an authorized
  time server.

  The US Naval Observatory operates stratum 1 time servers, identified at
  http://tycho.usno.navy.mil/ntp.html. Time synchronization will occur through a
  hierarchy of time servers down to the local level. Clients and lower-level
  servers will synchronize with an authorized time server in the hierarchy."
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\W32time\Parameters') do
    its('Type') { should_not cmp == 'NTP' }
    its('Type') { should_not cmp == 'AllSync' }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\W32time\Parameters') do
    its('NTPServer') { should_not cmp == 'time.windows.com' }
  end
end

