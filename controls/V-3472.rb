# frozen_string_literal: true

control 'V-3472' do
  title "If the time service is configured, it must use an authorized time
  server."
  desc "The Windows Time Service controls time synchronization settings.  Time
  synchronization is essential for authentication and auditing purposes.  If the
  Windows Time Service is used, it must synchronize with a secure, authorized
  time source.   Domain-joined systems are automatically configured to
  synchronize with domain controllers.  If an NTP server is configured, it must
  synchronize with a secure, authorized time source."
  impact 0.3
  tag "gtitle": 'Windows Time Service - Configure NTP Client'
  tag "gid": 'V-3472'
  tag "rid": 'SV-52919r2_rule'
  tag "stig_id": 'WN12-CC-000069'
  tag "fix_id": 'F-45845r1_fix'
  tag "cci": ['CCI-001891']
  tag "cce": ['CCE-23563-0']
  tag "nist": ['AU-8 (1) (a)', 'Rev_4']
  tag "documentable": false
  tag "check": "Review the following registry values:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\Software\\Policies\\Microsoft\\W32time\\Parameters\\

  Value Name: Type
  Type: REG_SZ
  Value: Possible values are NoSync, NTP, NT5DS, AllSync

  and

  Value Name: NTPServer
  Type: REG_SZ
  Value: \"address of the time server\"

  If the following, this is a finding:
  \"Type\" has a value of \"NTP\" or \"Allsync\" AND the \"NTPServer\" value is
  set to \"time.windows.com\" or other unauthorized server.

  If the following, this not a finding:
  The referenced registry values do not exist.
  \"Type\" has a value of \"NoSync\" or \"NT5DS\".
  \"Type\" has a value of \"NTP\" or \"Allsync\" AND the \"NTPServer\" is blank
  or configured to an authorized time server.

  For DoD organizations, the US Naval Observatory operates stratum 1 time
  servers, identified at http://tycho.usno.navy.mil/ntp.html. Time
  synchronization will occur through a hierarchy of time servers down to the
  local level. Clients and lower-level servers will synchronize with an
  authorized time server in the hierarchy.

  Domain-joined systems are automatically configured to synchronize with domain
  controllers, and it would not be a finding unless this is changed."
  tag "fix": "If the system needs to be configured to an NTP server, configure
  the system to point to an authorized time server by setting the policy value
  for Computer Configuration -> Administrative Templates -> System -> Windows
  Time Service -> Time Providers -> \"Configure Windows NTP Client\" to
  \"Enabled\", and configure the \"NtpServer\" field to point to an authorized
  time server."

  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\W32time\Parameters') do
    its('Type') { should_not cmp == 'NTP' }
    its('Type') { should_not cmp == 'AllSync' }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\W32time\Parameters') do
    its('NTPServer') { should_not cmp == 'time.windows.com' }
  end
end
