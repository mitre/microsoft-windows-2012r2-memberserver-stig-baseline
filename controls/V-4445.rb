# frozen_string_literal: true

control 'V-4445' do
  title 'Optional Subsystems must not be permitted to operate on the system.'
  desc  "The POSIX subsystem is an Institute of Electrical and Electronic
  Engineers (IEEE) standard that defines a set of operating system services.  The
  POSIX Subsystem is required if the server supports applications that use that
  subsystem.  The subsystem introduces a security risk relating to processes that
  can potentially persist across logins.  That is, if a user starts a process and
  then logs out, there is a potential that the next user who logs in to the
  system could access the previous users process.  This is dangerous because the
  process started by the first user may retain that users system privileges, and
  anything the second user does with that process will be performed with the
  privileges of the first user."
  impact 0.3
  tag "gtitle": 'Optional Subsystems'
  tag "gid": 'V-4445'
  tag "rid": 'SV-52219r2_rule'
  tag "stig_id": 'WN12-SO-000088'
  tag "fix_id": 'F-45238r1_fix'
  tag "cci": ['CCI-000381']
  tag "cce": ['CCE-24878-1']
  tag "nist": ['CM-7 a', 'Rev_4']
  tag "documentable": false
  tag "third_party_tools": 'HK'
  tag "ia_controls": 'ECSC-1'
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\System\\CurrentControlSet\\Control\\Session
  Manager\\Subsystems\\

  Value Name: Optional

  Value Type: REG_MULTI_SZ
  Value: (Blank)"
  tag "fix": "Configure the policy value for Computer Configuration -> Windows
  Settings -> Security Settings -> Local Policies -> Security Options -> \"System
  settings: Optional subsystems\" to \"Blank\" (Configured with no entries)."

  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\SubSystems') do
    it { should have_property 'Optional' }
    its('Optional') { should eq [] }
  end
end
