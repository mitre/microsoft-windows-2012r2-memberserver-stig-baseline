# frozen_string_literal: true

control 'V-1173' do
  title 'The default permissions of global system objects must be increased.'
  desc  "Windows systems maintain a global list of shared system resources such
  as DOS device names, mutexes, and semaphores.  Each type of object is created
  with a default DACL that specifies who can access the objects with what
  permissions.  If this policy is enabled, the default DACL is stronger, allowing
  nonadministrative users to read shared objects, but not modify shared objects
  that they did not create."
  impact 0.3
  tag "gtitle": 'Global System Objects Permission Strength'
  tag "gid": 'V-1173'
  tag "rid": 'SV-52877r1_rule'
  tag "stig_id": 'WN12-SO-000076'
  tag "fix_id": 'F-45803r1_fix'
  tag "cci": ['CCI-000366']
  tag "cce": ['CCE-24633-0']
  tag "nist": ['CM-6 b', 'Rev_4']
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\System\\CurrentControlSet\\Control\\Session Manager\\

  Value Name: ProtectionMode

  Value Type: REG_DWORD
  Value: 1"
  tag "fix": "Configure the policy value for Computer Configuration -> Windows
  Settings -> Security Settings -> Local Policies -> Security Options -> \"System
  objects: Strengthen default permissions of internal system objects (e.g.
  Symbolic Links)\" to \"Enabled\"."

  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager') do
    it { should have_property 'ProtectionMode' }
    its('ProtectionMode') { should cmp == 1 }
  end
end
