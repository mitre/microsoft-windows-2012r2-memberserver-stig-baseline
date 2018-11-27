control 'V-21960' do
  title "Domain users must be required to elevate when setting a networks
  location."
  desc "Selecting an incorrect network location may allow greater exposure of
  a system.  Elevation is required by default on nondomain systems to change
  network location.  This setting configures elevation to also be required on
  domain-joined systems."
  impact 0.3
  tag "gtitle": "Elevate when setting a network\xE2\x80\x99s location"
  tag "gid": 'V-21960'
  tag "rid": 'SV-53182r1_rule'
  tag "stig_id": 'WN12-CC-000005'
  tag "fix_id": 'F-46108r1_fix'
  tag "cci": ['CCI-001084']
  tag "cce": ['CCE-23388-2']
  tag "nist": ['SC-3', 'Rev_4']
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\Software\\Policies\\Microsoft\\Windows\\Network Connections\\

  Value Name: NC_StdDomainUserSetLocation

  Type: REG_DWORD
  Value: 1"
  tag "fix": "Configure the policy value for Computer Configuration ->
  Administrative Templates -> Network -> Network Connections -> \"Require domain
  users to elevate when setting a network's location\" to \"Enabled\"."
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Network Connections') do
    it { should have_property 'NC_StdDomainUserSetLocation' }
    its('NC_StdDomainUserSetLocation') { should cmp == 1 }
  end
end
