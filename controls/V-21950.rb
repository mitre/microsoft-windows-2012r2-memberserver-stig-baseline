control 'V-21950' do
  title "The service principal name (SPN) target name validation level must be
  turned off."
  desc "If a service principle name (SPN) is provided by the client, it is
  validated against the server's list of SPNs.  Implementation may disrupt file
  and print sharing capabilities."
  impact 0.5
  tag "gtitle": 'SPN Target Name Validation Level'
  tag "gid": 'V-21950'
  tag "rid": 'SV-53175r1_rule'
  tag "stig_id": 'WN12-SO-000035'
  tag "fix_id": 'F-46101r1_fix'
  tag "cci": ['CCI-000366']
  tag "cce": ['CCE-24502-7']
  tag "nist": ['CM-6 b', 'Rev_4']
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\System\\CurrentControlSet\\Services\\LanmanServer\\Parameters\\

  Value Name: SmbServerNameHardeningLevel

  Type: REG_DWORD
  Value: 0"
  tag "fix": "Configure the policy value for Computer Configuration -> Windows
  Settings -> Security Settings -> Local Policies -> Security Options ->
  \"Microsoft network server: Server SPN target name validation level\" to
  \"Off\"."
  
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters') do
    it { should have_property 'SMBServerNameHardeningLevel' }
    its('SMBServerNameHardeningLevel') { should cmp == 0 }
  end
end
