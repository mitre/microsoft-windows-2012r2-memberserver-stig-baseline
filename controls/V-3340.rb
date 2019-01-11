control "V-3340" do
  title "Network shares that can be accessed anonymously must not be allowed."
  desc  "Anonymous access to network shares provides the potential for gaining
  unauthorized system access by network users.  This could lead to the exposure
  or corruption of sensitive data."
  impact 0.7
  tag "gtitle": "Anonymous Access to Network Shares"
  tag "gid": "V-3340"
  tag "rid": "SV-52884r1_rule"
  tag "stig_id": "WN12-SO-000059"
  tag "fix_id": "F-45810r1_fix"
  tag "cci": ['CCI-001090']
  tag "cce": ['CCE-25592-7']
  tag "nist": ['SC-4', 'Rev_4']
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
  tag "check": "If the following registry value does not exist, this is not a
  finding:

  If the following registry value does exist and is not configured as specified,
  this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\System\\CurrentControlSet\\Services\\LanManServer\\Parameters\\

  Value Name: NullSessionShares

  Value Type: REG_MULTI_SZ
  Value: (Blank)"
  tag "fix": "Ensure the policy value for Computer Configuration -> Windows
  Settings -> Security Settings -> Local Policies -> Security Options ->
  \"Network access: Shares that can be accessed anonymously\" contains no entries
  (blank)."
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters') do
    it { should have_property 'NullSessionShares' }
    its('NullSessionShares') { should eq [''] }
  end
end

