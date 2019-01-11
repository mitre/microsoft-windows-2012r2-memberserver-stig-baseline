control "V-3383" do
  title "The system must be configured to use FIPS-compliant algorithms for
  encryption, hashing, and signing."
  desc  "This setting ensures that the system uses algorithms that are
  FIPS-compliant for encryption, hashing, and signing.  FIPS-compliant algorithms
  meet specific standards established by the U.S. Government and must be the
  algorithms used for all OS encryption functions."
  impact 0.5
  tag "gtitle": "FIPS Compliant Algorithms "
  tag "gid": "V-3383"
  tag "rid": "SV-52896r2_rule"
  tag "stig_id": "WN12-SO-000074"
  tag "fix_id": "F-45822r2_fix"
  tag "cci": ['CCI-002450']
  tag "cce": ['CCE-23921-0']
  tag "nist": ['SC-13', 'Rev_4']
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
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\SYSTEM\\CurrentControlSet\\Control\\Lsa\\FIPSAlgorithmPolicy\\

  Value Name: Enabled

  Value Type: REG_DWORD
  Value: 1

  Warning: Clients with this setting enabled will not be able to communicate via
  digitally encrypted or signed protocols with servers that do not support these
  algorithms.  Both the browser and web server must be configured to use TLS, or
  the browser will not be able to connect to a secure site."
  tag "fix": "Configure the policy value for Computer Configuration >> Windows
  Settings >> Security Settings >> Local Policies >> Security Options >> \"System
  cryptography: Use FIPS compliant algorithms for encryption, hashing, and
  signing\" to \"Enabled\"."
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\FIPSAlgorithmPolicy') do
    it { should have_property 'Enabled' }
    its('Enabled') { should cmp == 1 }
  end
end

