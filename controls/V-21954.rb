control "V-21954" do
  title "Kerberos encryption types must be configured to prevent the use of DES
  and RC4 encryption suites."
  desc  "Certain encryption types are no longer considered secure. The DES and
  RC4 encryption suites must not be used for Kerberos encryption.

      Note: Removing the previously allowed RC4_HMAC_MD5 encryption suite may
  have operational impacts and must be thoroughly tested for the environment
  before changing. This includes but is not limited to parent\\child trusts where
  RC4 is still enabled; selecting \"The other domain supports Kerberos AES
  Encryption\" may be required on the domain trusts to allow client communication
  across the trust relationship.
    "
  impact 0.5
  tag "gtitle": "Kerberos Encryption Types"
  tag "gid": "V-21954"
  tag "rid": "SV-53179r4_rule"
  tag "stig_id": "WN12-SO-000064"
  tag "fix_id": "F-97093r3_fix"
  tag "cci": ['CCI-000803']
  tag "cce": ['CCE-24147-1']
  tag "nist": ['IA-7', 'Rev_4']
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
  configured as specified, this is a finding.

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path:
  \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Kerberos\\Parameters\\

  Value Name: SupportedEncryptionTypes

  Value Type: REG_DWORD
  Value: 0x7ffffff8 (2147483640)

  Note: Removing the previously allowed RC4_HMAC_MD5 encryption suite may have
  operational impacts and must be thoroughly tested for the environment before
  changing. This includes but is not limited to parent\\child trusts where RC4 is
  still enabled; selecting \"The other domain supports Kerberos AES Encryption\"
  may be required on the domain trusts to allow client communication across the
  trust relationship."
  tag "fix": "Configure the policy value for Computer Configuration >> Windows
  Settings >> Security Settings >> Local Policies >> Security Options >>
  \"Network security: Configure encryption types allowed for Kerberos\" to
  \"Enabled\" with only the following selected:

  AES128_HMAC_SHA1
  AES256_HMAC_SHA1
  Future encryption types

  Note: Removing the previously allowed RC4_HMAC_MD5 encryption suite may have
  operational impacts and must be thoroughly tested for the environment before
  changing. This includes but is not limited to parent\\child trusts where RC4 is
  still enabled; selecting \"The other domain supports Kerberos AES Encryption\"
  may be required on the domain trusts to allow client communication across the
  trust relationship."
  describe registry_key('HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters') do
    its('SupportedEncryptionTypes') { should eq 2_147_483_640 }
  end
end

