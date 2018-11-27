control 'V-21954' do
  title "The use of DES encryption suites must not be allowed for Kerberos
  encryption."
  desc "Certain encryption types are no longer considered secure.  By default,
  Windows 2012/R2 does not use the DES encryption suites.  If the configuration
  of allowed Kerberos encryption suites is needed, the DES encryption suites must
  not be included."
  impact 0.5
  tag "gtitle": 'Kerberos Encryption Types'
  tag "gid": 'V-21954'
  tag "rid": 'SV-53179r2_rule'
  tag "stig_id": 'WN12-SO-000064'
  tag "fix_id": 'F-66513r3_fix'
  tag "cci": ['CCI-000803']
  tag "cce": ['CCE-24147-1']
  tag "nist": ['IA-7', 'Rev_4']
  tag "documentable": false
  tag "check": "Verify whether the registry key below exists.  If it does not
  exist or the value is \"0\", this is not a finding.
  If the registry key exists and contains a value other than \"0\", continue
  below.

  The values are determined by the selection of encryption suites in the policy
  Computer Configuration >> Windows Settings >> Security Settings >> Local
  Policies >> Security Options >> \"Network Security: Configure encryption types
  allowed for Kerberos\".

  Registry Hive:  HKEY_LOCAL_MACHINE
  Registry Path:
  \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Kerberos\\Parameters\\
  Value Name:  SupportedEncryptionTypes
  Type:  REG_DWORD

  Due to the number of possible combinations that may include the DES encryption
  types, it is not possible to include all acceptable values as viewed directly
  in the registry.

  If the registry key does exist, the value must be converted to binary to
  determine configuration of specific bits.  This will determine whether this is
  a finding.

  Note the value for the registry key.
  For example, when all suites, including the DES suites are selected, the value
  will be \"0x7fffffff (2147483647)\".

  Open the Windows calculator (Run/Search for \"calc\").
  Select \"View\", then \"Programmer\".
  Select \"Dword\" and either \"Hex\" or \"Dec\".
  Enter the appropriate form of the value found for the registry key (e.g., Hex -
  enter 0x7fffffff, Dec - enter 2147483647)
  Select \"Bin\".
  The returned value may vary in length, up to 32 characters.
  If the either of 2 right most characters are \"1\", this is a finding.
  If the both of 2 right most characters are \"0\", this is not a finding."
  tag "fix": "The default system configuration does not use DES encryption for
  Kerberos and supports this requirement.  If Kerberos encryption types must be
  configured, ensure the following are not selected:

  DES_CBC_CRC
  DES_CBC_MD5

  If the policy for Computer Configuration >> Windows Settings >> Security
  Settings >> Local Policies >> Security Options >> \"Network security: Configure
  encryption types allowed for Kerberos\" is configured, only the following
  selections are allowed:

  RC4_HMAC_MD5
  AES128_HMAC_SHA1
  AES256_HMAC_SHA1
  Future encryption types"

  describe.one do
    describe registry_key('HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters') do
      its('SupportedEncryptionTypes') { should eq 2_147_483_644 }
    end
    describe registry_key('HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters') do
      its('SupportedEncryptionTypes') { should eq 0 }
    end
  end
  only_if do
    registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Server\ServerLevels').exists?
  end
end
