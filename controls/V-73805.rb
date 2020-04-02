control 'V-73805' do
  title "The Server Message Block (SMB) v1 protocol must be disabled on Windows
  2012 R2."
  desc "SMBv1 is a legacy protocol that uses the MD5 algorithm as part of SMB.
  MD5 is known to be vulnerable to a number of attacks such as collision and
  preimage attacks as well as not being FIPS compliant.

  Disabling SMBv1 support may prevent access to file or print sharing
  resources with systems or devices that only support SMBv1. File shares and
  print services hosted on Windows Server 2003 are an example, however Windows
  Server 2003 is no longer a supported operating system. Some older network
  attached devices may only support SMBv1.
  "
  impact 0.5
  tag "gtitle": 'WIN00-000160'
  tag "gid": 'V-73805'
  tag "rid": 'SV-88471r2_rule'
  tag "stig_id": 'WN12-00-000160'
  tag "fix_id": 'F-80261r1_fix'
  tag "cci": ['CCI-000381']
  tag "nist": ['CM-7 a', 'Rev_4']
  tag "documentable": false
  tag "check": "This requirement applies to Windows 2012 R2, it is NA for
  Windows 2012 (see V-73519 and V-73523 for 2012 requirements).

  Different methods are available to disable SMBv1 on Windows 2012 R2.  This is
  the preferred method, however if V-73519 and V-73523 are configured, this is NA.

  Run \"Windows PowerShell\" with elevated privileges (run as administrator).
  Enter the following:
  Get-WindowsOptionalFeature -Online | Where FeatureName -eq SMB1Protocol

  If \"State : Enabled\" is returned, this is a finding.

  Alternately:
  Search for \"Features\".
  Select \"Turn Windows features on or off\".

  If \"SMB 1.0/CIFS File Sharing Support\" is selected, this is a finding."
  tag "fix": "Run \"Windows PowerShell\" with elevated privileges (run as
  administrator).
  Enter the following:
  Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol

  Alternately:
  Search for \"Features\".
  Select \"Turn Windows features on or off\".
  De-select \"SMB 1.0/CIFS File Sharing Support\".

  The system must be restarted for the changes to take effect."
  if os['release'].to_f < 6.3
    impact 0.0
    describe 'System is not Windows 2012, control is NA' do
      skip 'System is not Windows 2012, control is NA'
    end
  else
   state = powershell("(Get-WindowsOptionalFeature -Online | Where {$_.FeatureName -eq 'SMB1Protocol'}).State ").stdout.strip
   describe 'SMB 1.0 Procotocl is disabled as part of Security Requirement' do
    subject { state }
    it { should_not eq "Enabled"}
   end
  end
end