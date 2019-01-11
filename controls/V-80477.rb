control "V-80477" do
  title "Windows PowerShell 2.0 must not be installed on Windows 2012/2012 R2."
  desc  "Windows PowerShell versions 4.0 (with a patch) and 5.x add advanced
  logging features that can provide additional detail when malware has been run
  on a system. Ensuring Windows PowerShell 2.0 is not installed as well mitigates
  against a downgrade attack that evades the advanced logging features of later
  Windows PowerShell versions."
  impact 0.5
  tag "gtitle": "WIN00-000220"
  tag "gid": "V-80477"
  tag "rid": "SV-95185r1_rule"
  tag "stig_id": "WN12-00-000220"
  tag "fix_id": "F-87287r3_fix"
  tag "cci": ["CCI-000381"]
  tag "nist": ['CM-7 a', 'Rev_4']
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
  tag "check": "Windows PowerShell 2.0 is not installed by default.

  Open \"Windows PowerShell\".

  Enter \"Get-WindowsFeature -Name PowerShell-v2\".

  If \"Installed State\" is \"Installed\", this is a finding.

  An Installed State of \"Available\" or \"Removed\" is not a finding."
  tag "fix": "Windows PowerShell 2.0 is not installed by default.

  Uninstall it if it has been installed.

  Open \"Windows PowerShell\".

  Enter \"Uninstall-WindowsFeature -Name PowerShell-v2\".

  Alternately:

  Use the \"Remove Roles and Features Wizard\" and deselect \"Windows PowerShell
  2.0 Engine\" under \"Windows PowerShell\"."
  describe windows_feature('PowerShell-v2') do
    it { should be_installed }
  end
end

