control "V-14232" do
  title "IPSec Exemptions must be limited."
  desc  "IPSec exemption filters allow specific traffic that may be needed by
  the system for such things as Kerberos authentication.  This setting
  configures Windows for specific IPSec exemptions."
  impact 0.3
  tag "gtitle": "IPSec Exemptions"
  tag "gid": "V-14232"
  tag "rid": "SV-52945r1_rule"
  tag "stig_id": "WN12-SO-000042"
  tag "fix_id": "F-45871r2_fix"
  tag "cci": ["CCI-000366"]
  tag "cce": ["CCE-24253-7"]
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\System\\CurrentControlSet\\Services\\IPSEC\\

  Value Name: NoDefaultExempt

  Value Type: REG_DWORD
  Value: 3"
    tag "fix": "Configure the policy value for Computer Configuration -> Windows
  Settings -> Security Settings -> Local Policies -> Security Options -> \"MSS:
  (NoDefaultExempt) Configure IPSec exemptions for various types of network
  traffic\" to \"Only ISAKMP is exempt (recommended for Windows Server 2003)\".

  (See \"Updating the Windows Security Options File\" in the STIG Overview
  document if MSS settings are not visible in the system's policy tools.)"
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\IPSEC") do
    it { should have_property "NoDefaultExempt" }
    its("NoDefaultExempt") { should cmp == 3 }
  end
end

