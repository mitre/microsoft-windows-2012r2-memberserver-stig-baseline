control "V-1098" do
  title "The reset period for the account lockout counter must be configured to
  15 minutes or greater on Windows 2012."
  desc  "The account lockout feature, when enabled, prevents brute-force
password attacks on the system.  This parameter specifies the period of time
that must pass after failed logon attempts before the counter is reset to
\"0\".  The smaller this value is, the less effective the account lockout
feature will be in protecting the local system."
  impact 0.5
  tag "gtitle": "Bad Logon Counter Reset"
  tag "gid": "V-1098"
  tag "rid": "SV-52849r2_rule"
  tag "stig_id": "WN12-AC-000003"
  tag "fix_id": "F-81025r1_fix"
  tag "cci": ['CCI-000044', 'CCI-002238']
  tag "cce": ['CCE-24840-1']
  tag "nist": ['AC-7 b', 'Rev_4']
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
  tag "check": "Verify the effective setting in Local Group Policy Editor.
  Run \"gpedit.msc\".

  Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings
  >> Security Settings >> Account Policies >> Account Lockout Policy.

  If the \"Reset account lockout counter after\" value is less than \"15\"
  minutes, this is a finding."
  tag "fix": "Configure the policy value for Computer Configuration >> Windows
  Settings >> Security Settings >> Account Policies >> Account Lockout Policy >>
  \"Reset account lockout counter after\" to at least \"15\" minutes."
  describe security_policy do
    its('ResetLockoutCount') { should be >= 15 }
  end
end

