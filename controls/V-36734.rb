control 'V-36734' do
  title "The operating system must employ automated mechanisms to determine the
  state of system components with regard to flaw remediation using the following
  frequency: continuously, where HBSS is used; 30 days, for any additional
  internal network scans not covered by HBSS; and annually, for external scans by
  Computer Network Defense Service Provider (CNDSP)."
  desc "Without the use of automated mechanisms to scan for security flaws on
  a continuous and/or periodic basis, the operating system or other system
  components may remain vulnerable to the exploits presented by undetected
  software flaws.  The operating system may have an integrated solution
  incorporating continuous scanning using HBSS and periodic scanning using other
  tools.."
  impact 0.5
  tag "gtitle": 'WINGE-000028'
  tag "gid": 'V-36734'
  tag "rid": 'SV-51582r2_rule'
  tag "stig_id": 'WN12-GE-000023'
  tag "fix_id": 'F-63425r1_fix'
  tag "cci": ['CCI-001233']
  tag "nist": ['SI-2 (2)', 'Rev_4']
  tag "documentable": false
  tag "check": "Verify the operating system employs automated mechanisms to
  determine the state of system components with regard to flaw remediation using
  the following frequency: continuously, where HBSS is used; 30 days, for any
  additional internal network scans not covered by HBSS; and annually, for
  external scans by Computer Network Defense Service Provider (CNDSP).  If it
  does not, this is a finding."
  tag "fix": "Configure the operating system to employ automated mechanisms to
  determine the state of system components with regard to flaw remediation using
  the following frequency: continuously, where HBSS is used; 30 days, for any
  additional internal network scans not covered by HBSS; and annually, for
  external scans by Computer Network Defense Service Provider (CNDSP)."
  describe "The operating system must employ automated mechanisms to determine the
  state of system components with regard to flaw remediation using the following
  frequency: continuously, where HBSS is used; 30 days, for any additional
  internal network scans not covered by HBSS; and annually, for external scans by
  Computer Network Defense Service Provider (CNDSP)." do
    skip 'is a manual check'
  end
end
