control "V-36666" do
  title "Policy must require that system administrators (SAs) be trained for
  the operating systems used by systems under their control."
  desc  "If SAs are assigned to systems running operating systems for which
  they have no training, these systems are at additional risk of unintentional
  misconfiguration that may result in vulnerabilities or decreased availability
  of the system."
  impact 0.5
  tag "gtitle": "WIN00-000014"
  tag "gid": "V-36666"
  tag "rid": "SV-51577r1_rule"
  tag "stig_id": "WN12-00-000006"
  tag "fix_id": "F-44706r1_fix"
  tag "cci": ["CCI-000366"]
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "documentable": false
  tag "ia_controls": "ECLP-1"
  tag "check": "Determine whether the site has a policy that requires SAs be
  trained for all operating systems running on systems under their control.  If
  the site does not have a policy requiring SAs be trained for all operating
  systems under their control, this is a finding."
  tag "fix": "Establish site policy that requires SAs be trained for all
  operating systems running on systems under their control."
  describe "Policy must require that system administrators (SAs) be trained for
  the operating systems used by systems under their control" do
    skip "is a manual check"
  end
end

