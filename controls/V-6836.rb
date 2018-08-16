control "V-6836" do
  title "Passwords must, at a minimum, be 14 characters."
  desc  "Information systems not protected with strong password schemes
  (including passwords of minimum length) provide the opportunity for anyone to
  crack the password, thus gaining access to the system and compromising the
  device, information, or the local network."
  impact 0.5
  tag "gtitle": "Minimum Password Length"
  tag "gid": "V-6836"
  tag "rid": "SV-52938r2_rule"
  tag "stig_id": "WN12-AC-000007"
  tag "fix_id": "F-45864r1_fix"
  tag "cci": ["CCE-25317-9", "CCI-000205"]
  tag "nist": ["IA-5 (1) (a)", "Rev_4"]
  tag "documentable": false
  tag "check": "Verify the effective setting in Local Group Policy Editor.
  Run \"gpedit.msc\".

  Navigate to Local Computer Policy -> Computer Configuration -> Windows Settings
  -> Security Settings -> Account Policies -> Password Policy.

  If the value for the \"Minimum password length,\" is less than \"14\"
  characters, this is a finding."
  tag "fix": "Configure the policy value for Computer Configuration -> Windows
  Settings -> Security Settings -> Account Policies -> Password Policy ->
  \"Minimum password length\" to \"14\" characters."
  describe security_policy do
    its("MinimumPasswordLength") { should be >= 14 }
  end
end

