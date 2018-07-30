control "V-15505" do
  title "The HBSS McAfee Agent must be installed."
  desc  "The McAfee Agent is the client side distributed component of McAfee
  ePolicy Orchestrator (McAfee ePO) which provides a secure communication channel
  between the ePO server and managed point products."
  impact 0.5
  tag "gtitle": "HBSS McAfee Agent"
  tag "gid": "V-15505"
  tag "rid": "SV-53010r3_rule"
  tag "stig_id": "WN12-GE-000019"
  tag "fix_id": "F-45937r1_fix"
  tag "cci": ["CCI-000366"]
  tag "nist": ["CCI-000366"]
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "documentable": false
  tag "check": "Run \"Services.msc\".

  Verify the McAfee Agent service is running, depending on the version installed.

  Version - Service Name
  McAfee Agent v5.x - McAfee Agent Service
  McAfee Agent v4.x - McAfee Framework Service

  If the service is not listed or does not have a Status of \"Started\", this is
  a finding."
  tag "fix": "Deploy the McAfee Agent as detailed in accordance with the DoD
  HBSS STIG."
  describe.one do
    describe command("Get-Service -DisplayName 'McAfee Agent Service' | Findstr /v 'status --'") do
     its('stdout') { should match /Running[\s\w\W]*/}
    end
    describe command("Get-Service -DisplayName 'McAfee Framework Service' | Findstr /v 'status --'") do
     its('stdout') { should match /Running[\s\w\W]*/}
    end
  end
end

 