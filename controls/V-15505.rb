# -*- encoding : utf-8 -*-
# frozen_string_literal: true

control 'V-15505' do
  title 'The HBSS McAfee Agent must be installed.'
  desc  "The McAfee Agent is the client side distributed component of McAfee
  ePolicy Orchestrator (McAfee ePO) which provides a secure communication channel
  between the ePO server and managed point products."
  impact 0.5
  tag "gtitle": 'HBSS McAfee Agent'
  tag "gid": 'V-15505'
  tag "rid": 'SV-53010r3_rule'
  tag "stig_id": 'WN12-GE-000019'
  tag "fix_id": 'F-45937r1_fix'
  tag "cci": ['CCI-000366']
  tag "nist": ['CM-6 b', 'Rev_4']
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

  mc_agent_startmode = powershell('Get-WmiObject -Class Win32_Service | Where-Object {$_.Name -eq "masvc"} | Select State | ConvertTo-Json').stdout.strip
  mc_agent_clean_startmode = mc_agent_startmode[18..24]
  mc_framework_startmode = powershell('Get-WmiObject -Class Win32_Service | Where-Object {$_.Name -eq "macompatsvc"} | Select State | ConvertTo-Json').stdout.strip
  mc_framework_clean_startmode = mc_framework_startmode[18..24]

  describe 'Verify the Mcafee Agent Service is Running' do
    subject { mc_agent_clean_startmode }
    it { should cmp 'Running' }
  end
  describe 'Verify the Mcafee Framework Service is Running' do
    subject { mc_framework_clean_startmode }
    it { should cmp 'Running' }
  end
end
