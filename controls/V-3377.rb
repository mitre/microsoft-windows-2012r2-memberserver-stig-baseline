# -*- encoding : utf-8 -*-
# frozen_string_literal: true

control 'V-3377' do
  title "The system must be configured to prevent anonymous users from having
  the same rights as the Everyone group."
  desc "Access by anonymous users must be restricted.  If this setting is
  enabled, then anonymous users have the same rights and permissions as the
  built-in Everyone group.  Anonymous users must not have these permissions or
  rights."
  impact 0.5
  tag "gtitle": 'Everyone Anonymous rights'
  tag "gid": 'V-3377'
  tag "rid": 'SV-52890r1_rule'
  tag "stig_id": 'WN12-SO-000054'
  tag "fix_id": 'F-45816r1_fix'
  tag "cci": ['CCI-000366']
  tag "cce": ['CCE-23807-1']
  tag "nist": ['CM-6 b', 'Rev_4']
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\System\\CurrentControlSet\\Control\\Lsa\\

  Value Name: EveryoneIncludesAnonymous

  Value Type: REG_DWORD
  Value: 0"
  tag "fix": "Configure the policy value for Computer Configuration -> Windows
  Settings -> Security Settings -> Local Policies -> Security Options ->
  \"Network access: Let everyone permissions apply to anonymous users\" to
  \"Disabled\"."

  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa') do
    it { should have_property 'EveryoneIncludesAnonymous' }
    its('EveryoneIncludesAnonymous') { should cmp == 0 }
  end
end
