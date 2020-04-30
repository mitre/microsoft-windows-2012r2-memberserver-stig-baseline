# frozen_string_literal: true

control 'V-75915' do
  title "Orphaned security identifiers (SIDs) must be removed from user rights
  on Windows 2012 / 2012 R2."
  desc "Accounts or groups given rights on a system may show up as unresolved
  SIDs for various reasons including deletion of the accounts or groups.  If the
  account or group objects are reanimated, there is a potential they may still
  have rights no longer intended.  Valid domain accounts or groups may also show
  up as unresolved SIDs if a connection to the domain cannot be established for
  some reason."
  impact 0.5
  tag "gtitle": 'WIN00-000190'
  tag "gid": 'V-75915'
  tag "rid": 'SV-90603r1_rule'
  tag "stig_id": 'WN12-00-000190'
  tag "fix_id": 'F-82553r1_fix'
  tag "cci": ['CCI-000366']
  tag "nist": ['CM-6 b', 'Rev_4']
  tag "documentable": false
  tag "check": "Review the effective User Rights setting in Local Group Policy
  Editor.
  Run \"gpedit.msc\".

  Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings
  >> Security Settings >> Local Policies >> User Rights Assignment.

  Review each User Right listed for any unresolved SIDs to determine whether they
  are valid, such as due to being temporarily disconnected from the domain.
  (Unresolved SIDs have the format of \"*S-1-…\".)

  If any unresolved SIDs exist and are not for currently valid accounts or
  groups, this is a finding."
  tag "fix": "Remove any unresolved SIDs found in User Rights assignments and
  determined to not be for currently valid accounts or groups by removing the
  accounts or groups from the appropriate group policy."

  describe "A manual review is required to ensure orphaned security identifiers (SIDs) are removed from user rights
  on Windows 2012 / 2012 R2" do
    skip 'A manual review is required to ensure orphaned security identifiers (SIDs) are removed from user rights
  on Windows 2012 / 2012 R2'
  end
end
