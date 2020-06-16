# -*- encoding : utf-8 -*-
# frozen_string_literal: true

control 'V-36451' do
  title "Administrative accounts must not be used with applications that access
  the Internet, such as web browsers, or with potential Internet sources, such as
  email."
  desc  "Using applications that access the Internet or have potential Internet
  sources using administrative privileges exposes a system to compromise.  If a
  flaw in an application is exploited while running as a privileged user, the
  entire system could be compromised.  Web browsers and email are common attack
  vectors for introducing malicious code and must not be run with an
  administrative account.

  Since administrative accounts may generally change or work around technical
  restrictions for running a web browser or other applications, it is essential
  that policy requires administrative accounts to not access the Internet or use
  applications, such as email.

  The policy should define specific exceptions for local service
  administration.  These exceptions may include HTTP(S)-based tools that are used
  from the administration of the local system, services, or attached devices.

  Technical means such as application whitelisting can be used to enforce the
  policy to ensure compliance.
  "
  impact 0.7
  tag "gtitle": 'Accounts with administrative privileges Internet access'
  tag "gid": 'V-36451'
  tag "rid": 'SV-51578r2_rule'
  tag "stig_id": 'WN12-00-000008'
  tag "fix_id": 'F-81021r2_fix'
  tag "cci": ['CCI-000366']
  tag "nist": ['CM-6 b', 'Rev_4']
  tag "documentable": false
  tag "check": "Determine whether administrative accounts are prevented from
  using applications that access the Internet, such as web browsers, or with
  potential Internet sources, such as email, except as necessary for local
  service administration.

  The organization must have a policy that prohibits administrative accounts from
  using applications that access the Internet, such as web browsers, or with
  potential Internet sources, such as email, except as necessary for local
  service administration.  The policy should define specific exceptions for local
  service administration. These exceptions may include HTTP(S)-based tools that
  are used for the administration of the local system, services, or attached
  devices.

  Technical measures such as the removal of applications or application
  whitelisting must be used where feasible to prevent the use of applications
  that access the Internet.

  If accounts with administrative privileges are not prevented from using
  applications that access the Internet or with potential Internet sources, this
  is a finding."
  tag "fix": "Establish and enforce a policy that prohibits administrative
  accounts from using applications that access the Internet, such as web
  browsers, or with potential Internet sources, such as email.  Define specific
  exceptions for local service administration. These exceptions may include
  HTTP(S)-based tools that are used for the administration of the local system,
  services, or attached devices.

  Implement technical measures where feasible such as removal of applications or
  use of application whitelisting to restrict the use of applications that can
  access the Internet."

  describe "A manual review is required to ensure administrative accounts are not be used with applications that access
  the Internet, such as web browsers, or with potential Internet sources, such as
  email" do
    skip 'A manual review is required to ensure administrative accounts are not be used with applications that access
  the Internet, such as web browsers, or with potential Internet sources, such as
  email'
  end
end
