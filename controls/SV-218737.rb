control 'SV-218737' do
  title 'A private IIS 10.0 website must only accept Secure Socket Layer (SSL) connections.'
  desc 'Transport Layer Security (TLS) encryption is a required security setting for a private web server. Encryption of private information is essential to ensuring data confidentiality. If private information is not encrypted, it can be intercepted and easily read by an unauthorized party. A private web server must use a FIPS 140-2-approved TLS version, and all non-FIPS-approved SSL versions must be disabled.

NIST SP 800-52 specifies the preferred configurations for government systems.'
  desc 'check', 'Note: If the server being reviewed is a public IIS 10.0 web server, this is Not Applicable.
Note: If the server is hosting SharePoint, this is Not Applicable.
Note: If the server is hosting WSUS, this is Not Applicable.
Note: If SSL is installed on load balancer/proxy server through which traffic is routed to the IIS 10.0 server, and the IIS 10.0 server receives traffic from the load balancer/proxy server, the SSL requirement must be met on the load balancer/proxy server.

Follow the procedures below for each site hosted on the IIS 10.0 web server:

Open the IIS 10.0 Manager.
Click the site name.
Double-click the "SSL Settings" icon.
Verify "Require SSL" check box is selected.

If the "Require SSL" check box is not selected, this is a finding.'
  desc 'fix', 'Follow the procedures below for each site hosted on the IIS 10.0 web server:

Open the IIS 10.0 Manager.

Click the site name.

Double-click the "SSL Settings" icon.

Select "Require SSL" check box.

Select "Apply" from the "Actions" pane.'
  impact 0.5
  tag check_id: 'C-20210r903107_chk'
  tag severity: 'medium'
  tag gid: 'V-218737'
  tag rid: 'SV-218737r903109_rule'
  tag stig_id: 'IIST-SI-000203'
  tag gtitle: 'SRG-APP-000014-WSR-000006'
  tag fix_id: 'F-20208r903108_fix'
  tag 'documentable'
  tag legacy: ['SV-109299', 'V-100195']
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']

  site_names = json(command: 'ConvertTo-Json @(Get-Website | select -expand name)').params

  site_names.each do |site_name|
    iis_configuration = json(command: "Get-WebConfigurationProperty -Filter system.webServer/security/access 'IIS:\\Sites\\#{site_name}'  -Name * | ConvertTo-Json")

    describe "IIS sessionState for site :'#{site_name}'" do
      subject { iis_configuration }
      its('sslFlags') { should include 'Ssl' }
    end
  end

  if attribute('public_server')
    impact 0.0
    desc 'The server being reviewed is a public IIS 10.0 web
    server, hence this control is Not Applicable.'
  end

  if site_names.empty?
    impact 0.0
    desc 'There are no IIS sites configured hence the control is Not-Applicable'

    describe 'No sites where found to be reviewed' do
      skip 'No sites where found to be reviewed'
    end
  end
end
