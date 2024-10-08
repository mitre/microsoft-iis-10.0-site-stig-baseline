control 'SV-218748' do
  title 'Each IIS 10.0 website must be assigned a default host header.'
  desc 'The web server must be configured to listen on a specified IP address and port. Without specifying an IP address and port for the web server to use, the web server will listen on all IP addresses available to the hosting server. If the web server has multiple IP addresses, i.e., a management IP address, the web server will also accept connections on the management IP address.

Accessing the hosted application through an IP address normally used for non-application functions opens the possibility of user access to resources, utilities, files, ports, and protocols that are protected on the desired application IP address.'
  desc 'check', 'Note: If the server being reviewed is hosting SharePoint, this is Not Applicable.

Follow the procedures below for each site hosted on the IIS 10.0 web server:

Open the IIS 10.0 Manager.
Right-click on the site name under review.
Select "Edit Bindings".

Verify there are hostname entries and unique IP addresses assigned to port 80 for HTTP and port 443 for HTTPS. Other approved and documented ports may be used.

If both hostname entries and unique IP addresses are not configured to port 80 for HTTP and port 443 for HTTPS (or other approved and documented port), this is a finding.

Note: If certificate handling is performed at the Proxy/Load Balancer, this is not a finding.

Note: If HTTP/Port 80 is not being used, and is not configured as above, this is not a finding.

Note: If this IIS 10.0 installation is supporting Microsoft Exchange, and not otherwise hosting any content, this requirement is Not Applicable.'
  desc 'fix', 'Note: If the server being reviewed is hosting SharePoint, this is Not Applicable.

Follow the procedures below for each site hosted on the IIS 10.0 web server:

Open the IIS 10.0 Manager.

Right-click on the site name under review.

Select "Edit Bindings".

Assign hostname entries and unique IP addresses to port 80 for HTTP and port 443 for HTTPS. Other approved and documented ports may be used.

Click "OK".

Select "Apply" from the "Actions" pane.'
  impact 0.5
  tag check_id: 'C-20221r802887_chk'
  tag severity: 'medium'
  tag gid: 'V-218748'
  tag rid: 'SV-218748r879588_rule'
  tag stig_id: 'IIST-SI-000219'
  tag gtitle: 'SRG-APP-000142-WSR-000089'
  tag fix_id: 'F-20219r802888_fix'
  tag 'documentable'
  tag legacy: ['SV-109321', 'V-100217']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']

  site_name = attribute('site_name')

  http_ip = attribute('http_ip')

  http_hostname = attribute('http_hostname')

  https_ip = attribute('https_ip')

  https_hostname = attribute('https_hostname')

  site_name.zip(http_ip, http_hostname).each do |site, httpip, httphostname|
    describe iis_site(site.to_s) do
      it { should exist }
      it { should have_binding("http #{httpip}:80:#{httphostname}") }
    end
  end
  site_name.zip(https_ip, https_hostname).each do |site, httpsip, httsphostname|
    describe iis_site(site.to_s) do
      it { should exist }
      it { should have_binding("https #{httpsip}:80:#{httsphostname}") }
    end
  end
end
