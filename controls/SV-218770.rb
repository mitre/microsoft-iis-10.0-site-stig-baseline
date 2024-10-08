control 'SV-218770' do
  title 'Cookies exchanged between the IIS 10.0 website and the client must have cookie properties set to prohibit client-side scripts from reading the cookie data.'
  desc 'A cookie can be read by client-side scripts easily if cookie properties are not set properly. By allowing cookies to be read by the client-side scripts, information such as session identifiers could be compromised and used by an attacker who intercepts the cookie. Setting cookie properties (i.e., HttpOnly property) to disallow client-side scripts from reading cookies better protects the information inside the cookie.

'
  desc 'check', 'Note: If the server being reviewed is a public IIS 10.0 web server, this is Not Applicable.
Note: If the server being reviewed is hosting SharePoint, this is Not Applicable.
Note: If the server being reviewed is hosting WSUS, this is Not Applicable.
Note: If SSL is installed on load balancer/proxy server through which traffic is routed to the IIS 10.0 server, and the IIS 10.0 server receives traffic from the load balancer/proxy server, the SSL requirement must be met on the load balancer/proxy server.

Follow the procedures below for each site hosted on the IIS 10.0 web server:

Access the IIS 10.0 Manager.
Under the "Management" section, double-click the "Configuration Editor" icon.
From the "Section:" drop-down list, select "system.web/httpCookies".
Verify the "require SSL" is set to "True".

From the "Section:" drop-down list, select "system.web/sessionState".
Verify the "compressionEnabled" is set to "False".

If both the "system.web/httpCookies:require SSL" is set to "True" and the "system.web/sessionState:compressionEnabled" is set to "False", this is not a finding.'
  desc 'fix', 'Follow the procedures below for each site hosted on the IIS 10.0 web server:

Access the IIS 10.0 Manager.
Under "Management" section, double-click the "Configuration Editor" icon.
From the "Section:" drop-down list, select "system.web/httpCookies".
Set the "require SSL" to "True".

From the "Section:" drop-down list, select "system.web/sessionState".
Set the "compressionEnabled" to "False".

Select "Apply" from the "Actions" pane.'
  impact 0.5
  tag check_id: 'C-20243r903124_chk'
  tag severity: 'medium'
  tag gid: 'V-218770'
  tag rid: 'SV-218770r903126_rule'
  tag stig_id: 'IIST-SI-000246'
  tag gtitle: 'SRG-APP-000439-WSR-000154'
  tag fix_id: 'F-20241r903125_fix'
  tag satisfies: ['SRG-APP-000439-WSR-000154', 'SRG-APP-000439-SSR-000155', 'SRG-APP-000439-WSR-000153']
  tag 'documentable'
  tag legacy: ['SV-109365', 'V-100261']
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']

  get_names = command("Get-Website | select name | findstr /v 'name ---'").stdout.strip.split("\r\n")
  get_compressionEnabled = command('Get-WebConfigurationProperty -pspath "IIS:\Sites\*" -Filter system.web/sessionState -name * | select -expand compressionEnabled').stdout.strip.split("\r\n")

  get_compressionEnabled.zip(get_names).each do |compressionEnabled, names|
    n = names.strip

    describe "The IIS site: #{n} website compressionEnabled enabled setting" do
      subject { compressionEnabled }
      it { should cmp 'False' }
    end
  end
  if get_names.empty?
    impact 0.0
    desc 'There are no IIS sites configured hence the control is Not-Applicable'

    describe 'No sites where found to be reviewed' do
      skip 'No sites where found to be reviewed'
    end
  end
end
