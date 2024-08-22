control 'SV-218745' do
  title 'The IIS 10.0 website must have resource mappings set to disable the serving of certain file types.'
  desc 'IIS 10.0 will either allow or deny script execution based on file extension. The ability to control script execution is controlled through two features with IIS 10.0, Request Filtering and Handler Mappings.

For Request Filtering, the ISSO must document and approve all allowable file extensions the website allows (white list) and denies (black list) by the website. The white list and black list will be compared to the Request Filtering in IIS 10.0. Request Filtering at the site level take precedence over Request Filtering at the server level.'
  desc 'check', 'Note: If the server being reviewed is hosting SharePoint, this is Not Applicable.

For Request Filtering, the ISSO must document and approve all allowable scripts the website allows (white list) and denies (black list). The white list and black list will be compared to the Request Filtering in IIS 10.0. Request Filtering at the site level take precedence over Request Filtering at the server level.

Follow the procedures below for each site hosted on the IIS 10.0 web server: 

Open the IIS 10.0 Manager.

Click the site name to review.

Double-click Request Filtering->File Name Extensions Tab.

If any script file extensions from the black list are not denied, this is a finding.'
  desc 'fix', 'Follow the procedures below for each site hosted on the IIS 10.0 web server: 

Open the IIS 10.0 Manager.

Click the site name to review.

Double-click Request Filtering->File Name Extensions Tab->Deny File Name Extension.

Add any script file extensions listed on the black list that are not listed.

Select "Apply" from the "Actions" pane.'
  impact 0.5
  tag check_id: 'C-20218r903114_chk'
  tag severity: 'medium'
  tag gid: 'V-218745'
  tag rid: 'SV-218745r903115_rule'
  tag stig_id: 'IIST-SI-000216'
  tag gtitle: 'SRG-APP-000141-WSR-000083'
  tag fix_id: 'F-20216r311134_fix'
  tag 'documentable'
  tag legacy: ['SV-109315', 'V-100211']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  site_names = json(command: 'ConvertTo-Json @(Get-Website | select -expand name)').params
  black_listed_extensions = attribute('black_listed_extensions')

  site_names.each do |site_name|
    extensions = command("Get-WebConfigurationProperty -Filter /system.webserver/security/requestFiltering/fileExtensions 'IIS:\\Sites\\#{site_name}'  -Name Collection | where {$_.allowed -eq $true}| select -expand fileExtension").stdout.split

    describe "Allowed Request Filtering extensions should not be in black listed extensions; #{extensions}" do
      subject { extensions }
      it { should_not be_in black_listed_extensions }
    end
  end

  if site_names.empty?
    impact 0.0
    desc 'There are no IIS sites configured hence the control is Not-Applicable'

    describe 'No sites where found to be reviewed' do
      skip 'No sites where found to be reviewed'
    end
  end
end
