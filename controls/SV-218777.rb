control 'SV-218777' do
  title 'The application pools rapid fail protection for each IIS 10.0 website must be enabled.'
  desc 'Rapid fail protection is a feature that interrogates the health of worker processes associated with websites and web applications. It can be configured to perform a number of actions such as shutting down and restarting worker processes that have reached failure thresholds. By not setting rapid fail protection, the web server could become unstable in the event of a worker process crash potentially leaving the web server unusable.'
  desc 'check', 'Note: If the IIS Application Pool is hosting Microsoft SharePoint, this is Not Applicable.

If this IIS 10.0 installation is supporting Microsoft Exchange, and not otherwise hosting any content, this requirement is Not Applicable.

Open the IIS 10.0 Manager.

Click "Application Pools".

Perform the following for each Application Pool:

Highlight an Application Pool to review and click "Advanced Settings" in the "Actions" pane.

Scroll down to the "Rapid Fail Protection" section and verify the value for "Enabled" is set to "True".

If the "Rapid Fail Protection:Enabled" is not set to "True", this is a finding.'
  desc 'fix', 'Open the IIS 10.0 Manager.

Click "Application Pools".

Perform the following for each Application Pool:

Highlight an Application Pool to review and click "Advanced Settings" in the "Actions" pane.

Scroll down to the "Rapid Fail Protection" section and set the value for "Enabled" to "True".

Click "OK".'
  impact 0.5
  tag check_id: 'C-20250r311229_chk'
  tag severity: 'medium'
  tag gid: 'V-218777'
  tag rid: 'SV-218777r879887_rule'
  tag stig_id: 'IIST-SI-000258'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-20248r311230_fix'
  tag 'documentable'
  tag legacy: ['SV-109379', 'V-100275']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  application_pool_names = json(command: 'ConvertTo-Json @(Get-ChildItem -Path IIS:\AppPools | select -expand name)').params

  application_pool_names.each do |application_pool|
    iis_configuration = json(command: "Get-ItemProperty 'IIS:\\AppPools\\#{application_pool}' -name * | select -expand failure | ConvertTo-Json")

    describe "The rapid fail protection setting for IIS Application Pool :'#{application_pool}'" do
      subject { iis_configuration }
      its('rapidFailProtection') { should cmp 'True' }
    end
  end
  if application_pool_names.empty?
    impact 0.0
    desc 'There are no application pool configured hence the control is Not-Applicable'

    describe 'No application pool where found to be reviewed' do
      skip 'No application pool where found to be reviewed'
    end
  end
end
