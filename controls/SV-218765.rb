control 'SV-218765' do
  title 'The IIS 10.0 website must use a logging mechanism configured to allocate log record storage capacity large enough to accommodate the logging requirements of the IIS 10.0 website.'
  desc 'To make certain the logging mechanism used by the web server has sufficient storage capacity in which to write the logs, the logging mechanism must be able to allocate log record storage capacity.

The task of allocating log record storage capacity is usually performed during initial installation of the logging mechanism. The system administrator will usually coordinate the allocation of physical drive space with the web server administrator along with the physical location of the partition and disk. Refer to NIST SP 800-92 for specific requirements on log rotation and storage dependent on the impact of the web server.'
  desc 'check', 'Follow the procedures below for each site hosted on the IIS 10.0 web server:

Access the IIS 10.0 web server IIS 10.0 Manager.

Under "IIS" double-click on the "Logging" icon.

In the "Logging" configuration box, determine the "Directory:" to which the "W3C" logging is being written.

Confirm with the System Administrator that the designated log path is of sufficient size to maintain the logging.

Under "Log File Rollover", verify "Do not create new log files" is not selected.

Verify a schedule is configured to rollover log files on a regular basis.

Consult with the System Administrator to determine if there is a documented process for moving the log files off of the IIS 10.0 web server to another logging device.

If the designated logging path device is not of sufficient space to maintain all log files and there is not a schedule to rollover files on a regular basis, this is a finding.'
  desc 'fix', 'Follow the procedures below for each site hosted on the IIS 10.0 web server:

Under "IIS" double-click on the "Logging" icon.

If necessary, in the "Logging" configuration box, redesignate a log path to a location able to house the logs.

Under "Log File Rollover", deselect the "Do not create new log files" setting.

Configure a schedule to rollover log files on a regular basis.'
  impact 0.5
  tag check_id: 'C-20238r311193_chk'
  tag severity: 'medium'
  tag gid: 'V-218765'
  tag rid: 'SV-218765r879730_rule'
  tag stig_id: 'IIST-SI-000238'
  tag gtitle: 'SRG-APP-000357-WSR-000150'
  tag fix_id: 'F-20236r311194_fix'
  tag 'documentable'
  tag legacy: ['SV-109355', 'V-100251']
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']

  log_directory_path = attribute('log_directory')

  get_names = json(command: 'ConvertTo-Json @(Get-Website | select -expand name)').params

  system_drive = command('$env:SystemDrive').stdout.strip

  get_log_directory = command("Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter 'system.applicationHost/sites/*/logFile' -name * | select -expand directory").stdout.strip.split("\r\n")

  get_log_directory.zip(get_names).each do |log_directory, name|
    log_directory = log_directory.gsub(/%SystemDrive%/, system_drive.to_s)

    describe "The IIS site: #{name} log directory" do
      subject { log_directory }
      it { should cmp log_directory_path.to_s }
    end
  end

  get_log_period = command('Get-WebConfigurationProperty -pspath "IIS:\Sites\*" -Filter system.ApplicationHost/log -name centralW3CLogFile | select -expand period').stdout.strip.split("\r\n")

  get_log_period.zip(get_names).each do |log_period, name|
    describe "The IIS site: #{name} websites log file rollover period" do
      subject { log_period }
      it { should cmp 'Daily' }
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
