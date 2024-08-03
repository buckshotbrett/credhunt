#! /usr/bin/env python3
# By Brett Caldwell
# Based off the spider_plus.py cme plugin and snaffler
# sudo cp credhunt.py /usr/lib/python3/dist-packages/cme/modules/
# Usage: crackmapexec smb <TARGET(S)> -u '<USER>' -p '<PASSWORD>' -d '<DOMAIN>' -M credhunt

import re
import time
import datetime
from cme.protocols.smb.remotefile import RemoteFile
from impacket.smb3structs import FILE_READ_DATA
from impacket.smbconnection import SessionError

class CredentialCrawler:

	def __init__(self, smb, logger) -> None:
		'''Initialize password spider'''
		self.smb = smb
		self.host = self.smb.conn.getRemoteHost()
		self.max_connection_attempts = 5
		self.logger = logger
		self.max_size = 10 * 1024 * 1024
		self.max_connection_attempts = 5
		# Snaffler rules modified for Python
		self.rules = {
			'FilePath': [
				{
					'rule': 'KeepSSHFilesByPath',
					'target': 'FilePath',
					'match_type': 'Contains',
					'action': 'Snaffle',
					'triage': 'Black',
					'wordlist': [
						'/\\.ssh/'
					]
				},
				{
					'rule': 'KeepDomainJoinCredsByPath',
					'target': 'FilePath',
					'match_type': 'Contains',
					'action': 'Snaffle',
					'triage': 'Red',
					'wordlist': [
						'control/customsettings.ini'
					]
				},
				{
					'rule': 'KeepSCCMBootVarCredsByPath',
					'target': 'FilePath',
					'match_type': 'Regex',
					'action': 'Snaffle',
					'triage': 'Red',
					'wordlist': [
						'reminst/smstemp/.*\\.var',
						'sms/data/variables.dat',
						'sms/data/policy.xml'
					]
				},
				{
					'rule': 'KeepCloudApiKeysByPath',
					'target': 'FilePath',
					'match_type': 'Contains',
					'action': 'Snaffle',
					'triage': 'Black',
					'wordlist': [
						'/\\.aws/',
						'doctl/config.yaml'
					]}
			],
			'FileName': [
				{
					'rule': 'KeepFtpClientConfigConfigByName',
					'target': 'FileName',
					'match_type': 'Exact',
					'action': 'Snaffle',
					'triage': 'Red',
					'wordlist': [
						'recentservers.xml',
						'sftp-config.json'
					]
				},
				{
					'rule': 'KeepWinHashesByName',
					'target': 'FileName',
					'match_type': 'Exact',
					'action': 'Snaffle',
					'triage': 'Black',
					'wordlist': [
						'ntds.dit',
						'system',
						'sam',
						'security'
					]
				},
				{
					'rule': 'KeepDbMgtConfigByName',
					'target': 'FileName',
					'match_type': 'Exact',
					'action': 'Snaffle',
					'triage': 'Red',
					'wordlist': [
						'sqlstudio.bin',
						'.mysql_history',
						'.psql_history',
						'.pgpass',
						'.dbeaver-data-sources.xml',
						'credentials-config.json',
						'dbvis.xml',
						'robomongo.json'
					]
				},
				{
					'rule': 'KeepShellHistoryByName',
					'target': 'FileName',
					'match_type': 'Exact',
					'action': 'Snaffle',
					'triage': 'Green',
					'wordlist': [
						'.bash_history',
						'.zsh_history',
						'.sh_history',
						'zhistory',
						'.irb_history',
						'consolehost_history.txt'
					]
				},
				{
					'rule': 'KeepRubyByName',
					'target': 'FileName',
					'match_type': 'Exact',
					'action': 'Snaffle',
					'triage': 'Red',
					'wordlist': [
						'database.yml',
						'.secret_token.rb',
						'knife.rb',
						'carrierwave.rb',
						'omniauth.rb'
					]
				},
				{
					'rule': 'KeepMemDumpByName',
					'target': 'FileName',
					'match_type': 'Exact',
					'action': 'Snaffle',
					'triage': 'Black',
					'wordlist': [
						'memory.dmp',
						'hiberfil.sys',
						'lsass.dmp',
						'lsass.exe.dmp'
					]
				},
				{
					'rule': 'KeepRemoteAccessConfByName',
					'target': 'FileName',
					'match_type': 'Exact',
					'action': 'Snaffle',
					'triage': 'Black',
					'wordlist': [
						'mobaxterm.ini',
						'mobaxterm backup.zip',
						'confcons.xml'
					]
				},
				{
					'rule': 'KeepSSHKeysByFileName',
					'target': 'FileName',
					'match_type': 'Exact',
					'action': 'Snaffle',
					'triage': 'Black',
					'wordlist': [
						'id_rsa',
						'id_dsa',
						'id_ecdsa',
						'id_ed25519'
					]
				},
				{
					'rule': 'KeepConfigByName',
					'target': 'FileName',
					'match_type': 'Exact',
					'action': 'Snaffle',
					'triage': 'Red',
					'wordlist': [
						'.htpasswd'
					]
				},
				{
					'rule': 'CertContentByEnding',
					'target': 'FileName',
					'match_type': 'EndsWith',
					'action': 'Relay',
					'triage': 'Green',
					'wordlist': [
						'_rsa',
						'_dsa',
						'_ed25519',
						'_ecdsa'
					],
					'relay_configs': [
						'KeepInlinePrivateKey'
					]
				},
				{
					'rule': 'KeepShellRcFilesByName',
					'target': 'FileName',
					'match_type': 'Exact',
					'action': 'Snaffle',
					'triage': 'Green',
					'wordlist': [
						'.netrc',
						'_netrc',
						'.exports',
						'.functions',
						'.extra',
						'.npmrc',
						'.env',
						'.bashrc',
						'.profile',
						'.zshrc'
					]
				},
				{
					'rule': 'KeepNetConfigFileByName',
					'target': 'FileName',
					'match_type': 'Exact',
					'action': 'Snaffle',
					'triage': 'Black',
					'wordlist': [
						'running-config.cfg',
						'startup-config.cfg',
						'running-config',
						'startup-config'
					]
				},
				{
					'rule': 'RelayUnattendXml',
					'target': 'FileName',
					'match_type': 'Exact',
					'action': 'Relay',
					'triage': 'Green',
					'wordlist': [
						'unattend.xml',
						'autounattend.xml'
					],
					'relay_configs': [
						'KeepUnattendXmlRegexRed'
					]
				},
				{
					'rule': 'RelayNetConfigByName',
					'target': 'FileName',
					'match_type': 'Contains',
					'action': 'Relay',
					'triage': 'Green',
					'wordlist': [
						'cisco',
						'router',
						'firewall',
						'switch'
					],
					'relay_configs': [
						'KeepNetConfigCreds'
					]
				},
				{
					'rule': 'KeepDomainJoinCredsByName',
					'target': 'FileName',
					'match_type': 'Exact',
					'action': 'Snaffle',
					'triage': 'Yellow',
					'wordlist': [
						'customsettings.ini'
					]
				},
				{
					'rule': 'KeepFtpServerConfigByName',
					'target': 'FileName',
					'match_type': 'Exact',
					'action': 'Snaffle',
					'triage': 'Red',
					'wordlist': [
						'proftpdpasswd',
						'filezilla.xml'
					]
				},
				{
					'rule': 'KeepDefenderConfigByName',
					'target': 'FileName',
					'match_type': 'Exact',
					'action': 'Snaffle',
					'triage': 'Yellow',
					'wordlist': [
						'sensorconfiguration.json',
						'mdatp_managed.json'
					]
				},
				{
					'rule': 'KeepPasswordFilesByName',
					'target': 'FileName',
					'match_type': 'Exact',
					'action': 'Snaffle',
					'triage': 'Red',
					'wordlist': [
						'passwords.txt',
						'pass.txt',
						'accounts.txt',
						'passwords.doc',
						'pass.doc',
						'accounts.doc',
						'passwords.xls',
						'pass.xls',
						'accounts.xls',
						'passwords.docx',
						'pass.docx',
						'accounts.docx',
						'passwords.xlsx',
						'pass.xlsx',
						'accounts.xlsx',
						'secrets.txt',
						'secrets.doc',
						'secrets.xls',
						'secrets.docx',
						'secrets.xlsx'
					]
				},
				{
					'rule': 'KeepNameContainsGreen',
					'target': 'FileName',
					'match_type': 'Contains',
					'action': 'Snaffle',
					'triage': 'Green',
					'wordlist': [
						'passw',
						'secret',
						'credential',
						'thycotic',
						'cyberark'
					]
				},
				{
					'rule': 'KeepPhpByName',
					'target': 'FileName',
					'match_type': 'Exact',
					'action': 'Snaffle',
					'triage': 'Red',
					'wordlist': [
						'localsettings.php'
					]
				},
				{
					'rule': 'KeepFfLoginsJsonRelay',
					'target': 'FileName',
					'match_type': 'Exact',
					'action': 'Relay',
					'triage': 'Green',
					'wordlist': [
						'logins.json'
					],
					'relay_configs': [
						'KeepFFRegexRed'
					]
				},
				{
					'rule': 'KeepJenkinsByName',
					'target': 'FileName',
					'match_type': 'Exact',
					'action': 'Snaffle',
					'triage': 'Red',
					'wordlist': [
						'jenkins.plugins.publish_over_ssh.bapsshpublisherplugin.xml',
						'credentials.xml'
					]
				},
				{
					'rule': 'KeepCyberArkConfigsByName',
					'target': 'FileName',
					'match_type': 'Exact',
					'action': 'Snaffle',
					'triage': 'Black',
					'wordlist': [
						'psmapp.cred',
						'psmgw.cred',
						'backup.key',
						'masterreplicationuser.pass',
						'recprv.key',
						'replicationuser.pass',
						'server.key',
						'vaultemergency.pass',
						'vaultuser.pass',
						'vault.ini',
						'padr.ini',
						'paragent.ini',
						'cacpmscanner.exe.config',
						'pvconfiguration.xml'
					]
				},
				{
					'rule': 'KeepNixLocalHashesByName',
					'target': 'FileName',
					'match_type': 'Exact',
					'action': 'Snaffle',
					'triage': 'Black',
					'wordlist': [
						'shadow',
						'pwd.db',
						'passwd'
					]
				},
				{
					'rule': 'KeepPSHistoryByName',
					'target': 'FileName',
					'match_type': 'Exact',
					'action': 'Relay',
					'triage': 'Green',
					'wordlist': [
						'consolehost_history.txt'
					],
					'relay_configs': [
						'KeepPsCredentials',
						'KeepCmdCredentials',
						'KeepAwsKeysInCode',
						'KeepInlinePrivateKey',
						'KeepPassOrKeyInCode',
						'KeepSlackTokensInCode',
						'KeepSqlAccountCreation',
						'KeepDbConnStringPw'
					]
				},
				{
					'rule': 'KeepGitCredsByName',
					'target': 'FileName',
					'match_type': 'Exact',
					'action': 'Snaffle',
					'triage': 'Red',
					'wordlist': [
						'.git-credentials'
					]
				},
				{
					'rule': 'KeepKerberosCredentialsByName',
					'target': 'FileName',
					'match_type': 'Regex',
					'action': 'Snaffle',
					'triage': 'Yellow',
					'wordlist': [
						'krb5cc_.*'
					]
				},
				{
					'rule': 'KeepCloudApiKeysByName',
					'target': 'FileName',
					'match_type': 'Exact',
					'action': 'Snaffle',
					'triage': 'Black',
					'wordlist': [
						'.tugboat'
					]}
			],
			'FileExtension': [
				{
					'rule': 'RelayCertByExtension',
					'target': 'FileExtension',
					'match_type': 'Exact',
					'action': 'CheckForKeys',
					'triage': 'Red',
					'wordlist': [
						'.pem',
						'.der',
						'.pfx',
						'.pk12',
						'.p12',
						'.pkcs12'
					]
				},
				{
					'rule': 'KeepCyberArkByExtension',
					'target': 'FileExtension',
					'match_type': 'Exact',
					'action': 'Snaffle',
					'triage': 'Red',
					'wordlist': [
						'.cred',
						'.pass'
					]
				},
				{
					'rule': 'KeepDatabaseByExtension',
					'target': 'FileExtension',
					'match_type': 'Exact',
					'action': 'Snaffle',
					'triage': 'Yellow',
					'wordlist': [
						'.mdf',
						'.sdf',
						'.sqldump',
						'.bak'
					]
				},
				{
					'rule': 'KeepInfraAsCodeByExtension',
					'target': 'FileExtension',
					'match_type': 'Exact',
					'action': 'Snaffle',
					'triage': 'Red',
					'wordlist': [
						'.cscfg',
						'.tfvars'
					]
				},
				{
					'rule': 'RelayRdpByExtension',
					'target': 'FileExtension',
					'match_type': 'Exact',
					'action': 'Relay',
					'triage': 'Green',
					'wordlist': [
						'.rdp'
					],
					'relay_configs': [
						'KeepRdpPasswords'
					]
				},
				{
					'rule': 'RelayJsByExtension',
					'target': 'FileExtension',
					'match_type': 'Exact',
					'action': 'Relay',
					'triage': 'Green',
					'wordlist': [
						'.js',
						'.cjs',
						'.mjs',
						'.cs',
						'.ts',
						'.tsx',
						'.ls',
						'.es6',
						'.es'
					],
					'relay_configs': [
						'KeepAwsKeysInCode',
						'KeepInlinePrivateKey',
						'KeepPassOrKeyInCode',
						'KeepSlackTokensInCode',
						'KeepSqlAccountCreation',
						'KeepDbConnStringPw'
					]
				},
				{
					'rule': 'RelayCSharpByExtension',
					'target': 'FileExtension',
					'match_type': 'Exact',
					'action': 'Relay',
					'triage': 'Green',
					'wordlist': [
						'.aspx',
						'.ashx',
						'.asmx',
						'.asp',
						'.cshtml',
						'.cs',
						'.ascx',
						'.config'
					],
					'relay_configs': [
						'KeepCSharpDbConnStringsYellow',
						'KeepCSharpDbConnStringsRed',
						'KeepCSharpViewstateKeys',
						'KeepAwsKeysInCode',
						'KeepInlinePrivateKey',
						'KeepPassOrKeyInCode',
						'KeepSlackTokensInCode',
						'KeepSqlAccountCreation',
						'KeepDbConnStringPw',
						'KeepCSharpDbConnStringsRed',
						'KeepCSharpDbConnStringsYellow'
					]
				},
				{
					'rule': 'KeepDeployImageByExtension',
					'target': 'FileExtension',
					'match_type': 'Exact',
					'action': 'Snaffle',
					'triage': 'Yellow',
					'wordlist': [
						'.wim',
						'.ova',
						'.ovf'
					]
				},
				{
					'rule': 'RelayShellScriptByExtension',
					'target': 'FileExtension',
					'match_type': 'Exact',
					'action': 'Relay',
					'triage': 'Green',
					'wordlist': [
						'.netrc',
						'.exports',
						'.functions',
						'.extra',
						'.npmrc',
						'.env',
						'.bashrc',
						'.profile',
						'.zshrc',
						'.bash_history',
						'.zsh_history',
						'.sh_history',
						'zhistory',
						'.irb_history'
					],
					'relay_configs': [
						'KeepAwsKeysInCode',
						'KeepInlinePrivateKey',
						'KeepPassOrKeyInCode',
						'KeepSlackTokensInCode',
						'KeepSqlAccountCreation'
					]
				},
				{
					'rule': 'RelayPerlByExtension',
					'target': 'FileExtension',
					'match_type': 'Exact',
					'action': 'Relay',
					'triage': 'Green',
					'wordlist': [
						'.pl'
					],
					'relay_configs': [
						'KeepPerlDbConnStrings',
						'KeepAwsKeysInCode',
						'KeepInlinePrivateKey',
						'KeepPassOrKeyInCode',
						'KeepSlackTokensInCode',
						'KeepSqlAccountCreation',
						'KeepDbConnStringPw'
					]
				},
				{
					'rule': 'KeepSSHKeysByFileExtension',
					'target': 'FileExtension',
					'match_type': 'Exact',
					'action': 'Snaffle',
					'triage': 'Black',
					'wordlist': [
						'.ppk'
					]
				},
				{
					'rule': 'RelayConfigByExtension',
					'target': 'FileExtension',
					'match_type': 'Exact',
					'action': 'Relay',
					'triage': 'Green',
					'wordlist': [
						'.yaml',
						'.yml',
						'.toml',
						'.xml',
						'.json',
						'.config',
						'.ini',
						'.inf',
						'.cnf',
						'.conf',
						'.properties',
						'.env',
						'.dist',
						'.txt',
						'.sql',
						'.log',
						'.sqlite',
						'.sqlite3',
						'.fdb',
						'.tfvars'
					],
					'relay_configs': [
						'KeepAwsKeysInCode',
						'KeepInlinePrivateKey',
						'KeepPassOrKeyInCode',
						'KeepSlackTokensInCode',
						'KeepSqlAccountCreation',
						'KeepDbConnStringPw'
					]
				},
				{
					'rule': 'RelayInfraConfigByExtension',
					'target': 'FileExtension',
					'match_type': 'Exact',
					'action': 'Relay',
					'triage': 'Green',
					'wordlist': [
						'.xml',
						'.json',
						'.config',
						'.ini',
						'.inf',
						'.cnf',
						'.conf',
						'.txt'
					],
					'relay_configs': [
						'KeepNetConfigCreds'
					]
				},
				{
					'rule': 'KeepKerberosCredentialsByExtension',
					'target': 'FileExtension',
					'match_type': 'Exact',
					'action': 'Snaffle',
					'triage': 'Yellow',
					'wordlist': [
						'.keytab',
						'.ccache'
					]
				},
				{
					'rule': 'RelayVBScriptByExtension',
					'target': 'FileExtension',
					'match_type': 'Exact',
					'action': 'Relay',
					'triage': 'Green',
					'wordlist': [
						'.vbs',
						'.vbe',
						'.wsf',
						'.wsc',
						'.asp',
						'.hta'
					],
					'relay_configs': [
						'KeepCmdCredentials',
						'KeepAwsKeysInCode',
						'KeepInlinePrivateKey',
						'KeepPassOrKeyInCode',
						'KeepSlackTokensInCode',
						'KeepSqlAccountCreation',
						'KeepDbConnStringPw',
						'KeepCSharpDbConnStringsRed',
						'KeepCSharpDbConnStringsYellow'
					]
				},
				{
					'rule': 'RelayRubyByExtension',
					'target': 'FileExtension',
					'match_type': 'Exact',
					'action': 'Relay',
					'triage': 'Green',
					'wordlist': [
						'.rb'
					],
					'relay_configs': [
						'KeepRubyDbConnStrings',
						'KeepAwsKeysInCode',
						'KeepInlinePrivateKey',
						'KeepPassOrKeyInCode',
						'KeepSlackTokensInCode',
						'KeepSqlAccountCreation',
						'KeepDbConnStringPw'
					]
				},
				{
					'rule': 'KeepRemoteAccessConfByExtension',
					'target': 'FileExtension',
					'match_type': 'Exact',
					'action': 'Snaffle',
					'triage': 'Yellow',
					'wordlist': [
						'.rdg',
						'.rtsz',
						'.rtsx',
						'.ovpn',
						'.tvopt',
						'.sdtid'
					]
				},
				{
					'rule': 'RelayPsByExtension',
					'target': 'FileExtension',
					'match_type': 'Exact',
					'action': 'Relay',
					'triage': 'Green',
					'wordlist': [
						'.psd1',
						'.psm1',
						'.ps1'
					],
					'relay_configs': [
						'KeepPsCredentials',
						'KeepCmdCredentials',
						'KeepAwsKeysInCode',
						'KeepInlinePrivateKey',
						'KeepPassOrKeyInCode',
						'KeepSlackTokensInCode',
						'KeepSqlAccountCreation',
						'KeepDbConnStringPw'
					]
				},
				{
					'rule': 'RelayJavaByExtension',
					'target': 'FileExtension',
					'match_type': 'Exact',
					'action': 'Relay',
					'triage': 'Green',
					'wordlist': [
						'.jsp',
						'.do',
						'.java',
						'.cfm'
					],
					'relay_configs': [
						'KeepJavaDbConnStrings',
						'KeepAwsKeysInCode',
						'KeepInlinePrivateKey',
						'KeepPassOrKeyInCode',
						'KeepSlackTokensInCode',
						'KeepSqlAccountCreation',
						'KeepDbConnStringPw'
					]
				},
				{
					'rule': 'RelayPythonByExtension',
					'target': 'FileExtension',
					'match_type': 'Exact',
					'action': 'Relay',
					'triage': 'Green',
					'wordlist': [
						'.py'
					],
					'relay_configs': [
						'KeepPyDbConnStrings',
						'KeepAwsKeysInCode',
						'KeepInlinePrivateKey',
						'KeepPassOrKeyInCode',
						'KeepSlackTokensInCode',
						'KeepSqlAccountCreation',
						'KeepDbConnStringPw'
					]
				},
				{
					'rule': 'RelayPhpByExtension',
					'target': 'FileExtension',
					'match_type': 'Exact',
					'action': 'Relay',
					'triage': 'Green',
					'wordlist': [
						'.php',
						'.phtml',
						'.inc',
						'.php3',
						'.php5',
						'.php7'
					],
					'relay_configs': [
						'KeepPhpDbConnStrings',
						'KeepAwsKeysInCode',
						'KeepInlinePrivateKey',
						'KeepPassOrKeyInCode',
						'KeepSlackTokensInCode',
						'KeepSqlAccountCreation',
						'KeepDbConnStringPw'
					]
				},
				{
					'rule': 'KeepPcapByExtension',
					'target': 'FileExtension',
					'match_type': 'Exact',
					'action': 'Snaffle',
					'triage': 'Yellow',
					'wordlist': [
						'.pcap',
						'.cap',
						'.pcapng'
					]
				},
				{
					'rule': 'RelayCmdByExtension',
					'target': 'FileExtension',
					'match_type': 'Exact',
					'action': 'Relay',
					'triage': 'Green',
					'wordlist': [
						'.bat',
						'.cmd'
					],
					'relay_configs': [
						'KeepCmdCredentials',
						'KeepAwsKeysInCode',
						'KeepInlinePrivateKey',
						'KeepPassOrKeyInCode',
						'KeepSlackTokensInCode',
						'KeepSqlAccountCreation'
					]
				},
				{
					'rule': 'KeepPassMgrsByExtension',
					'target': 'FileExtension',
					'match_type': 'Exact',
					'action': 'Snaffle',
					'triage': 'Black',
					'wordlist': [
						'.kdbx',
						'.kdb',
						'.psafe3',
						'.kwallet',
						'.keychain',
						'.agilekeychain',
						'.cred'
					]
				},
				{
					'rule': 'KeepMemDumpByExtension',
					'target': 'FileExtension',
					'match_type': 'Exact',
					'action': 'Snaffle',
					'triage': 'Red',
					'wordlist': [
						'.dmp'
					]}
			],
			'Relay': {
				'KeepPassOrKeyInCode': {
					'rule': 'KeepPassOrKeyInCode',
					'target': 'FileContentAsString',
					'match_type': 'Regex',
					'action': 'Snaffle',
					'triage': 'Red',
					'wordlist': [
						b'passw?o?r?d\\s*=\\s*[\\\'\\"][^\\\'\\"]....',
						b'api[Kk]ey\\s*=\\s*[\\\'\\"][^\\\'\\"]....',
						b'passw?o?r?d?>\\s*[^\\s<]+\\s*<',
						b'passw?o?r?d?>.{3,2000}</pass',
						b'api[kK]ey>\\s*[^\\s<]+\\s*<',
						b'[_\\-\\.]oauth\\s*=\\s*[\\\'\\"][^\\\'\\"]....',
						b'client_secret\\s*=\\s*[\\\'\\"][^\\\'\\"]....',
						b'<ExtendedMatchKey>ClientAuth'
					]
				},
				'KeepPyDbConnStrings': {
					'rule': 'KeepPyDbConnStrings',
					'target': 'FileContentAsString',
					'match_type': 'Regex',
					'action': 'Snaffle',
					'triage': 'Red',
					'wordlist': [
						b'mysql\\.connector\\.connect\\(',
						b'psycopg2\\.connect\\('
					]
				},
				'KeepRubyDbConnStrings': {
					'rule': 'KeepRubyDbConnStrings',
					'target': 'FileContentAsString',
					'match_type': 'Regex',
					'action': 'Snaffle',
					'triage': 'Red',
					'wordlist': [
						b'DBI\\.connect\\('
					]
				},
				'KeepCSharpViewstateKeys': {
					'rule': 'KeepCSharpViewstateKeys',
					'target': 'FileContentAsString',
					'match_type': 'Regex',
					'action': 'Snaffle',
					'triage': 'Red',
					'wordlist': [
						b'validationkey\\s*=\\s*[\\\'\\"][^\\\'\\"]....',
						b'decryptionkey\\s*=\\s*[\\\'\\"][^\\\'\\"]....'
					]
				},
				'KeepRdpPasswords': {
					'rule': 'KeepRdpPasswords',
					'target': 'FileContentAsString',
					'match_type': 'Regex',
					'action': 'Snaffle',
					'triage': 'Red',
					'wordlist': [
						b'password 51\\:b'
					]
				},
				'KeepJavaDbConnStrings': {
					'rule': 'KeepJavaDbConnStrings',
					'target': 'FileContentAsString',
					'match_type': 'Regex',
					'action': 'Snaffle',
					'triage': 'Red',
					'wordlist': [
						b'\\.getConnection\\(\\"jdbc\\:',
						b'passwo?r?d\\s*=\\s*[\\\'\\"][^\\\'\\"]....'
					]
				},
				'KeepCSharpDbConnStringsYellow': {
					'rule': 'KeepCSharpDbConnStringsYellow',
					'target': 'FileContentAsString',
					'match_type': 'Regex',
					'action': 'Snaffle',
					'triage': 'Yellow',
					'wordlist': [
						b'Data Source=.+Integrated Security=(SSPI|true)',
						b'Integrated Security=(SSPI|true);.*Data Source=.+'
					]
				},
				'KeepCSharpDbConnStringsRed': {
					'rule': 'KeepCSharpDbConnStringsRed',
					'target': 'FileContentAsString',
					'match_type': 'Regex',
					'action': 'Snaffle',
					'triage': 'Red',
					'wordlist': [
						b'Data Source=.+(;|)Password=.+(;|)',
						b'Password=.+(;|)Data Source=.+(;|)'
					]
				},
				'KeepS3UriPrefixInCode': {
					'rule': 'KeepS3UriPrefixInCode',
					'target': 'FileContentAsString',
					'match_type': 'Regex',
					'action': 'Snaffle',
					'triage': 'Yellow',
					'wordlist': [
						b's3[a]?:\\/\\/[a-zA-Z0-9\\-\\+\\/]{2,16}'
					]
				},
				'KeepDbConnStringPw': {
					'rule': 'KeepDbConnStringPw',
					'target': 'FileContentAsString',
					'match_type': 'Regex',
					'action': 'Snaffle',
					'triage': 'Yellow',
					'wordlist': [
						b'connectionstring.{1,200}passw'
					]
				},
				'KeepUnattendXmlRegexRed': {
					'rule': 'KeepUnattendXmlRegexRed',
					'target': 'FileContentAsString',
					'match_type': 'Regex',
					'action': 'Snaffle',
					'triage': 'Red',
					'wordlist': [
						b'(?s)<AdministratorPassword>.{0,30}<Value>.*<\\/Value>',
						b'(?s)<AutoLogon>.{0,30}<Value>.*<\\/Value>'
					]
				},
				'KeepPsCredentials': {
					'rule': 'KeepPsCredentials',
					'target': 'FileContentAsString',
					'match_type': 'Regex',
					'action': 'Snaffle',
					'triage': 'Red',
					'wordlist': [
						b'-SecureString',
						b'-AsPlainText',
						b'\\[Net.NetworkCredential\\]::new\\('
					]
				},
				'KeepCmdCredentials': {
					'rule': 'KeepCmdCredentials',
					'target': 'FileContentAsString',
					'match_type': 'Regex',
					'action': 'Snaffle',
					'triage': 'Red',
					'wordlist': [
						b'passwo?r?d\\s*=\\s*[\\\'\\"][^\\\'\\"]....',
						b'schtasks.{1,300}(/rp\\s|/p\\s)',
						b'net user ',
						b'psexec .{0,100} -p ',
						b'net use .{0,300} /user:',
						b'cmdkey '
					]
				},
				'KeepPhpDbConnStrings': {
					'rule': 'KeepPhpDbConnStrings',
					'target': 'FileContentAsString',
					'match_type': 'Regex',
					'action': 'Snaffle',
					'triage': 'Red',
					'wordlist': [
						b'mysql_connect\\s*\\(.*\\$.*\\)',
						b'mysql_pconnect\\s*\\(.*\\$.*\\)',
						b'mysql_change_user\\s*\\(.*\\$.*\\)',
						b'pg_connect\\s*\\(.*\\$.*\\)',
						b'pg_pconnect\\s*\\(.*\\$.*\\)'
					]
				},
				'KeepInlinePrivateKey': {
					'rule': 'KeepInlinePrivateKey',
					'target': 'FileContentAsString',
					'match_type': 'Regex',
					'action': 'Snaffle',
					'triage': 'Red',
					'wordlist': [
						b'-----BEGIN( RSA| OPENSSH| DSA| EC| PGP)? PRIVATE KEY( BLOCK)?-----'
					]
				},
				'KeepFFRegexRed': {
					'rule': 'KeepFFRegexRed',
					'target': 'FileContentAsString',
					'match_type': 'Regex',
					'action': 'Snaffle',
					'triage': 'Red',
					'wordlist': [
						b'"encryptedPassword":"[A-Za-z0-9+/=]+"'
					]
				},
				'KeepSlackTokensInCode': {
					'rule': 'KeepSlackTokensInCode',
					'target': 'FileContentAsString',
					'match_type': 'Regex',
					'action': 'Snaffle',
					'triage': 'Red',
					'wordlist': [
						b'(xox[pboa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})',
						b'https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}'
					]
				},
				'KeepNetConfigCreds': {
					'rule': 'KeepNetConfigCreds',
					'target': 'FileContentAsString',
					'match_type': 'Regex',
					'action': 'Snaffle',
					'triage': 'Red',
					'wordlist': [
						b'NVRAM config last updated',
						b'enable password \\.',
						b'simple-bind authenticated encrypt',
						b'pac key [0-7] ',
						b'snmp-server community\\s.+\\sRW'
					]
				},
				'KeepAwsKeysInCode': {
					'rule': 'KeepAwsKeysInCode',
					'target': 'FileContentAsString',
					'match_type': 'Regex',
					'action': 'Snaffle',
					'triage': 'Red',
					'wordlist': [
						b'aws[_\\-\\.]?key',
						b'(\\s|\\\'|\\"|\\^|=)(A3T[A-Z0-9]|AKIA|AGPA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z2-7]{12,16}(\\s|\\\'|\\"|$)'
					]
				},
				'KeepSqlAccountCreation': {
					'rule': 'KeepSqlAccountCreation',
					'target': 'FileContentAsString',
					'match_type': 'Regex',
					'action': 'Snaffle',
					'triage': 'Red',
					'wordlist': [
						b'CREATE (USER|LOGIN) .{0,200} (IDENTIFIED BY|WITH PASSWORD)'
					]
				},
				'KeepPerlDbConnStrings': {
					'rule': 'KeepPerlDbConnStrings',
					'target': 'FileContentAsString',
					'match_type': 'Regex',
					'action': 'Snaffle',
					'triage': 'Red',
					'wordlist': [
						b'DBI\\-\\>connect\\('
					]
				}
			}
		}

	def _test_file(self, share_name: str, full_path: str, filename: str, fileext: str) -> None:
		'''Run a series of file path, name, ext, and content checks'''
		for category in ["FilePath", "FileName", "FileExtension"]:
			self._match_content(share_name, full_path, filename, fileext, category)

	def _match_content(self, share_name: str, full_path: str, filename: str, fileext: str, category: str) -> None:
		'''Trigger snaffle or relay actions based on file path'''
		# Initialize file content
		file_contents = b''
		# Get search content
		content = self._get_search_content(full_path, filename, fileext, category)
		# Iterate over the relevant rules
		for rule in self.rules[category]:
			match_function = self._get_match_function(rule)
			# Relay Action
			if rule["action"] == "Relay":
				match = match_function(content, rule["wordlist"])
				if match:
					if not file_contents:
						file_contents = self._download_file(share_name, full_path)
					for relay_rule in rule["relay_configs"]:
						rr = self.rules["Relay"][relay_rule]
						mf = self._get_match_function(rr)
						m = mf(file_contents, rr["wordlist"])
						if m:
							self._log_snaffle(rr["triage"], rr["rule"], share_name, full_path, m)
			# Snaffle Action
			elif rule["action"] == "Snaffle":
				match = match_function(content, rule["wordlist"])
				if match:
					self._log_snaffle(rule["triage"], rule["rule"], share_name, full_path, match)
			# Ignore other actions
			else:
				pass

	def _log_snaffle(self, triage: str, rule_name: str, share_name: str, full_path: str, match: bytes) -> None:
		'''Log output of finding details to the console'''
		now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
		self.logger.info(f'<CREDHUNT>{now}|[{triage}]|{rule_name}|//{self.host}/{share_name}{full_path}|{match}</CREDHUNT>')

	def _get_search_content(self, full_path: str, filename: str, fileext: str, category: str) -> str:
		'''Return the content string used for searching against rules'''
		if category == "FilePath":
			content = full_path
		elif category == "FileName":
			content = filename
		elif category == "FileExtension":
			content = fileext
		return content

	def _get_match_function(self, rule: dict):
		'''Return the match function'''
		match_type = rule["match_type"]
		if rule["match_type"] == "Exact":
			match_function = self._exact
		elif rule["match_type"] == "Regex":
			match_function = self._regex
		elif rule["match_type"] == "Contains":
			match_function = self._contains
		elif rule["match_type"] == "EndsWith":
			match_function = self._endswith
		return match_function

	def _exact(self, target: str, wordlist: list) -> str:
		'''Return matching string if target equals wordlist word'''
		t = target.lower()
		for i in wordlist:
			if t == i:
				return i
		return ""

	def _regex(self, target: str, wordlist: list) -> str:
		'''Return matching string if target matches wordlist regex'''
		for i in wordlist:
			regex = re.compile(i, re.I)
			match = regex.search(target)
			if match:
				return match.string[match.start():match.end()]
		return ""

	def _contains(self, target: str, wordlist: list) -> str:
		'''Return matching string if target contains wordlist word'''
		t = target.lower()
		for i in wordlist:
			if i in t:
				return i
		return ""

	def _endswith(self, target: str, wordlist: list) -> str:
		'''Return matching string if target ends with wordlist word'''
		t = target.lower()
		for i in wordlist:
			if t.endswith(i):
				return i
		return ""

	def _read_chunk(self, file_handle, chunk_size=4096):
		'''Read a file chunk'''
		chunk = b""
		retry = 3
		while retry > 0:
			retry -= 1
			try:
				chunk = file_handle.read(chunk_size)
				break
			except SessionError:
				if self._reconnect():
					# Reset the smb connection
					file_handle.__smbConnection = self.smb.conn
					return self._read_chunk(file_handle)
			except Exception as e:
				break
		return chunk

	def _download_file(self, share: str, path: str) -> bytes:
		'''Download file contents in 4kb chunks and return'''
		contents = b""
		try:
			fh = RemoteFile(self.smb.conn, path, share, access=FILE_READ_DATA)
			fh.open()
			while True:
				chunk = self._read_chunk(fh)
				contents += chunk
				if not chunk:
					break
			fh.close()
		except Exception as e:
			if self._reconnect():
				return self._download_file(share, path)
		return contents

	def _is_interesting_share(self, share_name: str) -> bool:
		'''Return true if this share should be noted but not spidered'''
		sname = share_name.lower()
		interesting = [
			"netlogon",
			"sysvol",
			"c$",
			"admin$",
			"sccmcontentlib$"
		]
		for share in interesting:
			if sname == share:
				return True
		return False

	def _is_crawlable(self, share_name: str) -> bool:
		'''Return true if share is of interest'''
		sname = share_name.lower()
		do_not_crawl = [
			"print$",
			"ipc$"
		]
		for share in do_not_crawl:
			if sname == share:
				return False
		return True

	def _reconnect(self):
		'''Reconnect SMB connection'''
		for i in range(1, self.max_connection_attempts + 1):
			time.sleep(3)
			self.smb.create_conn_obj()
			self.smb.login()
			return True
		return False

	def _list_dir(self, share: str, subfolder: str) -> list:
		'''Return a list of paths for a share folder'''
		filelist = []
		try:
			# Get file list for the current folder
			filelist = self.smb.conn.listPath(share, subfolder + "*")
		except SessionError as e:
			error = str(e)
			if "STATUS_ACCESS_DENIED" in error:
				pass
			elif "STATUS_OBJECT_PATH_NOT_FOUND" in error:
				pass
			elif "STATUS_NO_SUCH_FILE" in error:
				pass
			else:
				if self._reconnect():
					filelist = self.smb.conn.listPath(share, subfolder + "*")
		return filelist

	def _in_ignore_ext_list(self, ext: str) -> bool:
		'''Return True if file should be ignored based on extension'''
		ignore = {
			".bmp", ".eps", ".gif", ".ico", ".jfi", ".jfif", ".jif", ".jpe",
			".jpeg", ".jpg", ".png", ".psd", ".svg", ".tif", ".tiff", ".webp",
			".xcf", ".ttf",	".otf", ".lock", ".css", ".less", ".admx", ".adml",
			".xsd", ".nse", ".xsl"
		}
		if ext in ignore:
			return True
		return False

	def _not_fp_filename(self, filename: str) -> bool:
		'''Return true if filename is not an FP'''
		fname = filename.lower()
		fps = [
			"credentialprovider.idl",
			"pspasswd64.exe",
			"pspasswd.exe",
			"psexec.exe",
			"psexec64.exe",
			"jmxremote.password.template",
			"sceregvl.inf"
		]
		for fp in fps:
			if fp == fname:
				return False
		return True

	def _not_in_fp_folders(self, folder: str) -> bool:
		'''Return true if folder is not known for FPs'''
		fps = [
			r"/puppet/share/doc",
			r"/lib/ruby",
			r"/lib/site-packages",
			r"/usr/share/doc",
			r"node_modules",
			r"vendor/bundle",
			r"vendor/cache",
			r"/doc/openssl",
			r"Anaconda3/Lib/test",
			r"WindowsPowerShell/Modules",
			r"Python[\d\x2e]{0,4}/Lib",
			r"Reference Assemblies/Microsoft/Framework/\.NETFramework"
			r"dotnet/sdk",
			r"dotnet/shared",
			r"Modules/Microsoft\.PowerShell\.Security",
			r"Windows/assembly",
			r"/winsxs",
			r"/syswow64",
			r"/system32",
			r"/systemapps",
			r"/windows/servicing",
			r"/servicing",
			r"/Microsoft\.NET/Framework",
			r"/windows/immersivecontrolpanel",
			r"/windows/diagnostics",
			r"/windows/debug",
			r"/locale",
			r"/chocolatey/helpers",
			r"/sources/sxs",
			r"/localization",
			r"/AppData/Local/Microsoft",
			r"/AppData/Roaming/Microsoft/Windows",
			r"/AppData/Roaming/Microsoft/Teams",
			r"/wsuscontent",
			r"/Application Data/Microsoft/CLR Security Config",
			r"/servicing/LCU",
			r"Windows Kits/10",
			r"Git/mingw64",
			r"Git/usr/lib",
			r"ProgramData/Microsoft/NetFramework/BreadcrumbStore",
			r"\.MSSQLSERVER/MSSQL/Binn/Templates"
		]
		for fp in fps:
			if re.search(fp, folder, re.I):
				return False
		return True

	def _get_filename(self, filepath: str) -> str:
		'''Return filename given a full path'''
		return filepath.split("/")[-1]

	def _get_file_ext(self, filename: str) -> str:
		'''Return file extension given a file name'''
		ext = ""
		if "." in filename:
			exts = filename.split(".")[1:]
			ext = "." + ".".join(exts)
		return ext

	def _spider_folder(self, share_name: str, folder: str) -> None:
		'''Spider sufolders searching for credentials'''
		for result in self._list_dir(share_name, folder + "*"):
			_next = result.get_longname()
			if _next in [".", ".."]:
				continue
			path = folder + _next
			# Folders
			if result.is_directory():
				#print(path)
				if self._not_in_fp_folders(path):
					self._spider_folder(share_name, path + "/")
			# Files
			else:
				#print(path)
				size = result.get_filesize()
				if size <= self.max_size: # Maybe implement this in a different spot so filename rules and such can still work
					filename = self._get_filename(path)
					if self._not_fp_filename(filename):
						ext = self._get_file_ext(filename)
						if not self._in_ignore_ext_list(ext):
							self._test_file(share_name, path, filename, ext)

	def spider_shares(self):
		'''Enumerate all shares and spider files and folders'''
		self.logger.info("Enumerating shares for spidering.")
		try:
			# Get all available shares for the SMB connection
			shares = self.smb.shares()
			for share in shares:
				share_perms = share["access"]
				share_name = share["name"]
				if ("READ" in share_perms) or ("WRITE" in share_perms):
					# Log interesting shares but do not spider
					if self._is_interesting_share(share_name):
						self.logger.info(
							f'<CREDHUNT>{datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}|[Black]|Accessible Interesting Share|//{self.host}/{share_name}|{share_name}</CREDHUNT>'
						)
					# exclude shares that are not crawlable
					elif self._is_crawlable(share_name):
						try:
							# Spider the share root
							self._spider_folder(share_name, "/")
						except SessionError:
							self.logger.info(f"Error spidering {self.host}.")
							self._reconnect()
		except Exception as e:
			self.logger.info(f"Error enumerating shares ({self.host}): {str(e)}")


class CMEModule:

	name = "credhunt"
	description = "Spider shares looking for credentials and other interesting things"
	supported_protocols = ["smb"]
	opsec_safe = True 
	multiple_hosts = True

	def __init__(self) -> None:
		'''Initialize module'''
		pass

	def options(self, context, module_options):
		'''Get module options'''
		pass

	def on_login(self, context, connection):
		'''Login action is to spider for creds'''
		spider = CredentialCrawler(connection, context.log)
		spider.spider_shares()


