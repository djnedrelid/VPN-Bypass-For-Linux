/*
 *      Copyright (C) 2015 Dag Jonny Nedrelid
 *
 *      VPN Bypass for Linux, based off the Windows version.
 *		Needs 'apt-get install mono-complete' to run.
 *		Developed and tested for primarily Ubuntu.
 */

using System;
using System.Reflection;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.IO;
using System.Net;
using System.Diagnostics;

namespace VPNBypassLinux
{
	class Program
	{
		static void Main(string[] args)
		{
			VPNBypassForLinux VBFL = new VPNBypassForLinux();
			// ServicePointManager.DnsRefreshTimeout = 0; < DOES NOT WORK IN LINUX/MONO YET!

			if (args.Length > 0) {
				if (args[0] == "/cleanup") {
					VBFL.UpdateHostsAndRoutes(true);
					Console.WriteLine("Done.");
					return;
				} else if (args[0] == "/version") {
					Console.WriteLine("VPN Bypass For Linux (C) 2015-2019, Version " +
							Assembly.GetExecutingAssembly().GetName().Version.Major.ToString() +"."+
							Assembly.GetExecutingAssembly().GetName().Version.Minor.ToString() +
							Environment.NewLine +
							"Created by Dag J Nedrelid <https://nedrelid.net>");
					return;
				} else {
					Console.WriteLine("Either wrong parameter syntax or not supported.");
					return;
				}
			}

			if (VBFL.LoadConfigFile() && VBFL.CreateRouteTable())
				VBFL.StartVPNGuard();
			else
				Console.WriteLine("STOP! please check log file: /var/log/VPNBypassForLinux.log");
		}
	}

	class VPNBypassForLinux
	{
		private static string configfile = "/etc/VPNBypassForLinux.conf";
		private static string logfile = "/var/log/VPNBypassForLinux.log";
		private static string routefile = "/etc/VPNBypassRoutes";
		private string conf_interface_name = "";
		private string conf_interface_ip = "";
		private string conf_interface_gw = "";
		private List<string> conf_domains = new List<string>();
		private List<string> allroutes = new List<string>();
		//private Dictionary<string, string> resolved_ips = new Dictionary<string, string>();
		private List<KeyValuePair<string,string>> resolved_ips = new List<KeyValuePair<string,string>>();
		private bool GuardIsRunning = true;

		public VPNBypassForLinux()
		{
			if (!File.Exists(routefile))
				ResetRouteFile();
			else
				LoadRouteFile();
		}

		public bool LoadConfigFile()
		{
			try {
			string[] configLines = File.ReadAllLines(configfile);
			
			foreach (string configLine in configLines) {	
				if (configLine.StartsWith("add_domain#")) 
					conf_domains.Add(configLine.Substring(11));
				else if (configLine.StartsWith("interface_name#")) 
					conf_interface_name = configLine.Substring(15);
				else if (configLine.StartsWith("interface_ip#")) 
					conf_interface_ip = configLine.Substring(13);
				else if (configLine.StartsWith("interface_gw#")) 
					conf_interface_gw = configLine.Substring(13);
			}

			if (conf_interface_name == "" || conf_interface_gw == "" || conf_interface_ip == "") 
				throw new Exception("Please check network details in configuration file!");	
			else
				return true;
			
			} catch (Exception e) {
				LogIt("Failed to load configuration file: "+ e.Message);
				return false;
			}
		}

		private void LoadRouteFile()
		{
			string[] RouteCollection = File.ReadAllLines(routefile);
			foreach (string route in RouteCollection) {
				
				// Ignore comments.
				if (route.Contains("#"))
					continue;
			
				allroutes.Add(route);
			}
		}

		public bool CreateRouteTable()
		{
			string gw24mask = conf_interface_gw.Split('.')[0] + "."+ 
					conf_interface_gw.Split('.')[1] + "."+ 
					conf_interface_gw.Split('.')[2] + "."+ 
					"0/24";

			try {
			Process p = new Process();
			p.StartInfo.UseShellExecute = false;
			p.StartInfo.RedirectStandardOutput = true;
			p.StartInfo.RedirectStandardError = true;
			p.StartInfo.StandardOutputEncoding = Encoding.ASCII;
			p.StartInfo.StandardErrorEncoding = Encoding.ASCII;

			// Create bypass routing table.
			p.StartInfo.FileName = "ip";
			p.StartInfo.Arguments = "route add "+ gw24mask +" dev "+ conf_interface_name +" table 999";
			p.Start();
			p.WaitForExit(); 
			p.StartInfo.FileName = "ip";
			p.StartInfo.Arguments = "route add default via "+ conf_interface_gw +" table 999";
			p.Start();
			p.WaitForExit();

			// The from rule.
			if (!IpRuleFromExists()) {
				p.StartInfo.FileName = "ip";
				p.StartInfo.Arguments = "rule add from "+ conf_interface_ip +" table 999";
				p.Start();
				p.WaitForExit(); 
			}

			// Flush existing cached rules, keep things fresh.
			p.StartInfo.FileName = "ip";
			p.StartInfo.Arguments = "route flush cache > /dev/null 2>&1";
			p.Start();
			p.WaitForExit(); 

			return true;

			} catch (Exception e) {
				LogIt("CreateRouteTable() exception: "+ e.Message);
				return false;
			}
		}

		public void LogIt(string s)
		{
			string NewlineVal;
			if (s.Contains(Environment.NewLine))
				NewlineVal = "";
			else
				NewlineVal = Environment.NewLine;

			File.AppendAllText(logfile, DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") +"\t"+ s + NewlineVal);
		}

		public void StartVPNGuard()
		{
			List<string> ResolvedIPs = new List<string>();
			IPAddress _ip_out;
			LogIt("Starting VPNBypassGuard.");
			
			while(GuardIsRunning) {

				// Handle each domain in configuration file every 10 seconds.
				foreach (string _s in conf_domains) {
					ResolvedIPs = FetchTheIP(_s);
					if (ResolvedIPs.Count == 0) {
						LogIt(_s +" could not be resolved/renewed this round.");
						continue;
					} else {
						// We get all A records, but we can only route one so we pick the first.
						// Any load balacing should happen on the other side anyways, and if 
						// traffic shows up on eth0 from another IP, we already have ip rule
						// in place.
						foreach (string _ip in ResolvedIPs) {
							if (IPAddress.TryParse(_ip, out _ip_out)) {
								resolved_ips.Add(new KeyValuePair<string,string>(_s, _ip));
								//break;
							}
						}
					}
				}

				// Handle fresh list of resolved domains and wait to do it all over again.
				UpdateHostsAndRoutes(false);
				resolved_ips.Clear();

				// Relax for 10 seconds when work is done this round.
				Thread.Sleep(10000); 

				// Stay persistent as some network disconnects may reset it.
				CreateRouteTable(); 
			}
		}

		public void UpdateHostsAndRoutes(bool JustCleanIt)
		{
			if (resolved_ips.Count == 0 && !JustCleanIt)
				return;

			try {
			string[] HostLines = File.ReadAllLines("/etc/hosts");
			//Dictionary<string,string> AddedHosts = new Dictionary<string, string>();
			List<KeyValuePair<string,string>> AddedHosts = new List<KeyValuePair<string,string>>();
			string newHostData = "";
			int emptyLines = 0;
			Process p = new Process();

			// First find old hosts records.
			foreach (string HostLine in HostLines) {
				if (HostLine.Contains("# Added by VPN Bypass")) {
					AddedHosts.Add(new KeyValuePair<string,string>(HostLine.Split('\t')[1], HostLine.Split('\t')[0]));
					continue;
				}

				// Ignore excessive empty lines.
				if (HostLine == "")
					emptyLines += 1;
				else
					emptyLines = 0;

				if (emptyLines <= 1)
					newHostData += HostLine + Environment.NewLine;
			}
			
			// Prepare process object to (re)use.
			p.StartInfo.UseShellExecute = false;
			p.StartInfo.FileName = "ip";
			p.StartInfo.RedirectStandardOutput = true;
			p.StartInfo.RedirectStandardError = true;
			p.StartInfo.StandardOutputEncoding = Encoding.ASCII;
			p.StartInfo.StandardErrorEncoding = Encoding.ASCII;
			
			// Register new data if we're not just cleaning up.
			if (!JustCleanIt) {
				newHostData += Environment.NewLine;
				
				// Add new resolved/updated domains first.
				foreach (KeyValuePair<string,string> IPHost in resolved_ips) {
					newHostData += IPHost.Value +"\t"+ IPHost.Key +"\t"
						+"# Added by VPN Bypass" + Environment.NewLine;
					
					// Add to routing table. OS throws it away if it's already there so no worries.
					p.StartInfo.Arguments = "route add "+ IPHost.Value +" via "+ conf_interface_gw +" dev "+ conf_interface_name;
					p.Start();
					if (p.StandardError.ReadToEnd() == "") {
						if (!allroutes.Contains(IPHost.Value)) {
							allroutes.Add(IPHost.Value);
							File.AppendAllText(routefile, IPHost.Value + Environment.NewLine);
						}
					}
					p.WaitForExit();
				}

				// Add the already added, last. They may have failed to resolv just for a round or two.
				// If wanted, /cleanup can be used to clear the table if too many builds up over time.
				bool _dom_exists = false;
				foreach (KeyValuePair<string,string> r_ip in AddedHosts) {
					foreach (KeyValuePair<string,string> _dom in resolved_ips) {
						if (_dom.Key == r_ip.Key) 
							_dom_exists = true;
					}

					if (!_dom_exists) {
						// It should already exist in the routing table.
						// So we'll just add it again to /etc/hosts.
						newHostData += r_ip.Value +"\t"+ r_ip.Key +"\t"+ 
							"# Added by VPN Bypass" + Environment.NewLine;
					}
				}
			
			} else {
				Console.WriteLine("Cleaning up.");
				LogIt("Cleaning up all routes and hosts.");
				DeleteAllRoutes();
			}

			p.Dispose();
			File.WriteAllText("/etc/hosts", newHostData);

			} catch (Exception e) {
				LogIt("UpdateHostsAndRoutes() exception: "+ e.Message);
			}
		}

		private void DeleteAllRoutes()
		{
			Process p = new Process();
			p.StartInfo.UseShellExecute = false;
			p.StartInfo.FileName = "ip";
			p.StartInfo.RedirectStandardOutput = true;
			p.StartInfo.RedirectStandardError = true;
			p.StartInfo.StandardOutputEncoding = Encoding.ASCII;
			p.StartInfo.StandardErrorEncoding = Encoding.ASCII;

			try {
			foreach (string _s in allroutes) {

				if (_s != "") {
					p.StartInfo.Arguments = "route del "+ _s;
					p.Start();
					p.WaitForExit();
				}
			
			}} catch (Exception e) {
				LogIt("DeleteAllRoutes() notice: "+ e.Message);
			}

			p.Dispose();
			allroutes.Clear();
			ResetRouteFile();
		}

		private void ResetRouteFile()
		{
			File.WriteAllText(routefile, "# USED BY THE PROGRAM. DO NOT MAKE CHANGES TO THIS FILE."+ Environment.NewLine);
		}

		private List<string> FetchTheIP(string host)
		{
			List<string> ip_list = new List<string>();

			try {
				// This caches forever per 12.11.2015 as 
				// ServicePointManager.DnsRefreshTimeout 
				// is not implemented in Ubuntu packages yet.
				// IPAddress IPInfo = Dns.GetHostAddresses(host)[0];
				// return IPInfo.ToString();

				// Use the OS to lookup IP's instead.
				Process p = new Process();
				p.StartInfo.UseShellExecute = false;
				p.StartInfo.RedirectStandardOutput = true;
				p.StartInfo.RedirectStandardError = true;
				p.StartInfo.StandardOutputEncoding = Encoding.ASCII;
				p.StartInfo.StandardErrorEncoding = Encoding.ASCII;
				p.StartInfo.FileName = "dig";
				p.StartInfo.Arguments = host +" +short +tries=1 +time=1";
				p.Start();
				if (p.StandardError.ReadToEnd() == "") {
					while (p.StandardOutput.Peek() >= 0) {
						ip_list.Add(p.StandardOutput.ReadLine());
					}
				}
				p.WaitForExit(); 
				return ip_list;


			} catch (Exception e) {
				LogIt("FetchTheIP() exception: "+ e.Message);
				return ip_list;
			}
		}

		private bool IpRuleFromExists()
		{
			// Check if the rule is registered. Sometimes it may be deleted from 
			// other applications. This check will help CreateRouteTable() keep it consistent.
			bool IpAlreadyRegistered = false;

			try {
				Process p = new Process();
				p.StartInfo.UseShellExecute = false;
				p.StartInfo.RedirectStandardOutput = true;
				p.StartInfo.RedirectStandardError = true;
				p.StartInfo.StandardOutputEncoding = Encoding.ASCII;
				p.StartInfo.StandardErrorEncoding = Encoding.ASCII;
				p.StartInfo.FileName = "ip";
				p.StartInfo.Arguments = "rule show";
				p.Start();
				if (p.StandardError.ReadToEnd() == "") {
					while (p.StandardOutput.Peek() >= 0) {
						if (p.StandardOutput.ReadLine().Contains("from "+ conf_interface_ip +" lookup 999"))
							IpAlreadyRegistered = true;
					}
				}
				p.WaitForExit(); 
				return IpAlreadyRegistered;


			} catch (Exception e) {
				LogIt("IpRuleFromExists() exception: "+ e.Message);
				return IpAlreadyRegistered;
			}
		}
	}
}
