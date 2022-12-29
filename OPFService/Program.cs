// This file is part of OpenPasswordFilter.
// 
// OpenPasswordFilter is free software; you can redistribute it and / or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
// 
// OpenPasswordFilter is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with OpenPasswordFilter; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111 - 1307  USA
//

using System;
using System.Collections.Generic;
using System.Threading;
using System.ServiceProcess;
using System.IO;
using Microsoft.Win32;

namespace OPFService {
    class OPFService : ServiceBase {
        Thread worker;

        public static int auditMode = 0;
        public static int logLevel = 0;
        public static string dbUri = "10.34.240.22:8443";

        public OPFService() {
            auditMode = (int)ReadRegistryKey("AuditMode", auditMode);
            logLevel = (int)ReadRegistryKey("LogLevel", logLevel);
            dbUri = (string)ReadRegistryKey("DBAddress", dbUri);

            EventLogWorker eventLogWorker = new EventLogWorker();
            string mode = "prevent";
            if (auditMode == 1) mode = "audit";
            eventLogWorker.AddLogEntry("Info", "Password Filter service started in " +
                mode + " mode\r\nDB address: " + dbUri, 9000);
        }

        static void Main(string[] args) {
            //            ServiceBase.Run(new OPFService());
            OPFService service = new OPFService();
            if (Environment.UserInteractive)
            {
                service.OnStart(args);
                Console.WriteLine("Press any key to stop program");
                Console.Read();
                service.OnStop();
            }
            else
            {
                ServiceBase.Run(service);
            }
        }

        protected override void OnStart(string[] args) {
            base.OnStart(args);
			//OPFDictionary d = new OPFDictionary(AppDomain.CurrentDomain.BaseDirectory + "\\opfdict.txt", AppDomain.CurrentDomain.BaseDirectory + "opfdict.txt");
			// OPFDictionary d = new OPFDictionary("c:\\windows\\system32\\opfmatch.txt", "c:\\windows\\system32\\opfcont.txt");
			//NetworkService svc = new NetworkService(d);
			NetworkService svc = new NetworkService();
			worker = new Thread(() => svc.main());
            worker.Start();
        }

        protected override void OnShutdown() {
            base.OnShutdown();
            worker.Abort();
        }

        private void InitializeComponent()
        {
            // 
            // OPFService
            // 
            this.ServiceName = "OPF";
            
        }

        private object ReadRegistryKey(string keyName, object defaultValue)
		{
            try
            {
                RegistryKey registryKey = Registry.LocalMachine;
                string path = @"Software\CSLab\PassFilter";
                using (RegistryKey rk = registryKey.OpenSubKey(path, false))
                {
                    if (rk != null)
                    {
                        var value = rk.GetValue(keyName, defaultValue);
                        return value;
                    }
                    else
                    {
                        return defaultValue;
                    }
                }
            }
            catch
            {
                return defaultValue;
            }
		}
    }
}
