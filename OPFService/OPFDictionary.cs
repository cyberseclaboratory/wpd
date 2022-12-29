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
using System.Collections;
using System.IO;
using System.Diagnostics;

namespace OPFService {
    class OPFDictionary {
        List<string> matchlist;
        List<string> contlist;

        public OPFDictionary(string pathmatch, string pathcont) {
            string line;
            StreamReader infilecont = new StreamReader(pathcont);
            contlist = new List<string>();
            int a = 1;
            while ((line = infilecont.ReadLine()) != null)
            {
                try
                {
                    contlist.Add(line.ToLower());
                    a += 1;
                }
                catch
                {
                    using (EventLog eventLog = new EventLog("Application"))
                    {
                        eventLog.Source = "Application";
                        eventLog.WriteEntry("Died trying to ingest line number " + a.ToString() + " of " + pathcont + ".", EventLogEntryType.Information, 101, 1);
                    }
                }
            }

        }

		//Эту часть надо заменить на работу с БД
        public Boolean contains(string word) {
            foreach (string badstr in contlist)
            {
                if (word.ToLower().Contains(badstr))
                {
                    return true;
                }
            }
            return false;
        }
    }
}
