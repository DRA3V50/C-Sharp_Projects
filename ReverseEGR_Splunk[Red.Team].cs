using System;                           //For listing and directory.
using System.Collections.Generic;       //For file and directory access.
using System.ComponentModel.DataAnnotations;
using System.IO;                        //For JSON serial.
using System.Runtime.InteropServices;
using System.Text.Json;                 //For converting C# objects to and from JSON format.



namespace ReverseEGR_SplunkIntelGen
{
    class Program                       //Log storage of listed event of dictionaries.
    {
        static List<Dictionary<string, object>> SplunkLogs = new();
        static void Main()

        {
            Console.WriteLine("=== Splunk-Reverse Threat Engineering [Red.Team] ===");

            while (true)
            {                           //Main menu.
                Console.WriteLine("\nChoose Desired Action: ");
                Console.WriteLine("1 Simulate PE File Reverse Engineering");
                Console.WriteLine("2 Simulate Red Team Command Execution");
                Console.WriteLine("3 Search Logs [Splunk Related]");
                Console.WriteLine("4 Export Logs To JSON File");
                Console.WriteLine("5 Exit");               //Leave
                Console.WriteLine(">");
                var choice = Console.ReadLine();           //Give user option. 
                switch (choice)                            //Change menu option.
                {
                    case "1":
                        SimulatePEReverse();
                        break;
                    case "2":
                        SimulateCommandExecution();
                        break;
                    case "3":
                        SearchLogs();
                        break;
                    case "4":
                        ExportLogs();
                        break;
                    case "5":
                        return;
                    default:
                        Console.WriteLine("Invalid, please choose one of options given.");
                        break;
                }
            }
        }
        static void SimulatePEReverse()
        {
            Console.WriteLine("[SimulatePEReverse] Simulating PE Import Extraction - - - ");
            var logEntry = new Dictionary<string, object>
            {
                ["Timestamp"] = DateTime.Now,
                ["EventType"] = "PE_ReverseEngineering",
                ["Details"] = "Imported DLLS: kernel32.dll, user32.dll, advapi32.dll"
            };

            SplunkLogs.Add(logEntry);
            Console.WriteLine("PE imports simulated and logged.");
        }
        //Red team command execution & suspicious log.
        static void SimulateCommandExecution()
        {
            Console.WriteLine("[SimulationCommandExecution] Simulating Red Team Tool .> .> .>");
            var command = "net user hacker /add";  //Red team command.
            var suspiciousKeywords = new[] { "net user", " powershell", "cmd.exe" };
            bool isSuspicious = false;
            foreach (var keyword in suspiciousKeywords)
            {
                if (command.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                {
                    isSuspicious = true;
                    break;
                }
            }
            var logEntry = new Dictionary<string, object>
            {
                ["Timestamp"] = DateTime.Now,
                ["EventType"] = "RedTeam.Command",
                ["Command"] = command,
                ["Suspicious"] = isSuspicious
            };

            SplunkLogs.Add(logEntry);
            Console.WriteLine($"Command '{command}' execute and logged. Suspicious: {isSuspicious}");
        }

        //Search the logs for the user input keywords, display matching entries from user.
        static void SearchLogs()
        {
            Console.Write("Enter search keyword: ");
            var keyword = Console.ReadLine();
            if (string.IsNullOrEmpty(keyword))
            {
                Console.WriteLine("No keyword entered.");
                return;
            }

            Console.WriteLine($"Searching logs for keyword: '{keyword}' ..._..._..._");
            bool found = false;
            foreach (var log in SplunkLogs)
            {
                foreach (var kvp in log)
                {
                    if (kvp.Value is string value && value.IndexOf(keyword, StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        Console.WriteLine(JsonSerializer.Serialize(log));
                        found = true;
                        break;
                    }
                }
            }

            if (!found)
            {
                Console.WriteLine("No matches of logs founds.");
            }
        }
        //Export all JSON file logs on disk.
        static void ExportLogs()
        {
            string filename = "SplunkLogsExport.json";
            var option = new JsonSerializerOptions { WriteIndented = true };
            try
            {
                string json = JsonSerializer.Serialize(SplunkLogs, option);
                File.WriteAllText(filename, json);
                Console.WriteLine($"Logs successfully exported to '{filename}'");
            }

            catch (Exception ex)
            {
                Console.WriteLine($"Error exporting logs: {ex.Message}");
            }
        }
    }
}