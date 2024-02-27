/**
 * Copyright 2024 Aon plc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

using System;
using System.IO;
using System.Linq;
using System.Diagnostics;
using System.Collections.Generic;
using System.Management;
using System.Threading;

namespace LowDLL
{
    class Program
    {
        static uint GetStaticAddress(PeNet.PeFile peFile, string sectionName)
        {
            var headers = peFile.ImageSectionHeaders;
            foreach (var header in headers)
            {
                if (header.Name == sectionName)
                {
                    var headerVirtualAddress = header.VirtualAddress;
                    var pointerToRawData = header.PointerToRawData;
                    return peFile.ImageNtHeaders.OptionalHeader.AddressOfEntryPoint - headerVirtualAddress + pointerToRawData;
                }
            }
            return 0;
        }
        public static bool CurrentUserHasWritePermission(string tempdirpath)
        {
            try
            {
                Guid g = Guid.NewGuid();
                System.IO.File.Create(tempdirpath + g).Close();
                System.IO.File.Delete(tempdirpath + g);
            }
            catch (Exception e)
            {
                Console.WriteLine("Exception: " + e);
                Console.WriteLine("PATH: " + tempdirpath);
                return false;
            }

            return true;
        }
        class procDll
        {
            public string procName;
            public int pid;
            public List<string> dllPaths = new List<string>();
        }

        static void Main(string[] args)
        {
            if(args.Length != 1)
            {
                Console.WriteLine("Usage: LowDll.exe <path_to_ListDlls64.exe>");
                Console.WriteLine("[*] Path to ListDlls64.exe from SysInternals is required for this tool.");
                Console.WriteLine("[*] NOTE: Make sure the programs you're checking out are CURRENTLY RUNNING.");
                return;
            }

            ConsoleColor currColor = Console.ForegroundColor;
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("\n\nRed: 64-bit and DLL entry point patchable by current DUALITY capabilities.");
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("Yellow: 64-bit but entry point is a little off. Either entry point is not supported or file is already backdoored.");
            Console.ForegroundColor = ConsoleColor.Blue;
            Console.WriteLine("Blue: File is 32-bit and there are no plans to support this, although theoretically it's possible to backdoor.");
            Console.ForegroundColor = currColor;
            Console.WriteLine("\n\nParsing currently running processes for DLLs loaded from low-priv locations... this might take a little while...\n");

            //Console.WriteLine(CurrentUserHasWritePermission(path));
            List<string> outputLines = new List<string>();
            var proc = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = args[0],
                    Arguments = @"-accepteula",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true
                }
            };
            proc.Start();
            while(!proc.StandardOutput.EndOfStream)
            {
                string line = proc.StandardOutput.ReadLine();
                outputLines.Add(line);
            }

            List<procDll> procDlls = new List<procDll>();
            foreach (string line in outputLines)
            {
                if (!string.IsNullOrEmpty(line))
                {
                    try
                    {
                        if (line.StartsWith("----"))
                        {
                            procDll currInst = new procDll();
                            procDlls.Add(currInst);
                        }
                        string[] splitLine = line.Split(' ');
                        if (splitLine.Length > 2 && splitLine[splitLine.Length - 2] == "pid:")
                        {
                            procDll lastEntry = procDlls[procDlls.Count - 1];
                            lastEntry.procName = splitLine[0];
                            lastEntry.pid = Int32.Parse(splitLine[splitLine.Length - 1]);
                        }
                        if (line.StartsWith("0x"))
                        {
                            procDll lastEntry = procDlls[procDlls.Count - 1];
                            List<string> justDLL = new List<string>(line.Split(new char[] { ' ' }, StringSplitOptions.RemoveEmptyEntries));
                            justDLL.RemoveAt(0);
                            justDLL.RemoveAt(0);
                            justDLL = new List<string>(string.Join("", justDLL).Split('\\'));
                            lastEntry.dllPaths.Add(string.Join("\\", justDLL));
                        }
                    } catch (Exception e)
                    {
                        Console.WriteLine(e);
                        continue;
                    }

                }
            }

            foreach(procDll item in procDlls)
            {
                item.dllPaths = item.dllPaths.Distinct().ToList();
            }

            List<string> cnaList = new List<string>();

            foreach(procDll item in procDlls)
            {
                Console.WriteLine("[*] Checking " + item.pid + " -- '" + item.procName + "'");
                foreach(string dllPath in item.dllPaths)
                {
                    string l_dllpath = dllPath.Replace(@"\\?\", "");

                    if (CurrentUserHasWritePermission(Path.GetDirectoryName(l_dllpath)))
                    {
                        ConsoleColor originalColor = Console.ForegroundColor;

                        try
                        {
                            PeNet.PeFile peFile = new PeNet.PeFile(l_dllpath);
                            var staticEntryPoint = GetStaticAddress(peFile, ".text");
                            if (staticEntryPoint != 0)
                            {
                                uint[] firstFewInstructions = new uint[5];
                                for (uint x = 0; x < 5; x++)
                                {
                                    uint b = 0;
                                    try
                                    {
                                        firstFewInstructions[x] = peFile.RawFile.ReadByte(staticEntryPoint + x);
                                    } catch(Exception ex)
                                    {
                                        Console.WriteLine("\t[-] Error while reading DLL: " + l_dllpath);
                                        break;
                                    }
                                }
                                if (firstFewInstructions[0] == 0x48 && firstFewInstructions[1] == 0x89 && peFile.Is64Bit)
                                {
                                    Console.ForegroundColor = ConsoleColor.Red;
                                    Console.WriteLine("\t[+] [64-bit] - Susceptible to DUALITY: " + l_dllpath);
                                    cnaList.Add(l_dllpath);
                                    Console.ForegroundColor = originalColor;
                                    continue;
                                }
                            }

                            Console.ForegroundColor = (peFile.Is32Bit) ? ConsoleColor.Blue : ConsoleColor.Yellow;
                            Console.WriteLine("\t[+] [" + ((peFile.Is32Bit) ? "32-bit" : "64-bit") + "] - User can modify: " + l_dllpath);
                            Console.ForegroundColor = originalColor;
                        } catch(DirectoryNotFoundException)
                        {
                            continue;
                        }

                    }
                    
                }
            }

            Console.WriteLine("\n\nAdd this to your CNA config: (NOTE: SOME WINDOWS INSTANCES ARE SET TO CASE SENSITIVE)");
            string homeDir = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            Console.WriteLine("$progArray = array(");
            var cnas = cnaList.Distinct().ToList();
            for (int x = 0; x < cnas.Count; x++)
            {
                if (char.IsLower(cnas[x][0]))
                {
                    cnas[x] = char.ToUpper(cnas[x][0]) + cnas[x].Substring(1);

                }
                cnas[x] = cnas[x].Replace(homeDir, @"C:\Users\SOMEDUALITYUSER");
                cnas[x] = cnas[x].Replace("\\", "\\\\");
                Console.WriteLine("\"" + cnas[x] + ((x == cnas.Count - 1) ? "\")" : "\","));
            }
            Console.WriteLine("\n\n");
        }
    }
}

