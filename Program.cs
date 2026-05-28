using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace HWIDChecker
{
    // Алиасы типов из Windows SDK для корректного маршаллинга в C#
    using IF_INDEX = System.UInt32;
    using PCHAR = System.IntPtr;   // char* в C++ (указатель на ANSI строку)
    using PWCHAR = System.IntPtr;  // wchar_t* в C++ (указатель на Unicode строку)
    

    public static class NetworkConstants
    {
        public const int MAX_ADAPTER_ADDRESS_LENGTH = 8;
        public const int MAX_DHCPV6_DUID_LENGTH = 130;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct InsideStruct
    {
        public uint Length;
        public IF_INDEX IfIndex;
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct AdapterAlignmentUnion
    {
        [FieldOffset(0)] public ulong Alignment;
        [FieldOffset(0)] public InsideStruct Nested;
        }

    [StructLayout(LayoutKind.Sequential)]
    public struct SOCKET_ADDRESS
    {
        public IntPtr lpSockaddr;
        public int iSockaddrLength;
    }



    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct IP_ADAPTER_ADDRESSES_LH
    {
        // Union (Alignment / Length + IfIndex)
        public AdapterAlignmentUnion AlignmentUnion;

        // Указатель на следующую структуру в списке (struct _IP_ADAPTER_ADDRESSES_LH*)
        public IntPtr Next;

        // PCHAR - указатель на имя адаптера (строка ANSI, содержит системный GUID)
        public PCHAR AdapterName;

        // Указатели на связанные списки адресов (PIP_...)
        public IntPtr FirstUnicastAddress;
        public IntPtr FirstAnycastAddress;
        public IntPtr FirstMulticastAddress;
        public IntPtr FirstDnsServerAddress;

        // Строки Unicode (PWCHAR)
        public PWCHAR DnsSuffix;
        public PWCHAR Description;
        public PWCHAR FriendlyName;

        // ТЕКУЩИЙ MAC-АДРЕС (Считывается из реестра/минипорта при инициализации)
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = NetworkConstants.MAX_ADAPTER_ADDRESS_LENGTH)]
        public byte[] PhysicalAddress;
        public uint PhysicalAddressLength;

        // Union флагов: Flags / Битовые поля (занимает ровно 4 байта)
        public uint Flags;

        public uint Mtu;
        public uint IfType;           // IFTYPE (enum/uint)
        public int OperStatus;        // IF_OPER_STATUS (enum/int)
        public uint Ipv6IfIndex;      // IF_INDEX

        // Массив индексов зон
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public uint[] ZoneIndices;

        public IntPtr FirstPrefix;

        // Скоростные характеристики линка
        public ulong TransmitLinkSpeed;
        public ulong ReceiveLinkSpeed;

        // Дополнительные указатели на адреса
        public IntPtr FirstWinsServerAddress;
        public IntPtr FirstGatewayAddress;

        public uint Ipv4Metric;
        public uint Ipv6Metric;

        // LUID устройства (8 байт)
        public ulong Luid; 
        
        public SOCKET_ADDRESS Dhcpv4Server;
        public uint CompartmentId;     // NET_IF_COMPARTMENT_ID
        public Guid NetworkGuid;       // NET_IF_NETWORK_GUID (16 байт)
        public int ConnectionType;     // NET_IF_CONNECTION_TYPE
        public int TunnelType;         // TUNNEL_TYPE
        
        public SOCKET_ADDRESS Dhcpv6Server;

        // Данные DHCPv6 DUID
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = NetworkConstants.MAX_DHCPV6_DUID_LENGTH)]
        public byte[] Dhcpv6ClientDuid;
        public uint Dhcpv6ClientDuidLength;
        public uint Dhcpv6Iaid;

        public IntPtr FirstDnsSuffix;
    }



    class DiskSerialReader
    {
        const uint IOCTL_STORAGE_QUERY_PROPERTY = 0x002D1400;
        const uint FILE_SHARE_READ = 0x00000001;
        const uint FILE_SHARE_WRITE = 0x00000002;
        const uint OPEN_EXISTING = 3;

        [StructLayout(LayoutKind.Sequential, Size = 12)]
        struct STORAGE_PROPERTY_QUERY
        {
            public uint PropertyId; 
            public uint QueryType; 
        }

        [StructLayout(LayoutKind.Sequential)]
        struct STORAGE_DEVICE_DESCRIPTOR
        {
            public uint Version;
            public uint Size;
            public byte DeviceType;
            public byte DeviceTypeModifier;
            [MarshalAs(UnmanagedType.U1)] public bool RemovableMedia;
            [MarshalAs(UnmanagedType.U1)] public bool CommandQueueing;
            public uint VendorIdOffset;
            public uint ProductIdOffset;
            public uint ProductRevisionOffset;
            public uint SerialNumberOffset; // Смещение до строки серийника в байтах
            public byte BusType;
            public uint RawPropertiesLength;
        }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern SafeFileHandle CreateFile(
            string lpFileName,
            uint dwDesiredAccess,
            uint dwShareMode,
            IntPtr lpSecurityAttributes,
            uint dwCreationDisposition,
            uint dwFlagsAndAttributes,
            IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool DeviceIoControl(
            SafeFileHandle hDevice,
            uint dwIoControlCode,
            ref STORAGE_PROPERTY_QUERY lpInBuffer,
            uint nInBufferSize,
            IntPtr lpOutBuffer,
            uint nOutBufferSize,
            out uint lpBytesReturned,
            IntPtr lpOverlapped);

        public static string GetDiskSerial(int driveIndex = 0)
        {
            string drivePath = $@"\\.\PhysicalDrive{driveIndex}";

            using (SafeFileHandle hDevice = CreateFile(
                       drivePath,
                       0,
                       FILE_SHARE_READ | FILE_SHARE_WRITE,
                       IntPtr.Zero,
                       OPEN_EXISTING,
                       0,
                       IntPtr.Zero))
            {
                if (hDevice.IsInvalid)
                {
                    throw new Exception($"Не удалось открыть диск. Код ошибки Win32: {Marshal.GetLastWin32Error()}. Требуются права Администратора.");
                }

                STORAGE_PROPERTY_QUERY query = new STORAGE_PROPERTY_QUERY
                {
                    PropertyId = 0, // StorageDeviceProperty
                    QueryType = 0  // PropertyStandardQuery
                };

                uint bufferSize = 1024;
                IntPtr bufferPtr = Marshal.AllocHGlobal((int)bufferSize);

                try
                {
                    if (DeviceIoControl(hDevice, IOCTL_STORAGE_QUERY_PROPERTY, ref query, 12, bufferPtr, bufferSize, out uint bytesReturned, IntPtr.Zero))
                    {
                        var descriptor = Marshal.PtrToStructure<STORAGE_DEVICE_DESCRIPTOR>(bufferPtr);

                        if (descriptor.SerialNumberOffset != 0 && descriptor.SerialNumberOffset < descriptor.Size)
                        {
                            IntPtr serialPtr = IntPtr.Add(bufferPtr, (int)descriptor.SerialNumberOffset);
                            string serial = Marshal.PtrToStringAnsi(serialPtr);
                            return serial?.Trim();
                        }

                        return "Серийный номер не предоставлен устройством.";
                    }
                    else
                    {
                        throw new Exception($"DeviceIoControl завершился с ошибкой Win32: {Marshal.GetLastWin32Error()}");
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(bufferPtr);
                }
            }
        }
    }
    

    class MacAddressReader
    {
        [DllImport("iphlpapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern uint GetAdaptersAddresses(
            uint Family,
            uint Flags,
            IntPtr Reserved,
            IntPtr AdapterAddresses,
            ref uint SizePointer);

        const uint AF_UNSPEC = 0;             // Получать IPv4 и IPv6 интерфейсы
        const uint GAA_FLAG_DEFAULT = 0x0000;   // Флаг вызова по умолчанию
        
        const uint ERROR_SUCCESS = 0;
        const uint ERROR_BUFFER_OVERFLOW = 111;
// https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--0-499-
        
        public static void PrintMacAddresses()
        {
            uint bufferSize = 0;
            
            // 1. Узнаем требуемый размер буфера памяти (первый вызов всегда вернет код 111)
            uint result = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_DEFAULT, IntPtr.Zero, IntPtr.Zero, ref bufferSize);

            if (result != ERROR_BUFFER_OVERFLOW)
            {
                throw new Exception($"Не удалось рассчитать размер буфера адаптеров. Код Win32: {result}");
            }

            // 2. Выделяем память в неуправляемой куче под связный список структур
            IntPtr bufferPtr = Marshal.AllocHGlobal((int)bufferSize);

            try
            {
                // 3. Заполняем память реальными данными сетевых карт
                result = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_DEFAULT, IntPtr.Zero, bufferPtr, ref bufferSize);

                if (result != ERROR_SUCCESS)
                {
                    throw new Exception($"Ошибка получения данных адаптеров. Код Win32: {result}");
                }

                // 4. Проходим по связному списку в памяти, начиная с головы (head)
                IntPtr currentAdapterPtr = bufferPtr;

                Console.WriteLine("\n=== Сетевые Адаптеры (Current MAC) ===");

                while (currentAdapterPtr != IntPtr.Zero)
                {
                    // Маршалим сырую память по текущему адресу в управляемую структуру C#
                    var adapter = Marshal.PtrToStructure<IP_ADAPTER_ADDRESSES_LH>(currentAdapterPtr);

                    // Проверяем длину адреса (пропускаем софтверные "пустышки" без MAC-адреса)
                    if (adapter.PhysicalAddressLength > 0)
                    {
                        // Переводим байтовый массив MAC-адреса в Hex-строку (AA:BB:CC...)
                        string[] macBytes = new string[adapter.PhysicalAddressLength];
                        for (int i = 0; i < adapter.PhysicalAddressLength; i++)
                        {
                            macBytes[i] = adapter.PhysicalAddress[i].ToString("X2");
                        }
                        string currentMac = string.Join(":", macBytes);

                        // Читаем строки из памяти по указателям типов PCHAR и PWCHAR
                        string adapterGuid = Marshal.PtrToStringAnsi(adapter.AdapterName);
                        string friendlyName = Marshal.PtrToStringUni(adapter.FriendlyName);
                        string description = Marshal.PtrToStringUni(adapter.Description);

                        // Вывод результатов в консоль
                        Console.WriteLine($"\nИмя интерфейса : {friendlyName}");
                        Console.WriteLine($"Описание       : {description}");
                        Console.WriteLine($"GUID (Класс)   : {adapterGuid}");
                        Console.WriteLine($"Current MAC    : {currentMac}");
                        Console.WriteLine($"IfIndex        : {adapter.AlignmentUnion.Nested.IfIndex}");
                        Console.WriteLine(new string('-', 50));
                    }

                    // Переходим к следующему узлу списка (сдвигаем указатель на адрес, хранящийся в поле Next)
                    currentAdapterPtr = adapter.Next;
                }
            }
            finally
            {
                // 5. Очищаем выделенную память, предотвращая утечку ресурсов приложения
                Marshal.FreeHGlobal(bufferPtr);
            }
        }
    }


    public static class GpuCheckerSmi
    {
        public static string GetGpuUuid()
        {
            string smiPath = @"C:\Windows\System32\nvidia-smi.exe";
        
            if (!File.Exists(smiPath))
                return "NVIDIA_SMI_NOT_INSTALLED";

            try
            {
                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = smiPath,
                    Arguments = "-L",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using (Process process = Process.Start(psi))
                {
                    if (process == null) return "FAILED_TO_START_PROCESS";

                    // Читаем весь текст, который вывела консоль
                    string output = process.StandardOutput.ReadToEnd();
                    process.WaitForExit();

                    // Ищем маркер "UUID: "
                    int uuidIndex = output.IndexOf("UUID: ");
                    if (uuidIndex != -1)
                    {
                        int start = uuidIndex + 6; // Смещение сразу после "UUID: "
                        int end = output.IndexOf(")", start);
                    
                        if (end != -1)
                        {
                            return output.Substring(start, end - start).Trim();
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                return $"ERROR: {ex.Message}";
            }

            return "UUID_NOT_FOUND_IN_OUTPUT";
        }
    }
    
    
    
    class Program
    {
        static void Main(string[] args)
        {
            // Устанавливаем UTF-8 для корректного вывода русских названий сетевых карт
            Console.OutputEncoding = Encoding.UTF8; 
            
            try
            {
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine("======================================================");
                Console.WriteLine("          HWID INFORMATION DETECTOR                   ");
                Console.WriteLine("======================================================");
                Console.ResetColor();
                
                // ЭТАП 1: Проверка физического диска (Серийный номер)
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("\n[+] Сбор данных дисковой подсистемы...");
                Console.ResetColor();
                
                try 
                {
                    string serial = DiskSerialReader.GetDiskSerial(0); 
                    Console.WriteLine($"Серийный номер Drive [0]: {serial}");
                }
                catch (Exception diskEx)
                {
                    Console.ForegroundColor = ConsoleColor.DarkYellow;
                    Console.WriteLine($"[-] Ошибка Drive [0]: {diskEx.Message}");
                    Console.ResetColor();
                }

                // ЭТАП 2: Проверка сетевых адаптеров через NDIS API списка памяти
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("\n[+] Сбор данных сетевых адаптеров...");
                Console.ResetColor();
                
                MacAddressReader.PrintMacAddresses();
                
                
                // ЭТАП 3: Проверка серийного номера видеокарты
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("\n[+] Серийный номер видеокарты NVIDIA");
                Console.ResetColor();

                Console.WriteLine(GpuCheckerSmi.GetGpuUuid());
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"\n[КРИТИЧЕСКАЯ ОШИБКА]: {ex.Message}");
                Console.ResetColor();
            }
            
            Console.ForegroundColor = ConsoleColor.Gray;
            Console.WriteLine("\nСканирование завершено. Нажмите Enter для выхода...");
            Console.ResetColor();
            Console.ReadLine();
        }
    }


}