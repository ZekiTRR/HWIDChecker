using System;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;


namespace HWIDChecker;

class DiskSerialReader
{
    // Код управления IOCTL для запроса свойств хранилища
    const uint IOCTL_STORAGE_QUERY_PROPERTY = 0x002D1400;

    // Константы для открытия файла/устройства
    const uint FILE_SHARE_READ = 0x00000001;
    const uint FILE_SHARE_WRITE = 0x00000002;
    const uint OPEN_EXISTING = 3;

    // Структура запроса (в C++ её размер с выравниванием равен 12 байтам)
    [StructLayout(LayoutKind.Sequential, Size = 12)]
    struct STORAGE_PROPERTY_QUERY
    {
        public uint PropertyId; // 0 = StorageDeviceProperty
        public uint QueryType; // 0 = PropertyStandardQuery
    }

    // Структура заголовка ответа (фиксированная часть)
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
        public uint SerialNumberOffset; // Смещение до серийного номера в байтах
        public byte BusType;
        public uint RawPropertiesLength;
    }

    // Импорт функций Win32 API
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

        // 1. Открываем хэндл диска (Доступ 0 достаточен для базовых IOCTL запросов)
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
                throw new Exception(
                    $"Не удалось открыть диск. Код ошибки: {Marshal.GetLastWin32Error()}. Запустите от имени Администратора.");
            }

            // 2. Инициализируем структуру запроса
            STORAGE_PROPERTY_QUERY query = new STORAGE_PROPERTY_QUERY
            {
                PropertyId = 0, // StorageDeviceProperty
                QueryType = 0 // PropertyStandardQuery
            };

            // 3. Выделяем буфер в неуправляемой памяти (1024 байт точно хватит для структуры + строк)
            uint bufferSize = 1024;
            IntPtr bufferPtr = Marshal.AllocHGlobal((int)bufferSize);

            try
            {
                // 4. Посылаем IOCTL драйверу диска
                if (DeviceIoControl(
                        hDevice, // Получили в CreateFile
                        IOCTL_STORAGE_QUERY_PROPERTY,
                        ref query,
                        12, // Фиксированный размер структуры запроса
                        bufferPtr,
                        bufferSize,
                        out uint bytesReturned,
                        IntPtr.Zero))
                {
                    // Маршалим заголовок из памяти в структуру C#
                    var descriptor = Marshal.PtrToStructure<STORAGE_DEVICE_DESCRIPTOR>(bufferPtr);

                    // 5. Проверяем, вернул ли драйвер смещение для серийника
                    if (descriptor.SerialNumberOffset != 0 && descriptor.SerialNumberOffset < descriptor.Size)
                    {
                        // Сдвигаем указатель на количество байт, указанных в SerialNumberOffset
                        IntPtr serialPtr = IntPtr.Add(bufferPtr, (int)descriptor.SerialNumberOffset);

                        // Читаем как обычную null-terminated ANSI строку
                        string serial = Marshal.PtrToStringAnsi(serialPtr);
                        return serial?.Trim();
                    }

                    return "Серийный номер не предоставлен устройством.";
                }
                else
                {
                    throw new Exception($"DeviceIoControl завершился с ошибкой: {Marshal.GetLastWin32Error()}");
                }
            }
            finally
            {
                // Обязательно освобождаем выделенную память
                Marshal.FreeHGlobal(bufferPtr);
            }
        }
    }
}

class Program
{
    static void Main(string[] args)
    {
        try
        {
            string serial = DiskSerialReader.GetDiskSerial(1); // Получаем серийник первого диска
            Console.WriteLine($"Серийный номер диска: {serial}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Ошибка: {ex.Message}");
        }
    }
}