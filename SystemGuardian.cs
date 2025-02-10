using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace SystemGuardian
{
    public class GuardianService : ServiceBase
    {
        #region Native Methods
        private static class NativeMethods
        {
            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern bool InitializeSecurityDescriptor(out SECURITY_DESCRIPTOR sd, uint dwRevision);

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern bool SetSecurityDescriptorDacl(ref SECURITY_DESCRIPTOR sd, bool daclPresent, IntPtr dacl, bool daclDefaulted);

            [DllImport("kernel32.dll")]
            public static extern IntPtr GetCurrentProcess();

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern bool GetTokenInformation(IntPtr TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, IntPtr TokenInformation, uint TokenInformationLength, out uint ReturnLength);

            [StructLayout(LayoutKind.Sequential)]
            public struct SECURITY_DESCRIPTOR
            {
                public byte Revision;
                public byte Sbz1;
                public ushort Control;
                public IntPtr Owner;
                public IntPtr Group;
                public IntPtr Sacl;
                public IntPtr Dacl;
            }

            public enum TOKEN_INFORMATION_CLASS
            {
                TokenUser = 1,
                TokenGroups,
                TokenPrivileges,
                TokenOwner,
                TokenPrimaryGroup,
                TokenDefaultDacl,
                TokenSource,
                TokenType,
                TokenImpersonationLevel,
                TokenStatistics,
                TokenRestrictedSids,
                TokenSessionId,
                TokenGroupsAndPrivileges,
                TokenSessionReference,
                TokenSandBoxInert,
                TokenAuditPolicy,
                TokenOrigin,
                TokenElevationType,
                TokenLinkedToken,
                TokenElevation,
                TokenHasRestrictions,
                TokenAccessInformation,
                TokenVirtualizationAllowed,
                TokenVirtualizationEnabled,
                TokenIntegrityLevel,
                TokenUIAccess,
                TokenMandatoryPolicy,
                TokenLogonSid,
                MaxTokenInfoClass
            }
        }
        #endregion

        #region Constants and Fields
        private const string ServiceName = "SystemGuardian";
        private const string EventLogSource = "SystemGuardian";
        private const string EventLogName = "Application";
        private readonly string BaseDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SystemGuardian");
        private readonly string LogDirectory;
        private readonly string RecoveryDirectory;
        private readonly string BackupDirectory;

        private CancellationTokenSource _cancellationTokenSource;
        private readonly ConcurrentDictionary<string, ComponentInfo> _monitoredComponents;
        private readonly BlockingCollection<SystemEvent> _eventQueue;
        private readonly HashSet<string> _criticalPaths;
        private readonly ManagementEventWatcher _registryWatcher;
        private readonly ManagementEventWatcher _deviceWatcher;
        private readonly FileSystemWatcher _systemWatcher;
        private volatile bool _isInitialized;
        #endregion

        #region Data Structures
        private class ComponentInfo
        {
            public string Path { get; set; }
            public string Hash { get; set; }
            public DateTime LastModified { get; set; }
            public ComponentType Type { get; set; }
            public ComponentStatus Status { get; set; }
            public Dictionary<string, string> Metadata { get; set; }
        }

        private class SystemEvent
        {
            public DateTime Timestamp { get; set; }
            public EventType Type { get; set; }
            public string Source { get; set; }
            public string Description { get; set; }
            public EventSeverity Severity { get; set; }
        }

        private enum ComponentType
        {
            Driver,
            Service,
            SystemFile,
            RegistryKey
        }

        private enum ComponentStatus
        {
            Normal,
            Warning,
            Critical,
            Isolated
        }

        private enum EventType
        {
            SystemChange,
            SecurityEvent,
            PerformanceIssue,
            ComponentFailure
        }

        private enum EventSeverity
        {
            Information,
            Warning,
            Error,
            Critical
        }
        #endregion

        public GuardianService()
        {
            ServiceName = ServiceName;
            CanStop = true;
            CanShutdown = true;
            CanPauseAndContinue = false;
            AutoLog = false;

            LogDirectory = Path.Combine(BaseDirectory, "Logs");
            RecoveryDirectory = Path.Combine(BaseDirectory, "Recovery");
            BackupDirectory = Path.Combine(BaseDirectory, "Backups");

            _monitoredComponents = new ConcurrentDictionary<string, ComponentInfo>();
            _eventQueue = new BlockingCollection<SystemEvent>();
            _criticalPaths = new HashSet<string>
            {
                @"C:\Windows\System32\drivers",
                @"C:\Windows\System32",
                @"C:\Windows\SysWOW64"
            };

            InitializeEnvironment();
            InitializeEventLog();
            InitializeWatchers();
        }

        private void InitializeEnvironment()
        {
            try
            {
                Directory.CreateDirectory(BaseDirectory);
                Directory.CreateDirectory(LogDirectory);
                Directory.CreateDirectory(RecoveryDirectory);
                Directory.CreateDirectory(BackupDirectory);

                // Set secure permissions
                var directorySecurity = new DirectorySecurity();
                directorySecurity.SetAccessRuleProtection(true, false);
                var rule = new FileSystemAccessRule(
                    new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                    FileSystemRights.FullControl,
                    InheritanceFlags.ObjectInherit | InheritanceFlags.ContainerInherit,
                    PropagationFlags.None,
                    AccessControlType.Allow);
                directorySecurity.AddAccessRule(rule);

                Directory.SetAccessControl(BaseDirectory, directorySecurity);
                _isInitialized = true;
            }
            catch (Exception ex)
            {
                LogEvent($"Failed to initialize environment: {ex.Message}", EventLogEntryType.Error);
                throw;
            }
        }

        private void InitializeEventLog()
        {
            try
            {
                if (!EventLog.SourceExists(EventLogSource))
                {
                    EventLog.CreateEventSource(EventLogSource, EventLogName);
                }
            }
            catch (Exception ex)
            {
                LogEvent($"Failed to initialize event log: {ex.Message}", EventLogEntryType.Error);
                throw;
            }
        }

        private void InitializeWatchers()
        {
            try
            {
                // Initialize Registry Watcher
                _registryWatcher = new ManagementEventWatcher(
                    new WqlEventQuery("SELECT * FROM RegistryTreeChangeEvent WHERE Hive='HKEY_LOCAL_MACHINE'"));
                _registryWatcher.EventArrived += RegistryChangeDetected;

                // Initialize Device Watcher
                _deviceWatcher = new ManagementEventWatcher(
                    new WqlEventQuery("SELECT * FROM Win32_DeviceChangeEvent"));
                _deviceWatcher.EventArrived += DeviceChangeDetected;

                // Initialize File System Watcher
                _systemWatcher = new FileSystemWatcher();
                _systemWatcher.NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.FileName | NotifyFilters.DirectoryName;
                _systemWatcher.Changed += FileSystemChangeDetected;
                _systemWatcher.Created += FileSystemChangeDetected;
                _systemWatcher.Deleted += FileSystemChangeDetected;
                _systemWatcher.Error += FileSystemWatcherError;
            }
            catch (Exception ex)
            {
                LogEvent($"Failed to initialize watchers: {ex.Message}", EventLogEntryType.Error);
                throw;
            }
        }

        protected override void OnStart(string[] args)
        {
            try
            {
                if (!_isInitialized)
                {
                    throw new InvalidOperationException("Service not properly initialized");
                }

                _cancellationTokenSource = new CancellationTokenSource();
                LogEvent("Service starting...", EventLogEntryType.Information);

                // Start monitoring tasks
                Task.Run(() => MonitorSystem(_cancellationTokenSource.Token), _cancellationTokenSource.Token);
                Task.Run(() => ProcessEventQueue(_cancellationTokenSource.Token), _cancellationTokenSource.Token);

                // Start watchers
                _registryWatcher.Start();
                _deviceWatcher.Start();
                foreach (var path in _criticalPaths)
                {
                    if (Directory.Exists(path))
                    {
                        _systemWatcher.Path = path;
                        _systemWatcher.EnableRaisingEvents = true;
                    }
                }

                // Create initial system snapshot
                CreateSystemSnapshot();

                LogEvent("Service started successfully", EventLogEntryType.Information);
            }
            catch (Exception ex)
            {
                LogEvent($"Service failed to start: {ex.Message}", EventLogEntryType.Error);
                Stop();
            }
        }

        protected override void OnStop()
        {
            try
            {
                LogEvent("Service stopping...", EventLogEntryType.Information);

                _cancellationTokenSource?.Cancel();
                _registryWatcher?.Stop();
                _deviceWatcher?.Stop();
                _systemWatcher.EnableRaisingEvents = false;

                // Cleanup and final backup
                CreateSystemSnapshot("FinalSnapshot");
                CleanupOldRecoveryPoints();

                LogEvent("Service stopped successfully", EventLogEntryType.Information);
            }
            catch (Exception ex)
            {
                LogEvent($"Error during service shutdown: {ex.Message}", EventLogEntryType.Error);
            }
            finally
            {
                _cancellationTokenSource?.Dispose();
                _registryWatcher?.Dispose();
                _deviceWatcher?.Dispose();
                _systemWatcher?.Dispose();
            }
        }

        private async Task MonitorSystem(CancellationToken cancellationToken)
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    await Task.WhenAll(
                        MonitorSystemPerformance(cancellationToken),
                        MonitorServiceHealth(cancellationToken),
                        VerifySystemIntegrity(cancellationToken)
                    );

                    await Task.Delay(TimeSpan.FromMinutes(5), cancellationToken);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    LogEvent($"System monitoring error: {ex.Message}", EventLogEntryType.Error);
                    await Task.Delay(TimeSpan.FromMinutes(1), cancellationToken);
                }
            }
        }

        private async Task MonitorSystemPerformance(CancellationToken cancellationToken)
        {
            var cpuCounter = new PerformanceCounter("Processor", "% Processor Time", "_Total");
            var memoryCounter = new PerformanceCounter("Memory", "Available MBytes");

            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    var cpuUsage = cpuCounter.NextValue();
                    var availableMemory = memoryCounter.NextValue();

                    if (cpuUsage > 90 || availableMemory < 500)
                    {
                        _eventQueue.Add(new SystemEvent
                        {
                            Timestamp = DateTime.UtcNow,
                            Type = EventType.PerformanceIssue,
                            Source = "System Performance",
                            Description = $"High resource usage - CPU: {cpuUsage}%, Available Memory: {availableMemory}MB",
                            Severity = EventSeverity.Warning
                        });
                    }

                    await Task.Delay(TimeSpan.FromSeconds(30), cancellationToken);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    LogEvent($"Performance monitoring error: {ex.Message}", EventLogEntryType.Error);
                    await Task.Delay(TimeSpan.FromMinutes(1), cancellationToken);
                }
            }
        }

        private async Task MonitorServiceHealth(CancellationToken cancellationToken)
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    foreach (var service in ServiceController.GetServices())
                    {
                        var componentKey = $"Service_{service.ServiceName}";
                        if (!_monitoredComponents.ContainsKey(componentKey))
                        {
                            _monitoredComponents.TryAdd(componentKey, new ComponentInfo
                            {
                                Path = service.ServiceName,
                                Type = ComponentType.Service,
                                Status = ComponentStatus.Normal,
                                Metadata = new Dictionary<string, string>
                                {
                                    { "DisplayName", service.DisplayName },
                                    { "StartType", service.StartType.ToString() }
                                }
                            });
                        }

                        if (service.Status == ServiceControllerStatus.Stopped &&
                            service.StartType == ServiceStartMode.Automatic)
                        {
                            _eventQueue.Add(new SystemEvent
                            {
                                Timestamp = DateTime.UtcNow,
                                Type = EventType.ComponentFailure,
                                Source = $"Service_{service.ServiceName}",
                                Description = $"Automatic service {service.DisplayName} is stopped",
                                Severity = EventSeverity.Warning
                            });

                            await AttemptServiceRecovery(service);
                        }
                    }

                    await Task.Delay(TimeSpan.FromMinutes(1), cancellationToken);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    LogEvent($"Service health monitoring error: {ex.Message}", EventLogEntryType.Error);
                    await Task.Delay(TimeSpan.FromMinutes(1), cancellationToken);
                }
            }
        }

        private async Task VerifySystemIntegrity(CancellationToken cancellationToken)
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    foreach (var component in _monitoredComponents)
                    {
                        if (component.Value.Type == ComponentType.SystemFile ||
                            component.Value.Type == ComponentType.Driver)
                        {
                            if (File.Exists(component.Value.Path))
                        {
                            var currentHash = CalculateFileHash(component.Value.Path);
                            var lastModified = File.GetLastWriteTimeUtc(component.Value.Path);

                            if (currentHash != component.Value.Hash ||
                                lastModified != component.Value.LastModified)
                            {
                                _eventQueue.Add(new SystemEvent
                                {
                                    Timestamp = DateTime.UtcNow,
                                    Type = EventType.SystemChange,
                                    Source = component.Key,
                                    Description = $"File integrity change detected: {component.Value.Path}",
                                    Severity = EventSeverity.Warning
                                });

                                // Update component information
                                component.Value.Hash = currentHash;
                                component.Value.LastModified = lastModified;
                                await VerifyComponentSignature(component.Value);
                            }
                        }
                        else
                        {
                            _eventQueue.Add(new SystemEvent
                            {
                                Timestamp = DateTime.UtcNow,
                                Type = EventType.ComponentFailure,
                                Source = component.Key,
                                Description = $"Monitored component missing: {component.Value.Path}",
                                Severity = EventSeverity.Critical
                            });

                            await AttemptComponentRecovery(component.Key);
                        }
                    }

                    await Task.Delay(TimeSpan.FromMinutes(15), cancellationToken);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    LogEvent($"System integrity verification error: {ex.Message}", EventLogEntryType.Error);
                    await Task.Delay(TimeSpan.FromMinutes(1), cancellationToken);
                }
            }
        }

        private async Task ProcessEventQueue(CancellationToken cancellationToken)
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    if (_eventQueue.TryTake(out SystemEvent evt, 1000, cancellationToken))
                    {
                        await HandleSystemEvent(evt);
                    }
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    LogEvent($"Event processing error: {ex.Message}", EventLogEntryType.Error);
                }
            }
        }

        private async Task HandleSystemEvent(SystemEvent evt)
        {
            try
            {
                // Log the event
                LogEvent(evt.Description, MapSeverityToEventLogEntryType(evt.Severity));

                // Take action based on event type and severity
                switch (evt.Type)
                {
                    case EventType.ComponentFailure:
                        if (evt.Severity >= EventSeverity.Error)
                        {
                            await CreateRecoveryPoint($"Pre-recovery_{evt.Source}");
                            await AttemptComponentRecovery(evt.Source);
                        }
                        break;

                    case EventType.SecurityEvent:
                        if (evt.Severity >= EventSeverity.Warning)
                        {
                            await CreateRecoveryPoint($"Security_{evt.Source}");
                            if (evt.Severity >= EventSeverity.Critical)
                            {
                                await IsolateComponent(evt.Source);
                            }
                        }
                        break;

                    case EventType.SystemChange:
                        if (evt.Severity >= EventSeverity.Warning)
                        {
                            await ValidateSystemChange(evt.Source);
                        }
                        break;

                    case EventType.PerformanceIssue:
                        if (evt.Severity >= EventSeverity.Error)
                        {
                            await AttemptPerformanceRecovery();
                        }
                        break;
                }
            }
            catch (Exception ex)
            {
                LogEvent($"Error handling event {evt.Type} from {evt.Source}: {ex.Message}", EventLogEntryType.Error);
            }
        }

        private async Task ValidateSystemChange(string componentKey)
        {
            if (_monitoredComponents.TryGetValue(componentKey, out var component))
            {
                try
                {
                    bool isValid = await VerifyComponentSignature(component);
                    if (!isValid)
                    {
                        _eventQueue.Add(new SystemEvent
                        {
                            Timestamp = DateTime.UtcNow,
                            Type = EventType.SecurityEvent,
                            Source = componentKey,
                            Description = "Invalid signature detected on changed component",
                            Severity = EventSeverity.Critical
                        });
                    }
                }
                catch (Exception ex)
                {
                    LogEvent($"Change validation error for {componentKey}: {ex.Message}", EventLogEntryType.Error);
                }
            }
        }

        private async Task AttemptComponentRecovery(string componentKey)
        {
            if (_monitoredComponents.TryGetValue(componentKey, out var component))
            {
                try
                {
                    switch (component.Type)
                    {
                        case ComponentType.Driver:
                            await RecoverDriver(component);
                            break;

                        case ComponentType.Service:
                            await RecoverService(component);
                            break;

                        case ComponentType.SystemFile:
                            await RecoverSystemFile(component);
                            break;

                        case ComponentType.RegistryKey:
                            await RecoverRegistryKey(component);
                            break;
                    }
                }
                catch (Exception ex)
                {
                    LogEvent($"Recovery failed for {componentKey}: {ex.Message}", EventLogEntryType.Error);
                }
            }
        }

        private async Task RecoverDriver(ComponentInfo component)
        {
            try
            {
                // Attempt to restore from backup
                var backupPath = Path.Combine(BackupDirectory, Path.GetFileName(component.Path));
                if (File.Exists(backupPath))
                {
                    if (await VerifyComponentSignature(new ComponentInfo { Path = backupPath, Type = ComponentType.Driver }))
                    {
                        File.Copy(backupPath, component.Path, true);
                        await ReloadDriver(component.Path);
                    }
                }
                else
                {
                    // Attempt to restore from Windows Driver Store
                    await RestoreFromDriverStore(component.Path);
                }
            }
            catch (Exception ex)
            {
                throw new Exception($"Driver recovery failed: {ex.Message}", ex);
            }
        }

        private async Task RecoverService(ComponentInfo component)
        {
            try
            {
                using (var service = new ServiceController(component.Path))
                {
                    if (service.Status == ServiceControllerStatus.Stopped)
                    {
                        service.Start();
                        await Task.Delay(TimeSpan.FromSeconds(30));
                        
                        if (service.Status != ServiceControllerStatus.Running)
                        {
                            throw new Exception($"Service failed to start: {component.Path}");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                throw new Exception($"Service recovery failed: {ex.Message}", ex);
            }
        }

        private async Task RecoverSystemFile(ComponentInfo component)
        {
            try
            {
                // Attempt to restore from backup
                var backupPath = Path.Combine(BackupDirectory, Path.GetFileName(component.Path));
                if (File.Exists(backupPath))
                {
                    if (await VerifyComponentSignature(new ComponentInfo { Path = backupPath, Type = ComponentType.SystemFile }))
                    {
                        File.Copy(backupPath, component.Path, true);
                    }
                }
                else
                {
                    // Attempt to restore from Windows Component Store
                    var process = new Process
                    {
                        StartInfo = new ProcessStartInfo
                        {
                            FileName = "DISM.exe",
                            Arguments = $"/Online /Cleanup-Image /RestoreHealth /StartComponentCleanup",
                            UseShellExecute = false,
                            RedirectStandardOutput = true,
                            CreateNoWindow = true
                        }
                    };
                    process.Start();
                    await process.WaitForExitAsync();
                }
            }
            catch (Exception ex)
            {
                throw new Exception($"System file recovery failed: {ex.Message}", ex);
            }
        }

        private async Task RecoverRegistryKey(ComponentInfo component)
        {
            try
            {
                // Attempt to restore from last known good configuration
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "reg.exe",
                        Arguments = $"restore \"{component.Path}\" \"{Path.Combine(BackupDirectory, "registry.bak")}\"",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        CreateNoWindow = true
                    }
                };
                process.Start();
                await process.WaitForExitAsync();
            }
            catch (Exception ex)
            {
                throw new Exception($"Registry recovery failed: {ex.Message}", ex);
            }
        }

        private async Task AttemptPerformanceRecovery()
        {
            try
            {
                // Analyze and terminate resource-heavy processes
                var processes = Process.GetProcesses()
                    .Where(p => !string.IsNullOrEmpty(p.ProcessName))
                    .Select(p => new
                    {
                        Process = p,
                        CpuUsage = GetProcessCpuUsage(p),
                        MemoryUsage = p.WorkingSet64 / (1024 * 1024) // MB
                    })
                    .Where(p => p.CpuUsage > 80 || p.MemoryUsage > 1000)
                    .ToList();

                foreach (var proc in processes)
                {
                    _eventQueue.Add(new SystemEvent
                    {
                        Timestamp = DateTime.UtcNow,
                        Type = EventType.PerformanceIssue,
                        Source = proc.Process.ProcessName,
                        Description = $"High resource usage - CPU: {proc.CpuUsage}%, Memory: {proc.MemoryUsage}MB",
                        Severity = EventSeverity.Warning
                    });
                }

                // Clean up temporary files
                await CleanupTemporaryFiles();
            }
            catch (Exception ex)
            {
                LogEvent($"Performance recovery failed: {ex.Message}", EventLogEntryType.Error);
            }
        }

        #region Helper Methods
        private string CalculateFileHash(string filePath)
        {
            using (var sha256 = SHA256.Create())
            using (var stream = File.OpenRead(filePath))
            {
                var hash = sha256.ComputeHash(stream);
                return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
            }
        }

        private async Task<bool> VerifyComponentSignature(ComponentInfo component)
        {
            try
            {
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "signtool.exe",
                        Arguments = $"verify /pa \"{component.Path}\"",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        CreateNoWindow = true
                    }
                };
                process.Start();
                await process.WaitForExitAsync();
                return process.ExitCode == 0;
            }
            catch (Exception)
            {
                return false;
            }
        }

        private async Task CreateRecoveryPoint(string description)
        {
            var timestamp = DateTime.UtcNow.ToString("yyyyMMddHHmmss");
            var recoveryPath = Path.Combine(RecoveryDirectory, timestamp);
            Directory.CreateDirectory(recoveryPath);

            try
            {
                // Backup critical components
                foreach (var component in _monitoredComponents.Values)
                {
                    if (File.Exists(component.Path))
                    {
                        File.Copy(component.Path, Path.Combine(recoveryPath, Path.GetFileName(component.Path)), true);
                    }
                }

                // Backup registry
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "reg.exe",
                        Arguments = $"save HKLM \"{Path.Combine(recoveryPath, "registry.hiv")}\"",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        CreateNoWindow = true
                    }
                };
                process.Start();
                await process.WaitForExitAsync();

                // Save recovery point metadata
                File.WriteAllText(
                    Path.Combine(recoveryPath, "metadata.json"),
                    System.Text.Json.JsonSerializer.Serialize(new
                    {
                        Timestamp = DateTime.UtcNow,
                        Description = description,
                        Components = _monitoredComponents
                    }));
            }
            catch (Exception ex)
            {
                LogEvent($"Failed to create recovery point: {ex.Message}", EventLogEntryType.Error);
                Directory.Delete(recoveryPath, true);
            }
        }

        private void LogEvent(string message, EventLogEntryType type)
        {
            try
            {
                EventLog.WriteEntry(EventLogSource, message, type);
                File.AppendAllText(
                    Path.Combine(LogDirectory, $"SystemGuardian_{DateTime.UtcNow:yyyyMMdd}.log"),
                    $"{DateTime.UtcNow:u}: [{type}] {message}{Environment.NewLine}"
                );
            }
            catch
            {
                // Fail silently if logging fails
            }
        }

        private EventLogEntryType MapSeverityToEventLogEntryType(EventSeverity severity)
        {
            return severity switch
            {
                EventSeverity.Information => EventLogEntryType.Information,
                EventSeverity.Warning => EventLogEntryType.Warning,
                EventSeverity.Error => EventLogEntryType.Error,
                EventSeverity.Critical => EventLogEntryType.Error,
                _ => EventLogEntryType.Information
            };
        }

        private float GetProcessCpuUsage(Process process)
        {
            try
            {
                var startTime = DateTime.UtcNow;
                var startCpuUsage = process.TotalProcessorTime;
                Thread.Sleep(500);
                var endTime = DateTime.UtcNow;
                var endCpuUsage = process.TotalProcessorTime;
                var cpuUsedMs = (endCpuUsage - startCpuUsage).TotalMilliseconds;
                var totalMsPassed = (endTime - startTime).TotalMilliseconds;
                var cpuUsageTotal = cpuUsedMs / (Environment.ProcessorCount * totalMsPassed) * 100;
                return (float)cpuUsageTotal;
            }
            catch
            {
                return 0;
            }
        }

        private async Task CleanupTemporaryFiles()
        {
            var tempPaths = new[]
            {
                Path.GetTempPath(),
                @"C:\Windows\Temp",
                @"C:\Windows\Prefetch"
            };

            foreach (var path in tempPaths)
            {
                try
                {
                    var di = new DirectoryInfo(path);
                    foreach (var file in di.GetFiles())
                    {
                        try
                        {
                            if (DateTime.UtcNow - file.LastAccessTimeUtc > TimeSpan.FromDays(7))
                            {
                                file.Delete();
                            }
                        }
                        catch
                        {
                            // Skip files that cannot be deleted
                            continue;
                        }
                    }

                    foreach (var dir in di.GetDirectories())
                    {
                        try
                        {
                            if (DateTime.UtcNow - dir.LastAccessTimeUtc > TimeSpan.FromDays(7))
                            {
                                dir.Delete(true);
                            }
                        }
                        catch
                        {
                            // Skip directories that cannot be deleted
                            continue;
                        }
                    }
                }
                catch (Exception ex)
                {
                    LogEvent($"Failed to cleanup temporary files in {path}: {ex.Message}", EventLogEntryType.Warning);
                }
            }
        }

        private async Task RestoreFromDriverStore(string driverPath)
        {
            try
            {
                var driverFileName = Path.GetFileName(driverPath);
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "pnputil.exe",
                        Arguments = $"/add-driver \"{driverPath}\" /install",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        CreateNoWindow = true
                    }
                };
                process.Start();
                await process.WaitForExitAsync();
            }
            catch (Exception ex)
            {
                throw new Exception($"Failed to restore driver from store: {ex.Message}", ex);
            }
        }

        private async Task ReloadDriver(string driverPath)
        {
            try
            {
                // Unload driver
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "sc.exe",
                        Arguments = $"stop \"{Path.GetFileNameWithoutExtension(driverPath)}\"",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        CreateNoWindow = true
                    }
                };
                process.Start();
                await process.WaitForExitAsync();

                await Task.Delay(1000); // Wait for driver to unload

                // Reload driver
                process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "sc.exe",
                        Arguments = $"start \"{Path.GetFileNameWithoutExtension(driverPath)}\"",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        CreateNoWindow = true
                    }
                };
                process.Start();
                await process.WaitForExitAsync();
            }
            catch (Exception ex)
            {
                throw new Exception($"Failed to reload driver: {ex.Message}", ex);
            }
        }

        private async Task IsolateComponent(string componentKey)
        {
            if (_monitoredComponents.TryGetValue(componentKey, out var component))
            {
                try
                {
                    var isolationPath = Path.Combine(
                        BackupDirectory,
                        "Isolated",
                        DateTime.UtcNow.ToString("yyyyMMddHHmmss"),
                        Path.GetFileName(component.Path)
                    );

                    Directory.CreateDirectory(Path.GetDirectoryName(isolationPath));

                    // Backup the component before isolation
                    File.Copy(component.Path, isolationPath, true);

                    // Update component status
                    component.Status = ComponentStatus.Isolated;
                    
                    switch (component.Type)
                    {
                        case ComponentType.Driver:
                            await DisableDriver(component.Path);
                            break;

                        case ComponentType.Service:
                            await DisableService(component.Path);
                            break;

                        case ComponentType.SystemFile:
                            // Rename the original file with .isolated extension
                            File.Move(component.Path, component.Path + ".isolated");
                            break;
                    }

                    LogEvent($"Component isolated: {componentKey}", EventLogEntryType.Warning);
                }
                catch (Exception ex)
                {
                    LogEvent($"Failed to isolate component {componentKey}: {ex.Message}", EventLogEntryType.Error);
                }
            }
        }

        private async Task DisableDriver(string driverPath)
        {
            try
            {
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "sc.exe",
                        Arguments = $"config \"{Path.GetFileNameWithoutExtension(driverPath)}\" start= disabled",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        CreateNoWindow = true
                    }
                };
                process.Start();
                await process.WaitForExitAsync();
            }
            catch (Exception ex)
            {
                throw new Exception($"Failed to disable driver: {ex.Message}", ex);
            }
        }

        private async Task DisableService(string serviceName)
        {
            try
            {
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "sc.exe",
                        Arguments = $"config \"{serviceName}\" start= disabled",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        CreateNoWindow = true
                    }
                };
                process.Start();
                await process.WaitForExitAsync();

                using (var service = new ServiceController(serviceName))
                {
                    if (service.Status != ServiceControllerStatus.Stopped)
                    {
                        service.Stop();
                        service.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(30));
                    }
                }
            }
            catch (Exception ex)
            {
                throw new Exception($"Failed to disable service: {ex.Message}", ex);
            }
        }

        private void CleanupOldRecoveryPoints()
        {
            try
            {
                var recoveryPoints = Directory.GetDirectories(RecoveryDirectory)
                    .Select(d => new DirectoryInfo(d))
                    .OrderByDescending(d => d.CreationTimeUtc)
                    .Skip(10); // Keep last 10 recovery points

                foreach (var point in recoveryPoints)
                {
                    try
                    {
                        point.Delete(true);
                    }
                    catch
                    {
                        // Skip if unable to delete
                        continue;
                    }
                }
            }
            catch (Exception ex)
            {
                LogEvent($"Failed to cleanup old recovery points: {ex.Message}", EventLogEntryType.Warning);
            }
        }
        #endregion
    }
}
}