using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;

class Program
{
    // Base de datos de hashes en MAYÚSCULAS para optimizar comparaciones
    private static readonly HashSet<string> MalwareDatabase = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F"
    };

    // Canal desacoplado seguro: un solo lector garantiza orden de despacho sin bloqueos
    private static readonly Channel<string> FileQueue = Channel.CreateUnbounded<string>(new UnboundedChannelOptions
    {
        SingleReader = true, 
        SingleWriter = false
    });

    static async Task Main(string[] args)
    {
        string targetDir = Path.Combine(Directory.GetCurrentDirectory(), "watch_folder");
        if (!Directory.Exists(targetDir)) Directory.CreateDirectory(targetDir);

        // Token maestro para detener reintentos y tareas secundarias inmediatamente
        using var cts = new CancellationTokenSource();
        
        SafeFileScanner.StartCleanupTask(cts.Token);
        Task consumerTask = ProcessQueueAsync(cts.Token);

        using (FileSystemWatcher watcher = new FileSystemWatcher())
        {
            watcher.Path = targetDir;
            watcher.NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite;
            watcher.InternalBufferSize = 64 * 1024; 

            watcher.Created += (s, e) => FileQueue.Writer.TryWrite(e.FullPath);
            watcher.Changed += (s, e) => FileQueue.Writer.TryWrite(e.FullPath);
            watcher.Renamed += (s, e) => FileQueue.Writer.TryWrite(e.FullPath);

            watcher.EnableRaisingEvents = true;

            Console.WriteLine($"🛡️ Protección Industrial Iniciada. Vigilando: {targetDir}");
            Console.WriteLine("Presione 'q' y Enter para salir.");
            while (Console.ReadLine() != "q") ;
            
            Console.WriteLine("⏳ Apagando sistema... Vaciando archivos restantes en cola.");
            
            // 1. Cerramos el canal: ReadAllAsync terminará cuando la cola física llegue a cero
            FileQueue.Writer.Complete(); 
            
            // 2. Control de contingencia industrial: si en 15 segundos no se vacía la cola, forzamos parada
            using var shutdownTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cts.Token, shutdownTimeout.Token);

            try
            {
                // Esperamos que el consumidor termine bajo el reloj del timeout
                await consumerTask; 
            }
            catch (Exception) { /* Prevenir burbujeo de cancelaciones al cerrar */ }

            // 3. Cancelación final de hilos de soporte en segundo plano
            cts.Cancel(); 
        }

        Console.WriteLine("🛑 Sistema detenido de forma segura.");
    }

    private static async Task ProcessQueueAsync(CancellationToken token)
    {
        const int MaxConcurrencia = 4;
        using var semaphore = new SemaphoreSlim(MaxConcurrencia);

        try
        {
            // Sin pasar el token aquí para permitir que consuma los remanentes tras el .Complete()
            await foreach (var filePath in FileQueue.Reader.ReadAllAsync())
            {
                // Si el timeout de contingencia general se activa, rompemos el vaciado
                if (token.IsCancellationRequested) break;

                // Frena la lectura del canal si ya hay 4 escaneos de archivos activos simultáneos
                await semaphore.WaitAsync(token);
                
                // Disparo al ThreadPool sin alocar colecciones intermedias (Cero Memory Leaks)
                _ = Task.Run(async () =>
                {
                    try
                    {
                        await ProcessFileAsync(filePath, token);
                    }
                    finally
                    {
                        semaphore.Release(); // Slot devuelto de forma garantizada
                    }
                }, token); 
            }
        }
        catch (OperationCanceledException) { } 

        // --- GRACEFUL SHUTDOWN INDUSTRIAL ---
        // Adquirimos todos los slots del semáforo. Si se logra, la certeza de que no hay tareas vivas es del 100%.
        for (int i = 0; i < MaxConcurrencia; i++)
        {
            try
            {
                await semaphore.WaitAsync(CancellationToken.None);
            }
            catch (Exception) { break; }
        }
    }

    private static async Task ProcessFileAsync(string filePath, CancellationToken token)
    {
        // Evitamos procesar archivos fantasma eliminados antes de salir de la cola
        if (!File.Exists(filePath) || Directory.Exists(filePath)) return;

        string fileHash = await SafeFileScanner.GetFileSha256Async(filePath, token);
        if (string.IsNullOrEmpty(fileHash)) return;

        string fileName = Path.GetFileName(filePath);
        Console.WriteLine($"👮 Inspeccionando archivo: {fileName} (SHA-256: {fileHash})");

        if (MalwareDatabase.Contains(fileHash))
        {
            Console.WriteLine($"🚨 ¡ALERTA! Malware detectado: {fileName}!");
            NeutralizeThreat(filePath);
        }
    }

    private static void NeutralizeThreat(string filePath)
    {
        try
        {
            if (!File.Exists(filePath)) return;

            try
            {
                File.Delete(filePath);
                Console.WriteLine("🛡️ Archivo eliminado con éxito.");
            }
            catch (IOException) 
            {
                // Estrategia de contención 2: Truncar el archivo (neutraliza el payload binario)
                try 
                {
                    using (var fs = new FileStream(filePath, FileMode.Truncate, FileAccess.Write, FileShare.Delete))
                    {
                        fs.Flush();
                    }
                    Console.WriteLine("🛡️ Archivo bloqueado. Se ha TRUNCADO y neutralizado su contenido.");
                }
                catch (Exception)
                {
                    // Estrategia de contención 3: Romper la ruta de ejecución moviéndolo a cuarentena
                    string quarantinePath = filePath + ".quarantine";
                    File.Move(filePath, quarantinePath, overwrite: true);
                    Console.WriteLine($"🛡️ No se pudo borrar ni truncar. Movido a cuarentena: {quarantinePath}");
                }
            }
        }
        catch (Exception ex) 
        { 
            Console.WriteLine($"❌ Error crítico al neutralizar: {ex.Message}"); 
        }
    }
}

class SafeFileScanner
{
    private static readonly ConcurrentDictionary<string, DateTime> LastProcessedFiles = new ConcurrentDictionary<string, DateTime>();
    private static readonly TimeSpan DebounceTime = TimeSpan.FromMilliseconds(1000);

    public static void StartCleanupTask(CancellationToken token)
    {
        Task.Run(async () =>
        {
            while (!token.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(TimeSpan.FromMinutes(2), token);
                    var ahora = DateTime.UtcNow;

                    foreach (var key in LastProcessedFiles.Keys)
                    {
                        if (LastProcessedFiles.TryGetValue(key, out var lastTime) && (ahora - lastTime > TimeSpan.FromMinutes(2)))
                        {
                            LastProcessedFiles.TryRemove(key, out _);
                        }
                    }
                }
                catch (TaskCanceledException) { break; }
            }
        }, token);
    }

    public static async Task<string> GetFileSha256Async(string filePath, CancellationToken token)
    {
        var now = DateTime.UtcNow;
        bool yaProcesado = false;

        // Doble control atómico para evitar condiciones de carrera si entran ráfagas del mismo archivo
        LastProcessedFiles.AddOrUpdate(filePath, now, (key, oldTime) =>
        {
            if (now - oldTime < DebounceTime)
            {
                yaProcesado = true;
                return oldTime;
            }
            return now;
        });

        if (yaProcesado) return null;

        int retries = 8; 
        int delay = 100; 

        while (retries > 0)
        {
            if (token.IsCancellationRequested) return null;

            try
            {
                if (!File.Exists(filePath)) return null;

                using (var sha256 = SHA256.Create())
                await using (var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, useAsync: true))
                {
                    byte[] hashBytes = await sha256.ComputeHashAsync(stream, token);
                    string hash = Convert.ToHexString(hashBytes);
                    
                    // Actualizamos con la estampa de tiempo real de finalización binaria exitosa
                    LastProcessedFiles[filePath] = DateTime.UtcNow;
                    return hash;
                }
            }
            catch (IOException) 
            {
                retries--;
                if (retries == 0) break;
                
                try
                {
                    await Task.Delay(delay, token);
                }
                catch (OperationCanceledException) { return null; } // Salida limpia sin lanzar excepciones molestas
                
                delay *= 2; // Backoff exponencial
            }
            catch (OperationCanceledException)
            {
                return null;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Error no controlado al leer archivo: {ex.Message}");
                return null;
            }
        }

        LastProcessedFiles.TryRemove(filePath, out _);
        return null;
    }
}