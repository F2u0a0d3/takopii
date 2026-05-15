/**
 * Frida-monitor detection agent for SkyWeather evasion specimen.
 *
 * Hooks sensitive API call-sites to detect specimen runtime behavior.
 * Completes the detection triad: YARA (static) + Sigma (behavior) + Frida (dynamic).
 *
 * Usage:
 *   frida -U -f com.skyweather.forecast -l skyweather-monitor.js --no-pause
 *
 * Each hook emits structured JSON to stdout for pipeline consumption:
 *   {"ts":"...","module":"...","event":"...","severity":"...","detail":{...}}
 */

'use strict';

// ─── Telemetry ────────────────────────────────────────────────────

function emit(module, event, severity, detail) {
    var entry = {
        ts: new Date().toISOString(),
        module: module,
        event: event,
        severity: severity,
        detail: detail || {}
    };
    send(JSON.stringify(entry));
    console.log('[' + severity.toUpperCase() + '] ' + module + '/' + event +
        ' — ' + JSON.stringify(detail));
}

// ─── Module 1: WorkManager Beacon Scheduling ──────────────────────

function hookWorkManager() {
    try {
        var WorkManager = Java.use('androidx.work.WorkManager');
        WorkManager.enqueueUniqueWork.overload(
            'java.lang.String',
            'androidx.work.ExistingWorkPolicy',
            'androidx.work.OneTimeWorkRequest'
        ).implementation = function (name, policy, request) {
            emit('workmanager', 'enqueue_unique_work', 'high', {
                work_name: name,
                policy: policy.toString(),
                request_class: request.getClass().getName()
            });

            // Check for weather-themed work names (specimen indicator)
            if (name.indexOf('weather') !== -1 || name.indexOf('sync') !== -1) {
                emit('workmanager', 'suspicious_work_name', 'critical', {
                    work_name: name,
                    pattern: 'weather/sync themed — matches SkyWeather beacon pattern'
                });
            }

            return this.enqueueUniqueWork(name, policy, request);
        };
        console.log('[+] WorkManager.enqueueUniqueWork hooked');
    } catch (e) {
        console.log('[-] WorkManager hook failed: ' + e);
    }
}

// ─── Module 2: HttpURLConnection Beacon/Exfil ─────────────────────

function hookHttpURLConnection() {
    try {
        var URL = Java.use('java.net.URL');
        var HttpURLConnection = Java.use('java.net.HttpURLConnection');

        URL.openConnection.overload().implementation = function () {
            var urlStr = this.toString();
            var conn = this.openConnection();

            // Detect RFC1918 / loopback connections (lab C2)
            var host = this.getHost();
            var port = this.getPort();

            if (host === '127.0.0.1' || host === 'localhost' ||
                host.indexOf('10.') === 0 || host.indexOf('192.168.') === 0 ||
                host.indexOf('10.0.2.2') === 0) {

                emit('network', 'rfc1918_connection', 'high', {
                    url: urlStr,
                    host: host,
                    port: port
                });
            }

            // Detect beacon/payload paths
            if (urlStr.indexOf('/api/v1/beacon') !== -1) {
                emit('network', 'beacon_endpoint', 'critical', {
                    url: urlStr,
                    pattern: 'C2 beacon path detected'
                });
            }
            if (urlStr.indexOf('/api/v1/payload') !== -1) {
                emit('network', 'payload_endpoint', 'critical', {
                    url: urlStr,
                    pattern: 'Payload download path detected'
                });
            }

            return conn;
        };
        console.log('[+] URL.openConnection hooked');
    } catch (e) {
        console.log('[-] HttpURLConnection hook failed: ' + e);
    }
}

// ─── Module 3: DexClassLoader (Payload Loading) ───────────────────

function hookDexClassLoader() {
    try {
        var DexClassLoader = Java.use('dalvik.system.DexClassLoader');

        DexClassLoader.$init.overload(
            'java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.ClassLoader'
        ).implementation = function (dexPath, optimizedDir, librarySearchPath, parent) {

            emit('dexloader', 'dexclassloader_init', 'critical', {
                dex_path: dexPath,
                optimized_dir: optimizedDir,
                library_path: librarySearchPath ? librarySearchPath : 'null',
                parent_loader: parent.getClass().getName()
            });

            // Check for suspicious filenames
            if (dexPath.indexOf('.cache_data') !== -1 ||
                dexPath.indexOf('.update_cache') !== -1 ||
                dexPath.indexOf('.dex') !== -1) {
                emit('dexloader', 'suspicious_dex_path', 'critical', {
                    dex_path: dexPath,
                    pattern: 'Hidden file prefix + DEX extension — anti-forensics pattern'
                });
            }

            return this.$init(dexPath, optimizedDir, librarySearchPath, parent);
        };

        // Also hook loadClass to capture what gets loaded
        DexClassLoader.loadClass.overload('java.lang.String').implementation = function (name) {
            emit('dexloader', 'load_class', 'high', {
                class_name: name
            });
            return this.loadClass(name);
        };

        console.log('[+] DexClassLoader hooked');
    } catch (e) {
        console.log('[-] DexClassLoader hook failed: ' + e);
    }
}

// ─── Module 4: Reflection Chain (API Hiding) ──────────────────────

function hookReflection() {
    try {
        var Class = Java.use('java.lang.Class');
        var Method = Java.use('java.lang.reflect.Method');

        // Class.forName — first step in reflection chain
        Class.forName.overload('java.lang.String').implementation = function (name) {
            // Filter noise: only alert on suspicious patterns
            if (name.indexOf('payload') !== -1 ||
                name.indexOf('Module') !== -1 ||
                name.indexOf('android.os.Build') !== -1) {

                emit('reflection', 'class_forname', 'medium', {
                    class_name: name
                });
            }
            return this.forName(name);
        };

        // Method.invoke — execution step
        Method.invoke.overload('java.lang.Object', '[Ljava.lang.Object;').implementation = function (obj, args) {
            var methodName = this.getName();
            var declaringClass = this.getDeclaringClass().getName();

            // Alert on suspicious reflective invocations
            if (methodName === 'execute' || methodName === 'run' ||
                declaringClass.indexOf('payload') !== -1) {

                emit('reflection', 'method_invoke', 'high', {
                    declaring_class: declaringClass,
                    method_name: methodName,
                    arg_count: args ? args.length : 0
                });
            }

            return this.invoke(obj, args);
        };

        console.log('[+] Reflection chain hooked');
    } catch (e) {
        console.log('[-] Reflection hook failed: ' + e);
    }
}

// ─── Module 5: Anti-Debug Detection ───────────────────────────────

function hookAntiDebug() {
    try {
        // Hook Debug.isDebuggerConnected
        var Debug = Java.use('android.os.Debug');
        Debug.isDebuggerConnected.implementation = function () {
            emit('antidebug', 'debugger_check', 'medium', {
                method: 'Debug.isDebuggerConnected',
                pattern: 'Java-layer debugger detection'
            });
            // Return false to bypass
            return false;
        };
        console.log('[+] Debug.isDebuggerConnected hooked (returns false)');

        // Hook System.nanoTime for timing-probe detection
        var callCount = 0;
        var lastCallTime = 0;
        var System = Java.use('java.lang.System');

        System.nanoTime.implementation = function () {
            var now = Date.now();
            callCount++;

            // Two nanoTime calls within 100ms = timing probe
            if (now - lastCallTime < 100 && callCount >= 2) {
                emit('antidebug', 'timing_probe', 'high', {
                    method: 'System.nanoTime',
                    call_count_within_100ms: callCount,
                    pattern: 'nanoTime timing probe — anti-debug triad'
                });
                callCount = 0;
            }
            lastCallTime = now;

            return this.nanoTime();
        };
        console.log('[+] System.nanoTime hooked (timing probe detector)');
    } catch (e) {
        console.log('[-] Anti-debug hook failed: ' + e);
    }
}

// ─── Module 6: File Operations (Anti-Forensics) ──────────────────

function hookFileOps() {
    try {
        var File = Java.use('java.io.File');

        File.delete.implementation = function () {
            var path = this.getAbsolutePath();

            // Alert on deletion of suspicious files
            if (path.indexOf('.cache_data') !== -1 ||
                path.indexOf('.update_cache') !== -1 ||
                path.indexOf('.oat_cache') !== -1 ||
                path.indexOf('.dex') !== -1) {

                emit('antiforensics', 'suspicious_delete', 'critical', {
                    path: path,
                    exists: this.exists(),
                    size: this.length(),
                    pattern: 'Post-load DEX deletion — anti-forensics cleanup'
                });
            }

            return this.delete();
        };

        File.setReadOnly.implementation = function () {
            var path = this.getAbsolutePath();

            if (path.indexOf('.dex') !== -1 || path.indexOf('.cache') !== -1) {
                emit('antiforensics', 'dex_set_readonly', 'high', {
                    path: path,
                    pattern: 'DEX setReadOnly before DexClassLoader — Android 14+ requirement'
                });
            }

            return this.setReadOnly();
        };

        console.log('[+] File.delete / File.setReadOnly hooked');
    } catch (e) {
        console.log('[-] File ops hook failed: ' + e);
    }
}

// ─── Module 7: MessageDigest (DGA Detection) ──────────────────────

function hookMessageDigest() {
    try {
        var MessageDigest = Java.use('java.security.MessageDigest');

        MessageDigest.getInstance.overload('java.lang.String').implementation = function (algorithm) {
            if (algorithm === 'MD5') {
                emit('dga', 'md5_getInstance', 'medium', {
                    algorithm: algorithm,
                    pattern: 'MD5 instantiation — DGA seed hashing'
                });
            }
            return this.getInstance(algorithm);
        };

        MessageDigest.digest.overload('[B').implementation = function (input) {
            var inputStr = '';
            try {
                inputStr = Java.use('java.lang.String').$new(input);
            } catch (e) {
                inputStr = '<binary ' + input.length + ' bytes>';
            }

            // DGA pattern: input looks like "alpha182026" (seed + week + year)
            if (/^(alpha|bravo|charlie|delta)\d+$/.test(inputStr)) {
                emit('dga', 'dga_seed_hash', 'critical', {
                    algorithm: 'MD5',
                    seed_input: inputStr,
                    pattern: 'DGA seed format — SharkBot V2.8 style week+year rotation'
                });
            }

            return this.digest(input);
        };

        console.log('[+] MessageDigest hooked (DGA detector)');
    } catch (e) {
        console.log('[-] MessageDigest hook failed: ' + e);
    }
}

// ─── Module 8: XOR Decryption Pattern ─────────────────────────────

function hookXorPattern() {
    try {
        // Hook FileOutputStream to catch encrypted payload writes
        var FileOutputStream = Java.use('java.io.FileOutputStream');

        FileOutputStream.$init.overload('java.io.File').implementation = function (file) {
            var path = file.getAbsolutePath();

            if (path.indexOf('.cache_data') !== -1) {
                emit('payload', 'encrypted_payload_write', 'high', {
                    path: path,
                    pattern: 'Encrypted payload written to .cache_data — Stage 2a download'
                });
            }

            return this.$init(file);
        };

        // Hook File.writeBytes (Kotlin extension compiled to JVM)
        // Catches the decrypted DEX write
        var Files = Java.use('kotlin.io.FilesKt__FileReadWriteKt');
        if (Files) {
            Files.writeBytes.implementation = function (file, bytes) {
                var path = file.getAbsolutePath();

                if (path.indexOf('.update_cache.dex') !== -1) {
                    emit('payload', 'decrypted_dex_write', 'critical', {
                        path: path,
                        size: bytes.length,
                        magic: bytes.length >= 3 ?
                            String.fromCharCode(bytes[0] & 0xFF) +
                            String.fromCharCode(bytes[1] & 0xFF) +
                            String.fromCharCode(bytes[2] & 0xFF) : 'too_short',
                        pattern: 'Decrypted DEX written — Stage 2b XOR decrypt complete'
                    });
                }

                return this.writeBytes(file, bytes);
            };
        }

        console.log('[+] XOR payload write hooked');
    } catch (e) {
        console.log('[-] XOR pattern hook failed: ' + e);
    }
}

// ─── Module 9: Hardware Metric Anti-Sandbox ───────────────────────

function hookSandboxChecks() {
    try {
        var SensorManager = Java.use('android.hardware.SensorManager');

        SensorManager.getDefaultSensor.overload('int').implementation = function (type) {
            var typeNames = {
                1: 'TYPE_ACCELEROMETER',
                4: 'TYPE_GYROSCOPE',
                5: 'TYPE_LIGHT',
                6: 'TYPE_PRESSURE'
            };
            var typeName = typeNames[type] || ('TYPE_' + type);

            emit('sandbox', 'sensor_query', 'low', {
                sensor_type: type,
                sensor_name: typeName,
                pattern: 'Hardware metric sandbox detection'
            });

            return this.getDefaultSensor(type);
        };

        // BatteryManager property read
        var BatteryManager = Java.use('android.os.BatteryManager');
        BatteryManager.getIntProperty.implementation = function (id) {
            var propNames = { 4: 'BATTERY_PROPERTY_CAPACITY' };
            emit('sandbox', 'battery_check', 'low', {
                property_id: id,
                property_name: propNames[id] || ('PROP_' + id),
                pattern: 'Battery realism check — emulator detection'
            });
            return this.getIntProperty(id);
        };

        // TelephonyManager SIM check
        var TelephonyManager = Java.use('android.telephony.TelephonyManager');
        var origGetSimState = TelephonyManager.getSimState;

        // Hook the no-arg version
        TelephonyManager.getSimState.overload().implementation = function () {
            emit('sandbox', 'sim_check', 'low', {
                pattern: 'SIM presence check — emulator detection'
            });
            return this.getSimState();
        };

        console.log('[+] Hardware metric / sandbox hooks installed');
    } catch (e) {
        console.log('[-] Sandbox check hooks failed: ' + e);
    }
}

// ─── Module 10: Kill Chain Composite Detector ─────────────────────

var killChainState = {
    beaconSeen: false,
    payloadDownloaded: false,
    dexLoaded: false,
    filesDeleted: false,
    startTime: 0
};

function checkKillChain(phase) {
    if (phase === 'beacon') {
        killChainState.beaconSeen = true;
        killChainState.startTime = Date.now();
    }
    if (phase === 'payload') killChainState.payloadDownloaded = true;
    if (phase === 'dexload') killChainState.dexLoaded = true;
    if (phase === 'cleanup') killChainState.filesDeleted = true;

    // Full kill chain: all 4 phases within 60 seconds
    if (killChainState.beaconSeen &&
        killChainState.payloadDownloaded &&
        killChainState.dexLoaded &&
        killChainState.filesDeleted) {

        var elapsed = Date.now() - killChainState.startTime;
        if (elapsed < 60000) {
            emit('killchain', 'full_anatsa_chain', 'critical', {
                elapsed_ms: elapsed,
                phases: 'beacon → payload → dexload → cleanup',
                pattern: 'Complete Anatsa Stage 1→2→3→4 progression in ' + elapsed + 'ms'
            });
        }

        // Reset for next detection
        killChainState.beaconSeen = false;
        killChainState.payloadDownloaded = false;
        killChainState.dexLoaded = false;
        killChainState.filesDeleted = false;
    }
}

// ─── Main ─────────────────────────────────────────────────────────

Java.perform(function () {
    console.log('');
    console.log('╔══════════════════════════════════════════════════════════╗');
    console.log('║  SkyWeather Frida-Monitor — Detection Agent v1.0        ║');
    console.log('║  Takopii Detection Engineering                          ║');
    console.log('║  Hooks: 10 modules × 15 API sites                      ║');
    console.log('╚══════════════════════════════════════════════════════════╝');
    console.log('');

    hookWorkManager();          // Module 1: Beacon scheduling
    hookHttpURLConnection();    // Module 2: Network C2
    hookDexClassLoader();       // Module 3: Payload loading
    hookReflection();           // Module 4: API hiding
    hookAntiDebug();            // Module 5: Anti-debug bypass
    hookFileOps();              // Module 6: Anti-forensics
    hookMessageDigest();        // Module 7: DGA
    hookXorPattern();           // Module 8: XOR decrypt
    hookSandboxChecks();        // Module 9: Hardware metrics
    // Module 10: Kill chain composite (driven by other modules)

    console.log('');
    console.log('[*] All hooks installed. Monitoring specimen behavior...');
    console.log('[*] Output format: JSON per event for pipeline ingestion');
    console.log('');
});
