package io.github.xalsace.qqbypass.hooks;

import android.os.Build;
import android.telephony.TelephonyManager;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

import io.github.xalsace.qqbypass.XposedEntry;
import io.github.xalsace.qqbypass.config.HookConfig;
import io.github.xalsace.qqbypass.utils.HookUtils;

/**
 * Device Info Hook - Consistency Protection
 *
 * Handles Pandora's multi-path cross-validation:
 * - Ensures consistent values across different API calls
 * - Prevents detection of single-API hooks
 * - Maintains device fingerprint consistency
 *
 * Pandora DeviceInfoMonitor uses 6+ different methods to get the same info:
 * - TelephonyManager.getImei()
 * - TelephonyManager.getDeviceId()
 * - Build.SERIAL (field)
 * - Build.getSerial() (method)
 * - SystemProperties.get()
 * - SubscriptionManager APIs
 */
public class DeviceInfoHook {

    private static String cachedImei = null;
    private static String cachedDeviceId = null;
    private static String cachedSerial = null;
    private static String cachedAndroidId = null;
    private static boolean httpAgentLogged = false;

    public static void hook(XC_LoadPackage.LoadPackageParam lpparam) {
        if (!HookConfig.ENABLE_DEVICE_SPOOF) return;

        XposedEntry.log("Initializing Device Info Hook");

        // Initialize cached values from config or real device
        initCachedValues();

        // Hook all device ID retrieval methods with consistent values
        hookTelephonyManager();
        hookBuildSerial();
        hookSystemProperties();
        hookAndroidId();

        // Hook Pandora monitoring framework
        hookPandoraMonitor();
    }

    private static void initCachedValues() {
        // Use configured fake values or null to pass through real values
        cachedImei = HookConfig.FAKE_IMEI;
        cachedDeviceId = HookConfig.FAKE_IMEI; // Same as IMEI for consistency
        cachedSerial = HookConfig.FAKE_SERIAL;
        cachedAndroidId = HookConfig.FAKE_ANDROID_ID;
    }

    private static void hookTelephonyManager() {
        // Hook all IMEI/DeviceId retrieval methods
        String[] methods = {"getImei", "getDeviceId", "getMeid"};

        for (String method : methods) {
            HookUtils.hookAllMethods("android.telephony.TelephonyManager", method,
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        if (cachedImei != null) {
                            param.setResult(cachedImei);
                        }
                        // If null, let real value pass through for consistency
                    }
                });
        }

        // Hook getSimSerialNumber
        HookUtils.hookAllMethods("android.telephony.TelephonyManager", "getSimSerialNumber",
            new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    if (cachedSerial != null) {
                        param.setResult(cachedSerial);
                    }
                }
            });
    }

    private static void hookBuildSerial() {
        // Hook Build.SERIAL field access (difficult to hook directly)
        // Hook Build.getSerial() method instead
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            HookUtils.hookMethod(Build.class, "getSerial",
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        if (cachedSerial != null) {
                            param.setResult(cachedSerial);
                        }
                    }
                });
        }
    }

    private static void hookSystemProperties() {
        // Hook SystemProperties.get() to return consistent values
        HookUtils.hookAllMethods("android.os.SystemProperties", "get",
            new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args.length > 0) {
                        String key = (String) param.args[0];

                        // Override specific properties
                        if ("ro.boot.serialno".equals(key) && cachedSerial != null) {
                            param.setResult(cachedSerial);
                        } else if ("gsm.serial".equals(key) && cachedSerial != null) {
                            param.setResult(cachedSerial);
                        }
                    }
                }
            });

        hookHttpAgent();
    }

    /**
     * AOSP RuntimeInit.commonInit() 会在 zygote fork 时就把 http.agent 算成一个静态
     * 字符串，内容为：
     *   "Dalvik/" + System.getProperty("java.vm.version")
     *           + " (Linux; U; Android " + Build.VERSION.RELEASE
     *           + "; " + Build.MODEL + " Build/" + Build.ID + ")"
     *
     * 这个值早于本模块（Xposed）加载，所以只改 Build.MODEL 字段对已缓存的 UA 无效，
     * HTTP 请求头里仍然带着真机机型——这是设备指纹最容易漏掉的一条通道。
     *
     * 在 System.getProperty 上拦截 "http.agent"，用已伪造的 Build 字段重新拼装，
     * 一处修复即可让全部读取点（HTTP 主路径、小程序、广点通、Bugly、gatherer）收敛。
     */
    private static void hookHttpAgent() {
        if (!HookConfig.ENABLE_DEVICE_SPOOF) return;
        HookUtils.hookAllMethods("java.lang.System", "getProperty", new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                if (param.args.length == 0 || !(param.args[0] instanceof String)) return;
                if (!"http.agent".equals(param.args[0])) return;

                String ua = "Dalvik/" + System.getProperty("java.vm.version", "2.1.0")
                    + " (Linux; U; Android " + Build.VERSION.RELEASE
                    + "; " + Build.MODEL + " Build/" + Build.ID + ")";
                if (!httpAgentLogged) {
                    httpAgentLogged = true;
                    XposedEntry.log("System.getProperty(http.agent) rebuilt -> " + ua);
                }
                param.setResult(ua);
            }
        });
    }

    private static void hookAndroidId() {
        // Hook Settings.Secure.getString for android_id
        HookUtils.hookAllMethods("android.provider.Settings.Secure", "getString",
            new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args.length >= 2) {
                        String key = (String) param.args[1];
                        if ("android_id".equals(key) && cachedAndroidId != null) {
                            param.setResult(cachedAndroidId);
                        }
                    }
                }
            });
    }

    private static void hookPandoraMonitor() {
        // Hook Pandora's DeviceInfoMonitor to prevent cross-validation
        HookUtils.hookAllMethods("com.tencent.qmethod.pandoraex.monitor.DeviceInfoMonitor", "getImei",
            new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    if (cachedImei != null) {
                        param.setResult(cachedImei);
                    }
                }
            });

        // Hook MonitorReporter.report (void method) to suppress anomaly reports.
        // report() returns void, so setResult(null) is type-safe.
        HookUtils.hookAllMethods("com.tencent.qmethod.pandoraex.core.MonitorReporter", "report",
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    // Block all monitoring reports
                    param.setResult(null);
                }
            });

        // NOTE: Do NOT hook getStrategyAndReport().
        // It sits on the NORMAL data-retrieval path (DeviceInfoMonitor.getModel,
        // InstalledAppListMonitor.getRunningAppProcesses) and returns a typed
        // strategy object. Forcing setResult(0) triggers a ClassCastException
        // ("Return value's type from hook callback does not match the hooked method")
        // thrown by Xposed during proceed() - impossible to catch - which crashes
        // QQ's startup tasks and blocks entry to the main UI (QQ 9.3.50).
    }
}
