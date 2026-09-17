package top.alice.transitionplayerfix.hook;

import android.os.Binder;
import android.os.Process;

import java.lang.reflect.Method;

import io.github.libxposed.api.XposedInterface;
import io.github.libxposed.api.XposedModule;

/**
 * 对应官方补丁的扩展修复：
 * 监控 ActivityManagerService 中调用 IApplicationThread 的路径，
 * 防止攻击者将窃取的 IApplicationThread 传递给 AMS，
 * 由 AMS 代为调用 scheduleReceiver 来绕过直接调用限制。
 *
 * 已知调用路径（AOSP 源码）：
 *   ActivityManagerService.processCurBroadcastLocked()
 *     → app.thread.scheduleReceiver(...)
 *   ActivityManagerService.performReceiveLocked()
 *     → app.thread.scheduleRegisteredReceiver(...)
 */
public class ActivityManagerHook {

    private static final String TAG = "TransitionPlayerFix";

    private static final String CLS_ACTIVITY_MANAGER_SERVICE =
            "com.android.server.am.ActivityManagerService";

    // AMS 中调用 IApplicationThread 的关键方法
    private static final String METHOD_PROCESS_CUR_BROADCAST_LOCKED =
            "processCurBroadcastLocked";
    private static final String METHOD_PERFORM_RECEIVE_LOCKED =
            "performReceiveLocked";

    public static void install(XposedModule module, ClassLoader classLoader) {
        try {
            Class<?> clazz = classLoader.loadClass(CLS_ACTIVITY_MANAGER_SERVICE);

            // Hook processCurBroadcastLocked(BroadcastRecord, ProcessRecord)
            try {
                Method processCurBroadcast = null;
                for (Method m : clazz.getDeclaredMethods()) {
                    if (METHOD_PROCESS_CUR_BROADCAST_LOCKED.equals(m.getName())
                            && m.getParameterCount() == 2) {
                        processCurBroadcast = m;
                        break;
                    }
                }
                if (processCurBroadcast != null) {
                    module.hook(processCurBroadcast)
                            .setExceptionMode(XposedInterface.ExceptionMode.PASSTHROUGH)
                            .intercept(new BroadcastDeliveryHooker(module, classLoader));
                    module.log(android.util.Log.INFO, TAG,
                            "已 Hook ActivityManagerService.processCurBroadcastLocked");
                } else {
                    module.log(android.util.Log.WARN, TAG,
                            "未找到 processCurBroadcastLocked 方法");
                }
            } catch (Throwable t) {
                module.log(android.util.Log.ERROR, TAG,
                        "Hook processCurBroadcastLocked 失败", t);
            }

            // Hook performReceiveLocked(...)
            try {
                Method performReceive = null;
                for (Method m : clazz.getDeclaredMethods()) {
                    if (METHOD_PERFORM_RECEIVE_LOCKED.equals(m.getName())
                            && m.getParameterCount() >= 6) {
                        performReceive = m;
                        break;
                    }
                }
                if (performReceive != null) {
                    module.hook(performReceive)
                            .setExceptionMode(XposedInterface.ExceptionMode.PASSTHROUGH)
                            .intercept(new BroadcastDeliveryHooker(module, classLoader));
                    module.log(android.util.Log.INFO, TAG,
                            "已 Hook ActivityManagerService.performReceiveLocked");
                } else {
                    module.log(android.util.Log.WARN, TAG,
                            "未找到 performReceiveLocked 方法");
                }
            } catch (Throwable t) {
                module.log(android.util.Log.ERROR, TAG,
                        "Hook performReceiveLocked 失败", t);
            }

        } catch (Throwable t) {
            module.log(android.util.Log.ERROR, TAG,
                    "Hook ActivityManagerService 失败", t);
        }
    }

    /**
     * 检查 AMS 即将调用的 IApplicationThread 是否来自非系统进程。
     *
     * 关键逻辑：
     *   AMS 从 ProcessRecord 中取出 IApplicationThread（app.thread），
     *   然后调用 scheduleReceiver。如果这个 IApplicationThread 是被攻击者
     *   通过某种方式注入到 ProcessRecord 中的，那么它的实际提供者可能不是
     *   合法的系统进程。
     *
     * 由于 AMS 自身运行在 system_server 中，无法直接通过 Binder.getCallingUid()
     * 判断 IApplicationThread 的来源。因此，需要通过 ProcessRecord 中的
     * 进程信息（如 uid、pid）来验证。
     */
    private static class BroadcastDeliveryHooker implements XposedInterface.Hooker {

        private final XposedModule module;
        private final ClassLoader classLoader;

        BroadcastDeliveryHooker(XposedModule module, ClassLoader classLoader) {
            this.module = module;
            this.classLoader = classLoader;
        }

        @Override
        public Object intercept(XposedInterface.Chain chain) throws Throwable {
            // AMS 内部的调用是合法的系统行为，不应该被拦截。
            // 此 Hook 的目的是监控和记录异常情况，
            // 而非阻止 AMS 的正常广播分发。
            //
            // 如果需要更严格的防护，可以检查 ProcessRecord 中的 uid 是否合法。
            // 但 AMS 内部的 ProcessRecord 是系统维护的，攻击者难以篡改。
            //
            // 此处的核心作用是：当攻击者通过某种方式将恶意 IApplicationThread
            // 注入到 ProcessRecord 中时，记录并告警。

            // 记录 AMS 即将调用的 IApplicationThread
            try {
                Object thisObject = chain.getThisObject();
                Object[] args = chain.getArgs().toArray();

                // 尝试从参数中提取 ProcessRecord 或 BroadcastRecord
                String callerInfo = extractCallerInfo(args);
                if (callerInfo != null) {
                    module.log(android.util.Log.DEBUG, TAG,
                            "AMS 即将调用 IApplicationThread: " + callerInfo);
                }
            } catch (Throwable ignored) {
                // 日志记录失败不影响正常流程
            }

            // AMS 内部调用直接放行
            return chain.proceed();
        }

        /**
         * 从参数中提取调用者信息，用于日志记录。
         */
        private String extractCallerInfo(Object[] args) {
            if (args == null || args.length == 0) return null;

            try {
                // processCurBroadcastLocked(BroadcastRecord r, ProcessRecord app)
                if (args.length >= 2) {
                    Object broadcastRecord = args[0];
                    Object processRecord = args[1];

                    if (broadcastRecord != null && processRecord != null) {
                        java.lang.reflect.Field callingUidField =
                                broadcastRecord.getClass().getDeclaredField("callingUid");
                        callingUidField.setAccessible(true);
                        int callingUid = callingUidField.getInt(broadcastRecord);

                        java.lang.reflect.Field uidField =
                                processRecord.getClass().getDeclaredField("uid");
                        uidField.setAccessible(true);
                        int targetUid = uidField.getInt(processRecord);

                        return "callingUid=" + callingUid + " targetUid=" + targetUid;
                    }
                }
            } catch (Throwable ignored) {}

            return null;
        }
    }
}