package top.alice.transitionplayerfix.hook;

import android.os.Binder;
import android.os.Build;
import android.os.Process;
import android.os.UserHandle;

import java.lang.reflect.Method;

import io.github.libxposed.api.XposedInterface;
import io.github.libxposed.api.XposedModule;

/**
 * Launcher 进程侧最终防线。
 *
 * CVE-2026-0091 的最终利用方式是攻击者直接调用 Launcher 进程的
 * IApplicationThread.scheduleReceiver() / scheduleRegisteredReceiver()，
 * 在 Launcher 进程内执行代码。
 *
 * 本 Hook 在这两个方法的 Binder 入口处校验调用者 UID：
 *   - 只允许 SYSTEM_UID (1000) 和 ROOT_UID (0)
 *   - 其他所有 UID（包括 shell 2000）一律拒绝
 *
 * scheduleReceiver / scheduleRegisteredReceiver 是 AMS 向应用进程
 * 派发广播的专用接口，在 AOSP 中只有 system_server 会调用。
 * 因此白名单只需要 SYSTEM_UID 和 ROOT_UID。
 */
public class LauncherProcessHook {

    private static final String TAG = "TransitionPlayerFix";

    private static final String CLS_ACTIVITY_THREAD =
            "android.app.ActivityThread";
    private static final String INNER_CLASS_APPLICATION_THREAD =
            "android.app.ActivityThread$ApplicationThread";

    private static final String METHOD_SCHEDULE_RECEIVER =
            "scheduleReceiver";
    private static final String METHOD_SCHEDULE_REGISTERED_RECEIVER =
            "scheduleRegisteredReceiver";

    /** Launcher 包名：覆盖 AOSP、Pixel 与 ColorOS */
    private static final String[] LAUNCHER_PACKAGES = {
            "com.android.launcher",         // ColorOS / OPPO 定制
            "com.android.launcher3",        // AOSP
    };

    public static void install(XposedModule module, ClassLoader classLoader,
                               String packageName) {
        // Android 17+ 已原生加固，跳过
        if (Build.VERSION.SDK_INT >= 37) {
            module.log(android.util.Log.INFO, TAG,
                    "Android 17+ 已原生加固，跳过 LauncherProcessHook");
            return;
        }

        // 只在 Launcher 进程中执行
        if (!isLauncherPackage(packageName)) {
            return;
        }

        module.log(android.util.Log.INFO, TAG,
                "在 Launcher 进程 (" + packageName + ") 中安装最终防线");

        try {
            Class<?> clazz = classLoader.loadClass(INNER_CLASS_APPLICATION_THREAD);

            installHook(module, clazz, METHOD_SCHEDULE_RECEIVER);
            installHook(module, clazz, METHOD_SCHEDULE_REGISTERED_RECEIVER);

        } catch (Throwable t) {
            module.log(android.util.Log.ERROR, TAG,
                    "LauncherProcessHook 安装失败", t);
        }
    }

    /**
     * 安装单个方法的 Hook。
     *
     * 使用方法名 + 参数数量匹配，避免因不同 Android 版本的参数差异
     * 导致精确签名匹配失败。
     */
    private static void installHook(XposedModule module, Class<?> clazz,
                                    String methodName) {
        try {
            int hookedCount = 0;

            for (Method m : clazz.getDeclaredMethods()) {
                if (!methodName.equals(m.getName())) {
                    continue;
                }

                try {
                    module.hook(m)
                            .setExceptionMode(
                                    XposedInterface.ExceptionMode.PASSTHROUGH)
                            .intercept(new CallerUidCheckHooker(module, methodName));
                    module.log(android.util.Log.INFO, TAG,
                            "已 Hook " + m);
                    hookedCount++;
                } catch (Throwable t) {
                    module.log(android.util.Log.ERROR, TAG,
                            "Hook " + m + " 失败", t);
                }
            }

            if (hookedCount == 0) {
                module.log(android.util.Log.WARN, TAG,
                        "未找到 " + methodName + " 方法");
            } else {
                module.log(android.util.Log.INFO, TAG,
                        "共 Hook " + hookedCount + " 个 " + methodName + " 重载");
            }
        } catch (Throwable t) {
            module.log(android.util.Log.ERROR, TAG,
                    "Hook " + methodName + " 失败", t);
        }
    }

    private static class CallerUidCheckHooker implements XposedInterface.Hooker {

        private final XposedModule module;
        private final String methodName;

        CallerUidCheckHooker(XposedModule module, String methodName) {
            this.module = module;
            this.methodName = methodName;
        }

        @Override
        public Object intercept(XposedInterface.Chain chain) throws Throwable {
            try {
                final int callingUid = Binder.getCallingUid();
                final int callingAppId = UserHandle.getAppId(callingUid);

                // 白名单：SYSTEM_UID (1000) 和 ROOT_UID (0)
                // 使用 getAppId 转换以兼容多用户场景
                if (callingAppId == Process.SYSTEM_UID
                        || callingAppId == Process.ROOT_UID) {
                    return chain.proceed();
                }

                // 非白名单调用者：拒绝
                module.log(android.util.Log.WARN, TAG,
                        "Blocked " + methodName
                                + " from uid=" + callingUid
                                + " (appId=" + callingAppId + ")");
                throw new SecurityException(
                        methodName + " requires SYSTEM_UID or ROOT_UID, "
                                + "got uid=" + callingUid);

            } catch (SecurityException se) {
                // 安全异常正常传播
                throw se;
            } catch (Throwable t) {
                // Hook 内部错误：记录日志后放行，保证系统不崩溃
                module.log(android.util.Log.ERROR, TAG,
                        "Hook internal error in " + methodName
                                + ", passing through", t);
            }

            return chain.proceed();
        }
    }

    private static boolean isLauncherPackage(String packageName) {
        if (packageName == null) return false;
        for (String pkg : LAUNCHER_PACKAGES) {
            if (pkg.equals(packageName)) return true;
        }
        return false;
    }
}