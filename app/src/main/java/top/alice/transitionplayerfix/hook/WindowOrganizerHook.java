package top.alice.transitionplayerfix.hook;

import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Binder;
import android.os.Build;
import android.os.Process;

import java.lang.reflect.Method;

import io.github.libxposed.api.XposedInterface;
import io.github.libxposed.api.XposedModule;

/**
 * 对应漏洞的入口拦截点：
 * WindowOrganizerController.registerTransitionPlayer()
 *
 * 漏洞利用链的第一步是攻击者从 adb shell（uid=2000）调用此方法，
 * 注册一个恶意的 ITransitionPlayer。虽然 shell 持有
 * MANAGE_ACTIVITY_TASKS 权限，但合法的调用者只应是 SystemUI/WMShell。
 *
 * UID 策略：
 *   - SystemUI 的 sharedUserId 是 "android.uid.systemui"，并非 SYSTEM_UID (1000)。
 *   - 在 install 阶段通过 PackageManager 动态获取其真实 UID 并缓存。
 *   - 只放行 SYSTEM_UID 和 SystemUI 的真实 UID，其他 UID 一律拒绝。
 */
public class WindowOrganizerHook {

    private static final String TAG = "TransitionPlayerFix";

    private static final String CLS_WINDOW_ORGANIZER_CONTROLLER =
            "com.android.server.wm.WindowOrganizerController";
    private static final String METHOD_REGISTER_TRANSITION_PLAYER =
            "registerTransitionPlayer";
    private static final String TYPE_I_TRANSITION_PLAYER =
            "android.window.ITransitionPlayer";

    private static final String PKG_SYSTEMUI = "com.android.systemui";

    /** 缓存的 SystemUI 真实 UID，-1 表示尚未解析 */
    private static volatile int sSystemUiUid = -1;

    public static void install(XposedModule module, ClassLoader classLoader) {
        // Android 17+ 已原生加固，跳过
        if (Build.VERSION.SDK_INT >= 37) {
            module.log(android.util.Log.INFO, TAG,
                    "Android 17+ 已原生加固，跳过 WindowOrganizerHook");
            return;
        }

        // 解析 SystemUI 的真实 UID
        resolveSystemUiUid(module);

        try {
            Class<?> clazz = classLoader.loadClass(CLS_WINDOW_ORGANIZER_CONTROLLER);

            Method target = null;
            for (Method m : clazz.getDeclaredMethods()) {
                if (METHOD_REGISTER_TRANSITION_PLAYER.equals(m.getName())
                        && m.getParameterCount() == 1) {
                    String paramType = m.getParameterTypes()[0].getName();
                    if (TYPE_I_TRANSITION_PLAYER.equals(paramType)) {
                        target = m;
                        break;
                    }
                }
            }

            if (target == null) {
                module.log(android.util.Log.ERROR, TAG,
                        "未找到 registerTransitionPlayer 方法");
                return;
            }

            module.log(android.util.Log.INFO, TAG, "找到方法: " + target);

            module.hook(target)
                    .setExceptionMode(XposedInterface.ExceptionMode.PASSTHROUGH)
                    .intercept(new UidCheckHooker(module));

            module.log(android.util.Log.INFO, TAG,
                    "已 Hook registerTransitionPlayer（UID 白名单: SYSTEM_UID + SystemUI）");

        } catch (Throwable t) {
            module.log(android.util.Log.ERROR, TAG,
                    "Hook registerTransitionPlayer 失败", t);
        }
    }

    /**
     * 通过 PackageManager 获取 SystemUI 的真实 UID。
     *
     * 使用模块自身的 Context 获取 PackageManager。如果 API 102 中
     * getModuleContext() 不可用，回退到反射调用 ActivityThread
     * 获取系统 Context。
     */
    private static void resolveSystemUiUid(XposedModule module) {
        try {
            // 首选：模块自身的 Context
            android.content.Context ctx = null;
            try {
                Method getCtx = module.getClass()
                        .getMethod("getModuleContext");
                ctx = (android.content.Context) getCtx.invoke(module);
            } catch (Throwable ignored) {
                // API 102 可能已移除 getModuleContext，走回退路径
            }

            if (ctx == null) {
                module.log(android.util.Log.WARN, TAG,
                        "无法获取模块 Context，尝试回退路径");
                resolveSystemUiUidByReflection(module);
                return;
            }

            PackageManager pm = ctx.getPackageManager();
            ApplicationInfo ai = pm.getApplicationInfo(PKG_SYSTEMUI, 0);
            sSystemUiUid = ai.uid;

            module.log(android.util.Log.INFO, TAG,
                    "SystemUI UID = " + sSystemUiUid
                            + " (appId=" + (sSystemUiUid % 100000) + ")");

        } catch (Throwable t) {
            module.log(android.util.Log.WARN, TAG,
                    "获取 SystemUI UID 失败，回退到 SYSTEM_UID", t);
            sSystemUiUid = Process.SYSTEM_UID;
        }
    }

    /**
     * 回退路径：通过 ActivityThread.currentActivityThread() 获取系统 Context。
     */
    private static void resolveSystemUiUidByReflection(XposedModule module) {
        try {
            Class<?> atClass = Class.forName("android.app.ActivityThread");
            Object activityThread = atClass
                    .getMethod("currentActivityThread").invoke(null);
            if (activityThread == null) {
                sSystemUiUid = Process.SYSTEM_UID;
                return;
            }

            Object systemCtx = activityThread.getClass()
                    .getMethod("getSystemContext").invoke(activityThread);
            if (systemCtx == null) {
                sSystemUiUid = Process.SYSTEM_UID;
                return;
            }

            PackageManager pm = (PackageManager) systemCtx.getClass()
                    .getMethod("getPackageManager").invoke(systemCtx);
            ApplicationInfo ai = pm.getApplicationInfo(PKG_SYSTEMUI, 0);
            sSystemUiUid = ai.uid;

            module.log(android.util.Log.INFO, TAG,
                    "SystemUI UID = " + sSystemUiUid + " (回退路径)");

        } catch (Throwable t) {
            module.log(android.util.Log.WARN, TAG,
                    "回退路径也失败，回退到 SYSTEM_UID", t);
            sSystemUiUid = Process.SYSTEM_UID;
        }
    }

    private static class UidCheckHooker implements XposedInterface.Hooker {

        private final XposedModule module;

        UidCheckHooker(XposedModule module) {
            this.module = module;
        }

        @Override
        public Object intercept(XposedInterface.Chain chain) throws Throwable {
            try {
                final int callingUid = Binder.getCallingUid();
                final int callingAppId = callingUid % 100000;

                // 白名单：SYSTEM_UID (1000) + SystemUI 真实 UID
                if (callingAppId == Process.SYSTEM_UID
                        || callingAppId == sSystemUiUid) {
                    return chain.proceed();
                }

                // 非白名单调用者：拒绝
                module.log(android.util.Log.WARN, TAG,
                        "拒绝未授权注册 TransitionPlayer: uid="
                                + callingUid + " appId=" + callingAppId
                                + " (白名单: 1000, " + sSystemUiUid + ")");
                throw new SecurityException(
                        "registerTransitionPlayer requires SYSTEM_UID or "
                                + "SystemUI UID, got uid=" + callingUid);

            } catch (SecurityException se) {
                throw se;
            } catch (Throwable t) {
                module.log(android.util.Log.ERROR, TAG,
                        "Hook 内部错误，放行避免崩溃", t);
            }
            return chain.proceed();
        }
    }
}