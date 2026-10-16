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
 *   - 只放行 SYSTEM_UID 和 SystemUI 的真实 UID。
 *   - 若解析失败，sSystemUiUid = -1，此时放行所有调用，避免误伤。
 *
 * 额外修复点：canDropDuringDisplayChange
 *   官方补丁直接移除了该方法。本 Hook 始终返回 false 模拟删除。
 *
 * API 102 适配：
 *   - getModuleContext() 在 API 101 中已被移除，改用 getModuleApplicationInfo()。
 *   - 通过 ActivityThread.getSystemContext() 获取系统 PackageManager。
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

    /** PER_USER_RANGE，与 UserHandle.PER_USER_RANGE 一致 */
    private static final int PER_USER_RANGE = 100000;

    /** 缓存的 SystemUI 真实 UID，-1 表示尚未解析或解析失败 */
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

        installRegisterHook(module, classLoader);
        installCanDropHook(module, classLoader);
    }

    // ==================== 修复点 1 ====================

    private static void installRegisterHook(XposedModule module,
                                             ClassLoader classLoader) {
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
                    "已 Hook registerTransitionPlayer（UID 白名单）");
        } catch (Throwable t) {
            module.log(android.util.Log.ERROR, TAG,
                    "Hook registerTransitionPlayer 失败", t);
        }
    }

    // ==================== 修复点 2 ====================

    private static void installCanDropHook(XposedModule module,
                                            ClassLoader classLoader) {
        try {
            Class<?> clazz = classLoader.loadClass(
                    CLS_WINDOW_ORGANIZER_CONTROLLER);

            Method target = null;
            for (Method m : clazz.getDeclaredMethods()) {
                if ("canDropDuringDisplayChange".equals(m.getName())) {
                    target = m;
                    break;
                }
            }

            if (target == null) {
                module.log(android.util.Log.INFO, TAG,
                        "canDropDuringDisplayChange 不存在（可能已打补丁），跳过");
                return;
            }

            module.hook(target)
                    .setExceptionMode(XposedInterface.ExceptionMode.DEFAULT)
                    .intercept(new CanDropHooker(module));

            module.log(android.util.Log.INFO, TAG,
                    "已 Hook canDropDuringDisplayChange（始终返回 false）");

        } catch (Throwable t) {
            module.log(android.util.Log.ERROR, TAG,
                    "Hook canDropDuringDisplayChange 失败", t);
        }
    }

    // ==================== SystemUI UID 解析 ====================

    /**
     * API 102 标准写法：使用 getModuleApplicationInfo() 获取模块自身信息，
     * 通过 ActivityThread.getSystemContext() 获取系统 PackageManager。
     *
     * 注意：getModuleContext() 在 API 101 中已被移除，不再使用反射调用。
     */
    private static void resolveSystemUiUid(XposedModule module) {
        try {
            // 获取模块自身的 ApplicationInfo（API 102 标准）
            ApplicationInfo moduleInfo = module.getModuleApplicationInfo();
            if (moduleInfo != null) {
                module.log(android.util.Log.INFO, TAG,
                        "模块 APK 路径: " + moduleInfo.sourceDir);
            }

            // 通过系统 Context 获取 SystemUI 的 UID
            resolveSystemUiUidBySystemContext(module);

        } catch (Throwable t) {
            module.log(android.util.Log.WARN, TAG,
                    "获取 SystemUI UID 失败，设置为 -1（放行模式）", t);
            sSystemUiUid = -1;
        }
    }

    private static void resolveSystemUiUidBySystemContext(XposedModule module) {
        try {
            Class<?> atClass = Class.forName("android.app.ActivityThread");
            Object activityThread = atClass
                    .getMethod("currentActivityThread").invoke(null);
            if (activityThread == null) {
                sSystemUiUid = -1;
                module.log(android.util.Log.WARN, TAG,
                        "ActivityThread 为空，SystemUI UID 设为 -1");
                return;
            }

            Object systemCtx = activityThread.getClass()
                    .getMethod("getSystemContext").invoke(activityThread);
            if (systemCtx == null) {
                sSystemUiUid = -1;
                module.log(android.util.Log.WARN, TAG,
                        "系统 Context 为空，SystemUI UID 设为 -1");
                return;
            }

            PackageManager pm = (PackageManager) systemCtx.getClass()
                    .getMethod("getPackageManager").invoke(systemCtx);
            ApplicationInfo ai = pm.getApplicationInfo(PKG_SYSTEMUI, 0);
            sSystemUiUid = ai.uid;

            module.log(android.util.Log.INFO, TAG,
                    "SystemUI UID = " + sSystemUiUid);

        } catch (Throwable t) {
            module.log(android.util.Log.WARN, TAG,
                    "系统 Context 路径失败，SystemUI UID 设为 -1", t);
            sSystemUiUid = -1;
        }
    }

    // ==================== Hooker 实现 ====================

    private static class UidCheckHooker implements XposedInterface.Hooker {

        private final XposedModule module;

        UidCheckHooker(XposedModule module) {
            this.module = module;
        }

        @Override
        public Object intercept(XposedInterface.Chain chain) throws Throwable {
            try {
                // 若 SystemUI UID 解析失败（-1），放行所有调用，避免误伤
                if (sSystemUiUid == -1) {
                    module.log(android.util.Log.WARN, TAG,
                            "SystemUI UID 未解析，放行所有调用");
                    return chain.proceed();
                }

                final int callingUid = Binder.getCallingUid();
                final int callingAppId = callingUid % PER_USER_RANGE;

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

    private static class CanDropHooker implements XposedInterface.Hooker {

        private final XposedModule module;

        CanDropHooker(XposedModule module) {
            this.module = module;
        }

        @Override
        public Object intercept(XposedInterface.Chain chain) throws Throwable {
            return false;
        }
    }
}