package top.alice.transitionplayerfix.hook;

import android.os.Binder;
import android.os.Build;
import android.os.Process;

import java.lang.reflect.Field;
import java.lang.reflect.Method;

import io.github.libxposed.api.XposedInterface;
import io.github.libxposed.api.XposedModule;

/**
 * 对应官方补丁修复点一：
 * 在 WindowOrganizerController.registerTransitionPlayer() 中补全
 * enforceCallingPermission(MANAGE_ACTIVITY_TASKS) 权限校验。
 *
 * 本版本针对 libxposed API 102 进行优化：
 * 1. 在 onPackageReady 阶段提前获取并缓存系统 Context，避免在 Hooker 内部进行脆弱的反射。
 * 2. 恢复多路径 Context 回退策略，提高定制 ROM 兼容性。
 * 3. 区分安全阻断（SecurityException）与 Hook 内部错误，避免因 Hook 故障导致 SystemUI 崩溃。
 * 4. 增加版本与进程名检查，Android 17+ 已原生加固，跳过 Hook。
 */
public class WindowOrganizerHook {

    private static final String TAG = "TransitionPlayerFix";

    // 目标类名
    private static final String CLS_WINDOW_ORGANIZER_CONTROLLER =
            "com.android.server.wm.WindowOrganizerController";
    private static final String CLS_ACTIVITY_THREAD =
            "android.app.ActivityThread";

    // 目标方法
    private static final String METHOD_REGISTER_TRANSITION_PLAYER =
            "registerTransitionPlayer";

    // 相关类型（用于方法签名精确匹配）
    private static final String TYPE_I_TRANSITION_PLAYER =
            "android.window.ITransitionPlayer";

    // 权限
    private static final String PERM_MANAGE_ACTIVITY_TASKS =
            "android.permission.MANAGE_ACTIVITY_TASKS";

    // 缓存的系统 Context
    private static volatile Object sSystemContext;

    /**
     * 在 onPackageReady 阶段调用，提前初始化系统 Context。
     * 采用多路径回退策略，提高兼容性。
     *
     * @param module      模块实例
     * @param classLoader system_server 的类加载器
     */
    public static void initContext(XposedModule module, ClassLoader classLoader) {
        // 版本检查：Android 17+ 已原生加固，跳过
        if (Build.VERSION.SDK_INT >= 37) {
            module.log(android.util.Log.INFO, TAG,
                    "Android 17+ 已原生加固，跳过 WindowOrganizerHook");
            return;
        }

        // 进程名检查：确保只在 system_server 进程中执行
        String processName = getCurrentProcessName(classLoader);
        if (processName != null && !"system_server".equals(processName)) {
            module.log(android.util.Log.INFO, TAG,
                    "当前进程不是 system_server (" + processName + ")，跳过");
            return;
        }

        // 路径一（首选）：ActivityThread.getSystemContext()
        Object ctx = getContextFromActivityThread(classLoader);
        if (ctx != null) {
            sSystemContext = ctx;
            module.log(android.util.Log.INFO, TAG,
                    "通过 ActivityThread.getSystemContext() 获取并缓存系统 Context");
            return;
        }

        // 路径二、三需要 controller 实例，在 Hooker 内部动态获取
        module.log(android.util.Log.WARN, TAG,
                "首选 Context 路径失败，将在 Hooker 内部尝试回退路径");
    }

    public static void install(XposedModule module, ClassLoader classLoader) {
        // 版本检查
        if (Build.VERSION.SDK_INT >= 37) {
            return;
        }

        try {
            Class<?> clazz = classLoader.loadClass(CLS_WINDOW_ORGANIZER_CONTROLLER);

            Method target = null;
            for (Method m : clazz.getDeclaredMethods()) {
                if (METHOD_REGISTER_TRANSITION_PLAYER.equals(m.getName())
                        && m.getParameterCount() == 1) {
                    String paramType = m.getParameterTypes()[0].getName();
                    // 精确匹配 ITransitionPlayer 参数类型，避免误匹配同名单参数重载
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

            // 关键：使用 PASSTHROUGH 模式，确保主动抛出的 SecurityException 能传播给调用者
            module.hook(target)
                    .setExceptionMode(XposedInterface.ExceptionMode.PASSTHROUGH)
                    .intercept(new PermissionCheckHooker(module));

            module.log(android.util.Log.INFO, TAG,
                    "已 Hook registerTransitionPlayer（补全权限校验）");
        } catch (Throwable t) {
            module.log(android.util.Log.ERROR, TAG,
                    "Hook registerTransitionPlayer 失败", t);
        }
    }

    private static class PermissionCheckHooker implements XposedInterface.Hooker {

        private final XposedModule module;

        PermissionCheckHooker(XposedModule module) {
            this.module = module;
        }

        @Override
        public Object intercept(XposedInterface.Chain chain) throws Throwable {
            final int callingUid = Binder.getCallingUid();
            final int callingPid = Binder.getCallingPid();

            // 策略一：系统 UID 直接放行
            if (callingUid == Process.SYSTEM_UID) {
                return chain.proceed();
            }

            // 策略二：使用缓存的 Context 执行官方补丁的权限校验
            Object context = sSystemContext;

            // 如果缓存的 Context 为 null，尝试从 controller 实例动态获取
            if (context == null) {
                context = resolveContextFromController(chain.getThisObject());
                if (context != null) {
                    sSystemContext = context;
                    module.log(android.util.Log.INFO, TAG,
                            "通过 controller 回退路径获取并缓存 Context");
                }
            }

            if (context != null) {
                try {
                    // enforceCallingPermission 是 Context 的公开 API，
                    // 标准反射在 system_server 中已足够可靠。
                    Method enforceMethod = context.getClass().getMethod(
                            "enforceCallingPermission", String.class, String.class);
                    enforceMethod.invoke(context, PERM_MANAGE_ACTIVITY_TASKS,
                            "registerTransitionPlayer requires "
                                    + PERM_MANAGE_ACTIVITY_TASKS);
                    // 权限校验通过，放行
                    return chain.proceed();
                } catch (Throwable t) {
                    // 区分安全阻断与 Hook 内部错误
                    if (isSecurityException(t)) {
                        module.log(android.util.Log.WARN, TAG,
                                "拒绝未授权调用: uid=" + callingUid
                                        + " pid=" + callingPid);
                        throw new SecurityException(
                                "registerTransitionPlayer requires "
                                        + PERM_MANAGE_ACTIVITY_TASKS
                                        + " (uid=" + callingUid + ")");
                    } else {
                        // Hook 内部错误（如方法签名变化），记录日志并放行，
                        // 避免因 Hook 故障导致 SystemUI 崩溃
                        module.log(android.util.Log.ERROR, TAG,
                                "权限校验调用失败，放行以避免崩溃: " + t);
                        return chain.proceed();
                    }
                }
            }

            // 策略三：所有 Context 路径均失败，安全优先，拒绝调用
            module.log(android.util.Log.ERROR, TAG,
                    "无法获取 Context，拒绝调用: uid=" + callingUid
                            + " pid=" + callingPid);
            throw new SecurityException(
                    "registerTransitionPlayer: cannot verify permission "
                            + "for uid=" + callingUid);
        }
    }

    /**
     * 判断异常是否为权限校验失败（SecurityException）。
     * 由于 invoke 会包装异常为 InvocationTargetException，需要检查 cause。
     */
    private static boolean isSecurityException(Throwable t) {
        Throwable cause = t;
        while (cause != null) {
            if (cause instanceof SecurityException) {
                return true;
            }
            cause = cause.getCause();
        }
        return false;
    }

    /**
     * 通过 ActivityThread 获取系统 Context。
     */
    private static Object getContextFromActivityThread(ClassLoader classLoader) {
        try {
            Class<?> atClass = Class.forName(CLS_ACTIVITY_THREAD, false, classLoader);
            Object activityThread = atClass.getMethod("currentActivityThread")
                    .invoke(null);
            if (activityThread != null) {
                return activityThread.getClass()
                        .getMethod("getSystemContext")
                        .invoke(activityThread);
            }
        } catch (Throwable ignored) {}
        return null;
    }

    /**
     * 从 WindowOrganizerController 实例动态解析 Context（回退路径）。
     *
     * 根据 AOSP 源码：
     *   WindowOrganizerController → mService (WindowManagerService) → mContext
     *   WindowOrganizerController → mAtmService (ActivityTaskManagerService) → mContext
     */
    private static Object resolveContextFromController(Object controller) {
        if (controller == null) return null;

        // 路径：controller.mService.mContext
        try {
            Field serviceField = controller.getClass().getDeclaredField("mService");
            serviceField.setAccessible(true);
            Object wms = serviceField.get(controller);
            if (wms != null) {
                Field ctxField = wms.getClass().getDeclaredField("mContext");
                ctxField.setAccessible(true);
                Object ctx = ctxField.get(wms);
                if (ctx != null) return ctx;
            }
        } catch (Throwable ignored) {}

        // 路径：controller.mAtmService.mContext
        try {
            Field atmField = controller.getClass().getDeclaredField("mAtmService");
            atmField.setAccessible(true);
            Object atm = atmField.get(controller);
            if (atm != null) {
                Field ctxField = atm.getClass().getDeclaredField("mContext");
                ctxField.setAccessible(true);
                Object ctx = ctxField.get(atm);
                if (ctx != null) return ctx;
            }
        } catch (Throwable ignored) {}

        return null;
    }

    /**
     * 获取当前进程名。
     *
     * 注意：ActivityThread.currentProcessName() 是静态方法，
     * 应使用 invoke(null) 调用，而非传入 activityThread 实例。
     * 若误传实例，会抛出 IllegalArgumentException，导致进程名检查失效。
     */
    private static String getCurrentProcessName(ClassLoader classLoader) {
        try {
            Class<?> atClass = Class.forName(CLS_ACTIVITY_THREAD, false, classLoader);
            // currentProcessName() 是静态方法，传入 null 作为实例参数
            return (String) atClass.getMethod("currentProcessName").invoke(null);
        } catch (Throwable ignored) {}
        return null;
    }
}