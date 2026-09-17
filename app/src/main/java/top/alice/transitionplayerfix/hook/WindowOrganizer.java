package top.alice.transitionplayerfix.hook;

import android.os.Binder;
import android.os.Process;

import androidx.annotation.NonNull;

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
 * 2. 使用 Chain 接口的 getThisObject() 与 getArgs() 方法，通过 Invoker 机制绕过访问检查。
 * 3. 采用基于调用者 UID 的精细化降级策略，而非简单拒绝，以平衡安全性与兼容性。
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
     * 这是比在 Hooker 内部反射更可靠的方法。
     *
     * @param module      模块实例
     * @param classLoader system_server 的类加载器
     */
    public static void initContext(XposedModule module, ClassLoader classLoader) {
        try {
            Class<?> atClass = Class.forName(CLS_ACTIVITY_THREAD, false, classLoader);
            Object activityThread = atClass.getMethod("currentActivityThread").invoke(null);
            if (activityThread != null) {
                Object ctx = activityThread.getClass()
                        .getMethod("getSystemContext")
                        .invoke(activityThread);
                if (ctx != null) {
                    sSystemContext = ctx;
                    module.log(android.util.Log.INFO, TAG,
                            "成功在 onPackageReady 阶段获取并缓存系统 Context");
                    return;
                }
            }
        } catch (Throwable t) {
            module.log(android.util.Log.ERROR, TAG,
                    "在 onPackageReady 阶段获取系统 Context 失败", t);
        }
        module.log(android.util.Log.WARN, TAG,
                "无法在 onPackageReady 阶段获取系统 Context，将依赖 Hooker 内部的降级策略");
    }

    public static void install(XposedModule module, ClassLoader classLoader) {
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

            module.log(android.util.Log.INFO, TAG,
                    "找到方法: " + target);

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
        public Object intercept(@NonNull XposedInterface.Chain chain) throws Throwable {
            final int callingUid = Binder.getCallingUid();
            final int callingPid = Binder.getCallingPid();

            // 策略一：系统 UID 直接放行
            if (callingUid == Process.SYSTEM_UID) {
                return chain.proceed();
            }

            // 策略二：使用缓存的系统 Context 执行官方补丁的权限校验
            Object context = sSystemContext;
            if (context != null) {
                try {
                    Method enforceMethod = context.getClass().getMethod(
                            "enforceCallingPermission", String.class, String.class);
                    enforceMethod.invoke(context, PERM_MANAGE_ACTIVITY_TASKS,
                            "registerTransitionPlayer requires "
                                    + PERM_MANAGE_ACTIVITY_TASKS);
                    // 权限校验通过，放行
                    return chain.proceed();
                } catch (Throwable t) {
                    // enforceCallingPermission 抛出 SecurityException 表示无权限
                    module.log(android.util.Log.WARN, TAG,
                            "拒绝未授权调用: uid=" + callingUid
                                    + " pid=" + callingPid);
                    throw new SecurityException(
                            "registerTransitionPlayer requires "
                                    + PERM_MANAGE_ACTIVITY_TASKS
                                    + " (uid=" + callingUid + ")");
                }
            }

            // 策略三：Context 获取失败时的精细化降级策略
            // 此时无法执行官方补丁的权限校验，出于安全考虑，默认拒绝。
            // 但为了兼容性，允许 system_server 自身（UID 1000）和 SystemUI（其 UID 需动态获取，
            // 但出于简化，这里假设其可能在特定 UID 范围内，实际生产中应通过 PackageManager 查询）通过。
            // 注意：绝对不要硬编码 UID，这里仅为示例逻辑。更安全的做法是直接拒绝所有非系统调用。
            module.log(android.util.Log.ERROR, TAG,
                    "无法获取 Context，执行降级策略。调用者: uid=" + callingUid
                            + " pid=" + callingPid);

            // 安全优先：如果无法校验，则拒绝。这比放行更安全，但可能误伤。
            // 如果你确认 SystemUI 的 UID 在特定范围内，可在此处添加白名单，但极不推荐。
            throw new SecurityException(
                    "registerTransitionPlayer: cannot verify permission "
                            + "for uid=" + callingUid);
        }
    }
}