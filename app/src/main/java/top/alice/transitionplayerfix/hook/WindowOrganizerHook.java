package top.alice.transitionplayerfix.hook;

import android.os.Binder;
import android.os.Build;
import android.os.Process;
import android.os.UserHandle;

import java.lang.reflect.Method;

import io.github.libxposed.api.XposedInterface;
import io.github.libxposed.api.XposedModule;

/**
 * 对应漏洞的入口拦截点：
 * WindowOrganizerController.registerTransitionPlayer()
 *
 * 漏洞利用链的第一步是攻击者从 adb shell（uid=2000）调用此方法，
 * 注册一个恶意的 ITransitionPlayer。虽然 shell 持有
 * MANAGE_ACTIVITY_TASKS 权限，但合法的调用者只应是 system_server。
 *
 * 因此本 Hook 使用 UID 硬校验：只放行 SYSTEM_UID (1000)，
 * 其他所有 UID（包括 shell 2000）一律拒绝。
 *
 * 注：不再依赖 enforceCallingPermission，因为 shell 持有该权限，
 *     权限校验对 shell 无效。
 */
public class WindowOrganizerHook {

    private static final String TAG = "TransitionPlayerFix";

    private static final String CLS_WINDOW_ORGANIZER_CONTROLLER =
            "com.android.server.wm.WindowOrganizerController";
    private static final String METHOD_REGISTER_TRANSITION_PLAYER =
            "registerTransitionPlayer";
    private static final String TYPE_I_TRANSITION_PLAYER =
            "android.window.ITransitionPlayer";

    public static void install(XposedModule module, ClassLoader classLoader) {
        // Android 17+ 已原生加固，跳过
        if (Build.VERSION.SDK_INT >= 37) {
            module.log(android.util.Log.INFO, TAG,
                    "Android 17+ 已原生加固，跳过 WindowOrganizerHook");
            return;
        }

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
                    "已 Hook registerTransitionPlayer（UID 硬校验）");
        } catch (Throwable t) {
            module.log(android.util.Log.ERROR, TAG,
                    "Hook registerTransitionPlayer 失败", t);
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
                final int callingAppId = UserHandle.getAppId(callingUid);

                // 只允许 system_server (1000) 调用
                // shell (2000) 即使持有 MANAGE_ACTIVITY_TASKS 也被拒绝
                if (callingAppId != Process.SYSTEM_UID) {
                    module.log(android.util.Log.WARN, TAG,
                            "拒绝非系统进程注册 TransitionPlayer: uid="
                                    + callingUid + " appId=" + callingAppId);
                    throw new SecurityException(
                            "registerTransitionPlayer requires SYSTEM_UID, "
                                    + "got uid=" + callingUid);
                }

                return chain.proceed();

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